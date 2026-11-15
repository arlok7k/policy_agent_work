"""Transactional execution and real-worker response revalidation regressions."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from celery.beat import Scheduler
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.legacy_policy import load_legacy_policy
from app.core.pb3_config import load_pb3_settings
from app.jobs.celery_app import (
    EXECUTE_RESPONSE_TASK,
    RECONCILE_RESPONSE_SCHEDULE,
    RECONCILE_RESPONSE_TASK,
)
from app.main import app
from app.response.execution import approved_for_reconciliation, execute_approved
from tests.integration.conftest import PB2API, PB2Account


def _seed(
    engine: Engine,
    requester: UUID,
    *,
    action_type: str = "isolate_host",
    level: int = 3,
    mode: str = "manual",
    approver: UUID | None = None,
    target: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    ttl: int | None = None,
    approve: bool = True,
) -> UUID:
    target = target or {"agent_id": "004", "ip": "8.8.8.8"}
    with engine.begin() as db:
        incident = db.execute(
            text("INSERT INTO incidents (title) VALUES ('worker case') RETURNING id")
        ).scalar_one()
        identifier = db.execute(
            text(
                "INSERT INTO response_actions "
                "(incident_id, action_type, target, params, level, approval_mode, "
                "requested_by, ttl_seconds) "
                "VALUES (:incident, :name, CAST(:target AS jsonb), CAST(:params AS jsonb), "
                ":level, :mode, :requester, :ttl) RETURNING id"
            ),
            {
                "incident": incident,
                "name": action_type,
                "target": json.dumps(target),
                "params": json.dumps(params or {}),
                "level": level,
                "mode": mode,
                "requester": requester,
                "ttl": ttl,
            },
        ).scalar_one()
        if mode == "automatic":
            db.execute(
                text("UPDATE response_actions SET status='approved' WHERE id=:id"),
                {"id": identifier},
            )
        else:
            db.execute(
                text("UPDATE response_actions SET status='pending_approval' WHERE id=:id"),
                {"id": identifier},
            )
            if approve:
                if approver is None:
                    raise ValueError("Test approval needs an approver")
                db.execute(
                    text(
                        "INSERT INTO response_approvals (action_id, approver_id, decision) "
                        "VALUES (:id, :actor, 'approved')"
                    ),
                    {"id": identifier, "actor": approver},
                )
                db.execute(
                    text(
                        "UPDATE response_actions SET status='approved', "
                        "decided_by=:actor WHERE id=:id"
                    ),
                    {"id": identifier, "actor": approver},
                )
        return identifier


def _execute(runtime: Engine, identifier: UUID) -> str:
    with Session(runtime) as db, db.begin():
        return execute_approved(db, identifier, load_legacy_policy(), load_pb3_settings())


def _state(owner: Engine, identifier: UUID) -> tuple[str, int]:
    with owner.connect() as db:
        row = db.execute(
            text(
                "SELECT status, (SELECT count(*) FROM executed_commands WHERE action_id=:id) "
                "FROM response_actions WHERE id=:id"
            ),
            {"id": identifier},
        ).one()
        return row[0], row[1]


def test_ladder_execution_ttl_and_redelivery_are_atomic(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    requester, senior = pb2_accounts["analyst"].id, pb2_accounts["senior"].id
    try:
        l1 = _seed(
            owner,
            requester,
            action_type="ioc_add",
            level=1,
            mode="automatic",
            target={"value": "indicator"},
        )
        l2 = _seed(owner, requester, action_type="firewall_drop", level=2, mode="automatic", ttl=60)
        l3 = _seed(owner, requester, approver=senior)
        assert _execute(runtime, uuid4()) == "noop"
        for action in (l1, l2, l3):
            assert _execute(runtime, action) == "executed"
            assert _execute(runtime, action) == "noop"
            assert _state(owner, action) == ("executed", 1)
        with owner.connect() as db:
            row = db.execute(
                text(
                    "SELECT a.ttl_expires_at, c.executed_at, c.initiator FROM response_actions a "
                    "JOIN executed_commands c ON c.action_id=a.id WHERE a.id=:id"
                ),
                {"id": l2},
            ).one()
            assert row.ttl_expires_at - row.executed_at == timedelta(seconds=60)
            assert row.initiator == f"user:{requester}"
            assert (
                db.execute(
                    text("SELECT initiator FROM executed_commands WHERE action_id=:id"), {"id": l3}
                ).scalar_one()
                == f"user:{senior}"
            )
            assert (
                db.execute(
                    text("SELECT count(*) FROM case_activities WHERE action='response.transition'")
                ).scalar_one()
                == 6
            )
    finally:
        owner.dispose()
        runtime.dispose()


def test_new_safeguard_and_approver_demotion_fail_closed_and_terminally(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    requester, senior, admin = (pb2_accounts[x].id for x in ("analyst", "senior", "admin"))
    try:
        protected = _seed(owner, requester, approver=senior)
        revoked = _seed(
            owner, requester, approver=admin, target={"agent_id": "005", "ip": "8.8.4.4"}
        )
        with owner.begin() as db:
            db.execute(
                text(
                    "INSERT INTO response_safeguard_rule (code, kind, value) "
                    "VALUES ('new-agent', 'agent', '004')"
                )
            )
            db.execute(
                text(
                    "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='analyst') "
                    "WHERE id=:id"
                ),
                {"id": admin},
            )
        assert _execute(runtime, protected) == "failed"
        assert _execute(runtime, revoked) == "failed"
        assert _state(owner, protected) == ("failed", 0)
        assert _state(owner, revoked) == ("failed", 0)
        with owner.begin() as db:
            db.execute(text("DELETE FROM response_safeguard_rule WHERE code='new-agent'"))
            db.execute(
                text(
                    "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='admin') "
                    "WHERE id=:id"
                ),
                {"id": admin},
            )
        assert _execute(runtime, protected) == "noop"
        assert _execute(runtime, revoked) == "noop"
        with owner.connect() as db:
            reasons = (
                db.execute(
                    text(
                        "SELECT details->>'reason' FROM case_activities "
                        "WHERE action='response.execution_refused' ORDER BY details->>'reason'"
                    )
                )
                .scalars()
                .all()
            )
            assert reasons == ["ineligible_actor_or_approval", "safeguard"]
    finally:
        owner.dispose()
        runtime.dispose()


def test_worker_rechecks_l2_ttl_against_current_configured_maximum(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    try:
        action = _seed(
            owner,
            pb2_accounts["analyst"].id,
            action_type="firewall_drop",
            level=2,
            mode="automatic",
            ttl=120,
        )
        shorter = load_pb3_settings(
            {"RESPONSE_L2_TTL_DEFAULT_SECONDS": "30", "RESPONSE_L2_TTL_MAX_SECONDS": "60"}
        )
        with Session(runtime) as db, db.begin():
            assert execute_approved(db, action, load_legacy_policy(), shorter) == "failed"
        assert _state(owner, action) == ("failed", 0)
    finally:
        owner.dispose()
        runtime.dispose()


def test_pending_or_deactivated_requester_cannot_be_executed_and_policy_fails_closed(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    requester = pb2_accounts["analyst"].id
    try:
        pending = _seed(owner, requester, approve=False)
        automatic = _seed(
            owner,
            requester,
            action_type="ioc_add",
            level=1,
            mode="automatic",
            target={"value": "indicator"},
        )
        assert _execute(runtime, pending) == "noop"
        with Session(runtime) as db, db.begin(), pytest.raises(RuntimeError):
            execute_approved(db, automatic, {}, load_pb3_settings())
        assert _state(owner, automatic) == ("approved", 0)
        with owner.begin() as db:
            db.execute(text("UPDATE users SET is_active=false WHERE id=:id"), {"id": requester})
        assert _execute(runtime, automatic) == "failed"
        assert _state(owner, automatic) == ("failed", 0)
        assert _state(owner, pending) == ("pending_approval", 0)
    finally:
        owner.dispose()
        runtime.dispose()


def test_switch_pauses_auto_and_reconciliation_still_processes_manual(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    requester, senior = pb2_accounts["analyst"].id, pb2_accounts["senior"].id
    try:
        automatic = _seed(
            owner, requester, action_type="firewall_drop", level=2, mode="automatic", ttl=60
        )
        manual = _seed(owner, requester, approver=senior)
        with owner.begin() as db:
            db.execute(text("UPDATE kill_switch_state SET engaged=true WHERE id=1"))
        assert _execute(runtime, automatic) == "paused"
        with Session(runtime) as db, db.begin():
            assert approved_for_reconciliation(db, 1) == [manual]
        assert _execute(runtime, manual) == "executed"
        assert _state(owner, automatic) == ("approved", 0)
        with owner.begin() as db:
            db.execute(text("UPDATE kill_switch_state SET engaged=false WHERE id=1"))
        with Session(runtime) as db, db.begin():
            assert approved_for_reconciliation(db, 1) == [automatic]
        assert _execute(runtime, automatic) == "executed"
    finally:
        owner.dispose()
        runtime.dispose()


def test_concurrent_delivery_and_audit_failure_never_duplicate_or_partially_execute(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    requester, senior = pb2_accounts["analyst"].id, pb2_accounts["senior"].id
    action = _seed(owner, requester, approver=senior)
    retry = _seed(owner, requester, approver=senior, target={"agent_id": "005", "ip": "8.8.4.4"})
    barrier = threading.Barrier(2)
    try:

        def attempt() -> str:
            barrier.wait(timeout=10)
            return _execute(runtime, action)

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(attempt)
            second = executor.submit(attempt)
            assert sorted([first.result(timeout=15), second.result(timeout=15)]) == [
                "executed",
                "noop",
            ]
        assert _state(owner, action) == ("executed", 1)
        with owner.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        with pytest.raises(SQLAlchemyError):
            _execute(runtime, retry)
        assert _state(owner, retry) == ("approved", 0)
        with owner.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        assert _execute(runtime, retry) == "executed"
    finally:
        with owner.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        owner.dispose()
        runtime.dispose()


def test_direct_and_recovery_tasks_run_in_a_real_worker(pb2_api: PB2API) -> None:
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    actor = pb2_api.accounts["analyst"].id
    direct = _seed(
        owner, actor, action_type="ioc_add", level=1, mode="automatic", target={"value": "direct"}
    )
    recovered = _seed(
        owner,
        actor,
        action_type="ioc_update",
        level=1,
        mode="automatic",
        target={"value": "recovered"},
    )
    events: list[tuple[str, str, object]] = []
    condition = threading.Condition()

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        name = getattr(sender, "name", "")
        if name in {EXECUTE_RESPONSE_TASK, RECONCILE_RESPONSE_TASK}:
            with condition:
                events.append((name, state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    try:
        scheduler = Scheduler(app=app.state.celery)
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            app.state.celery.send_task(
                EXECUTE_RESPONSE_TASK,
                args=[str(direct)],
                headers={"initiator": "service:test"},
                retry=False,
            )
            with condition:
                assert condition.wait_for(lambda: len(events) >= 1, timeout=20)
            scheduler.apply_async(scheduler.schedule[RECONCILE_RESPONSE_SCHEDULE], advance=False)
            with condition:
                assert condition.wait_for(lambda: len(events) >= 2, timeout=20)
        assert events[0] == (EXECUTE_RESPONSE_TASK, "SUCCESS", {"result": "executed"})
        assert events[1][0:2] == (RECONCILE_RESPONSE_TASK, "SUCCESS")
        assert events[1][2]["executed"] == 1
        assert _state(owner, direct) == ("executed", 1)
        assert _state(owner, recovered) == ("executed", 1)
    finally:
        task_postrun.disconnect(observed)
        owner.dispose()
