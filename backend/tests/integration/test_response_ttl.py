"""Real L2 rollbacks, frozen database time, safety changes and Celery Beat."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from uuid import UUID

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
from app.jobs.celery_app import TTL_SWEEP_SCHEDULE, TTL_SWEEP_TASK
from app.main import app
from app.response.execution import execute_approved
from app.response.ttl import due_for_rollback, rollback_expired
from tests.integration.conftest import PB2API, PB2Account


def _executed_l2(
    owner: Engine,
    runtime: Engine,
    actor: UUID,
    *,
    name: str = "firewall_drop",
    address: str = "8.8.8.8",
    ttl: int = 60,
    approver: UUID | None = None,
) -> tuple[UUID, datetime]:
    with owner.begin() as db:
        incident = db.execute(
            text("INSERT INTO incidents (title) VALUES ('ttl case') RETURNING id")
        ).scalar_one()
        identifier = db.execute(
            text(
                "INSERT INTO response_actions "
                "(incident_id, action_type, target, params, level, approval_mode, "
                "requested_by, ttl_seconds) VALUES "
                "(:incident, :name, CAST(:target AS jsonb), '{}'::jsonb, 2, :mode, "
                ":actor, :ttl) RETURNING id"
            ),
            {
                "incident": incident,
                "name": name,
                "target": json.dumps({"agent_id": "004", "ip": address}),
                "actor": actor,
                "ttl": ttl,
                "mode": "manual" if approver is not None else "automatic",
            },
        ).scalar_one()
        if approver is None:
            db.execute(
                text("UPDATE response_actions SET status='approved' WHERE id=:id"),
                {"id": identifier},
            )
        else:
            db.execute(
                text("UPDATE response_actions SET status='pending_approval' WHERE id=:id"),
                {"id": identifier},
            )
            db.execute(
                text(
                    "INSERT INTO response_approvals (action_id, approver_id, decision) "
                    "VALUES (:id, :actor, 'approved')"
                ),
                {"id": identifier, "actor": approver},
            )
            db.execute(
                text(
                    "UPDATE response_actions SET status='approved', decided_by=:actor WHERE id=:id"
                ),
                {"id": identifier, "actor": approver},
            )
    with Session(runtime) as db, db.begin():
        assert (
            execute_approved(db, identifier, load_legacy_policy(), load_pb3_settings())
            == "executed"
        )
    with owner.connect() as db:
        expiry = db.execute(
            text("SELECT ttl_expires_at FROM response_actions WHERE id=:id"), {"id": identifier}
        ).scalar_one()
    return identifier, expiry


def _rollback(runtime: Engine, action: UUID) -> str:
    with Session(runtime) as db, db.begin():
        return rollback_expired(db, action)


def _due(runtime: Engine, batch: int = 100) -> list[UUID]:
    with Session(runtime) as db, db.begin():
        return due_for_rollback(db, batch)


def _rows(owner: Engine, action: UUID) -> tuple[str, list[tuple[str, str]]]:
    with owner.connect() as db:
        status = db.execute(
            text("SELECT status FROM response_actions WHERE id=:id"), {"id": action}
        ).scalar_one()
        commands = db.execute(
            text("SELECT phase, command FROM executed_commands WHERE action_id=:id ORDER BY id"),
            {"id": action},
        ).all()
    return status, commands


@pytest.mark.parametrize("manual", [False, True])
def test_ttl_boundary_with_frozen_database_clock_and_duplicate_delivery(
    migrated_url: str,
    runtime_url: str,
    pb2_accounts: dict[str, PB2Account],
    monkeypatch: pytest.MonkeyPatch,
    manual: bool,
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    try:
        approver = pb2_accounts["senior"].id if manual else None
        action, expiry = _executed_l2(owner, runtime, pb2_accounts["analyst"].id, approver=approver)
        frozen = [expiry - timedelta(microseconds=1)]
        monkeypatch.setattr("app.response.ttl.database_now", lambda _db: frozen[0])
        assert _due(runtime) == []
        assert _rollback(runtime, action) == "noop"
        assert _rows(owner, action) == ("executed", [("execute", "firewall_drop")])
        frozen[0] = expiry
        assert _due(runtime) == [action]
        assert _rollback(runtime, action) == "rolled_back"
        assert _rollback(runtime, action) == "noop"
        assert _rows(owner, action) == (
            "rolled_back",
            [("execute", "firewall_drop"), ("rollback", "firewall_allow")],
        )
        with owner.connect() as db:
            assert (
                db.execute(
                    text(
                        "SELECT count(*) FROM case_activities WHERE action='response.transition' "
                        "AND target=:target AND details->>'to'='rolled_back'"
                    ),
                    {"target": f"response_action:{action}"},
                ).scalar_one()
                == 1
            )
    finally:
        owner.dispose()
        runtime.dispose()


def test_newly_unsafe_reverse_is_audited_once_retried_and_cannot_starve_other_ttls(
    migrated_url: str,
    runtime_url: str,
    pb2_accounts: dict[str, PB2Account],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    try:
        actor = pb2_accounts["analyst"].id
        unsafe, unsafe_expiry = _executed_l2(owner, runtime, actor, name="firewall_allow")
        other, other_expiry = _executed_l2(owner, runtime, actor, address="1.1.1.1")
        frozen = max(unsafe_expiry, other_expiry)
        monkeypatch.setattr("app.response.ttl.database_now", lambda _db: frozen)
        with owner.begin() as db:
            db.execute(
                text(
                    "INSERT INTO response_safeguard_rule (code, kind, value) "
                    "VALUES ('added-network', 'network', '8.8.8.0/24')"
                )
            )
        assert _due(runtime, 1) == [unsafe]
        assert _rollback(runtime, unsafe) == "refused"
        assert _rollback(runtime, unsafe) == "refused"
        assert _rows(owner, unsafe) == ("executed", [("execute", "firewall_allow")])
        with owner.connect() as db:
            assert (
                db.execute(
                    text(
                        "SELECT count(*) FROM case_activities WHERE action='response.ttl_refused' "
                        "AND target=:target"
                    ),
                    {"target": f"response_action:{unsafe}"},
                ).scalar_one()
                == 1
            )
        assert _due(runtime, 1) == [other]
        assert _rollback(runtime, other) == "rolled_back"
        with owner.begin() as db:
            db.execute(text("DELETE FROM response_safeguard_rule WHERE code='added-network'"))
        assert _due(runtime, 1) == [unsafe]
        assert _rollback(runtime, unsafe) == "rolled_back"
        assert _rows(owner, unsafe) == (
            "rolled_back",
            [("execute", "firewall_allow"), ("rollback", "firewall_drop")],
        )
    finally:
        owner.dispose()
        runtime.dispose()


def test_switch_and_audit_failure_leave_overdue_action_for_later_retry(
    migrated_url: str,
    runtime_url: str,
    pb2_accounts: dict[str, PB2Account],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    try:
        action, expiry = _executed_l2(owner, runtime, pb2_accounts["analyst"].id)
        monkeypatch.setattr("app.response.ttl.database_now", lambda _db: expiry)
        with owner.begin() as db:
            db.execute(text("UPDATE kill_switch_state SET engaged=true WHERE id=1"))
        assert _due(runtime) == []
        assert _rollback(runtime, action) == "paused"
        assert _rows(owner, action) == ("executed", [("execute", "firewall_drop")])
        with owner.begin() as db:
            db.execute(text("UPDATE kill_switch_state SET engaged=false WHERE id=1"))
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        with pytest.raises(SQLAlchemyError):
            _rollback(runtime, action)
        assert _rows(owner, action) == ("executed", [("execute", "firewall_drop")])
        with owner.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        assert _rollback(runtime, action) == "rolled_back"
    finally:
        with owner.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        owner.dispose()
        runtime.dispose()


def test_concurrent_expiry_tasks_do_not_double_roll_back(
    migrated_url: str,
    runtime_url: str,
    pb2_accounts: dict[str, PB2Account],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    barrier = threading.Barrier(2)
    try:
        action, expiry = _executed_l2(owner, runtime, pb2_accounts["analyst"].id)
        monkeypatch.setattr("app.response.ttl.database_now", lambda _db: expiry)

        def attempt() -> str:
            barrier.wait(timeout=10)
            return _rollback(runtime, action)

        with ThreadPoolExecutor(max_workers=2) as executor:
            first, second = executor.submit(attempt), executor.submit(attempt)
            assert sorted([first.result(timeout=15), second.result(timeout=15)]) == [
                "noop",
                "rolled_back",
            ]
        assert _rows(owner, action) == (
            "rolled_back",
            [("execute", "firewall_drop"), ("rollback", "firewall_allow")],
        )
    finally:
        owner.dispose()
        runtime.dispose()


def test_beat_dispatches_ttl_task_to_real_worker(
    pb2_api: PB2API,
    runtime_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    events: list[tuple[str, object]] = []
    condition = threading.Condition()

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        if getattr(sender, "name", None) == TTL_SWEEP_TASK:
            with condition:
                events.append((state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    try:
        action, expiry = _executed_l2(owner, runtime, pb2_api.accounts["analyst"].id)
        monkeypatch.setattr("app.response.ttl.database_now", lambda _db: expiry)
        scheduler = Scheduler(app=app.state.celery)
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            scheduler.apply_async(scheduler.schedule[TTL_SWEEP_SCHEDULE], advance=False)
            with condition:
                assert condition.wait_for(lambda: bool(events), timeout=20)
        assert events[0][0] == "SUCCESS"
        assert events[0][1]["rolled_back"] == 1
        assert _rows(owner, action)[0] == "rolled_back"
    finally:
        task_postrun.disconnect(observed)
        owner.dispose()
        runtime.dispose()
