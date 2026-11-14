"""Audited switch access and propagation to a real running Celery worker."""

import json
import threading
from time import monotonic
from uuid import UUID

import pytest
from celery.beat import Scheduler
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.jobs.celery_app import (
    EXECUTE_RESPONSE_TASK,
    RECONCILE_RESPONSE_SCHEDULE,
    RECONCILE_RESPONSE_TASK,
)
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def _post(api: PB2API, headers: dict[str, Redacted], body: dict[str, object]) -> object:
    api.client.cookies.clear()
    return api.client.post("/api/response/kill-switch", headers=headers, json=body)


def _state(owner: Engine) -> tuple[bool, UUID | None]:
    with owner.connect() as db:
        row = db.execute(text("SELECT engaged, changed_by FROM kill_switch_state WHERE id=1")).one()
        return row[0], row[1]


def test_switch_roles_csrf_idempotent_audit_and_atomic_failure(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    admin, senior, analyst = (pb2_api.login(role) for role in ("admin", "senior", "analyst"))
    try:
        assert _post(pb2_api, {}, {"engaged": True}).status_code == 401
        assert _post(pb2_api, analyst, {"engaged": True}).status_code == 403
        assert _post(pb2_api, {"Cookie": senior["Cookie"]}, {"engaged": True}).status_code == 403
        assert _post(pb2_api, senior, {"engaged": "true"}).status_code == 400
        assert _post(pb2_api, senior, {"engaged": True, "extra": 1}).status_code == 400
        permissive = dict(app.state.legacy_policy)
        permissive["response_kill_switch"] = ("analyst", "senior_analyst", "admin")
        with monkeypatch.context() as patch:
            patch.setitem(app.state._state, "legacy_policy", permissive)
            assert _post(pb2_api, analyst, {"engaged": True}).status_code == 403
        assert _state(owner) == (False, None)
        first = _post(pb2_api, senior, {"engaged": True})
        assert first.status_code == 200
        assert first.json()["engaged"] is True
        assert first.json()["changed_by"] == str(pb2_api.accounts["senior"].id)
        assert first.headers["Cache-Control"] == "no-store"
        assert _post(pb2_api, senior, {"engaged": True}).status_code == 200
        assert _post(pb2_api, admin, {"engaged": False}).status_code == 200
        assert _state(owner) == (False, pb2_api.accounts["admin"].id)
        with owner.connect() as db:
            activities = db.execute(
                text(
                    "SELECT username, details FROM case_activities "
                    "WHERE action='response.kill_switch' ORDER BY id"
                )
            ).all()
        assert [
            (username, details["before"], details["after"]) for username, details in activities
        ] == [("senior", False, True), ("senior", True, True), ("admin", True, False)]
        for _, details in activities:
            assert set(details) == {"before", "after", "correlation_id"}
            UUID(details["correlation_id"])
        with owner.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        assert _post(pb2_api, senior, {"engaged": True}).status_code == 503
        assert _state(owner) == (False, pb2_api.accounts["admin"].id)
    finally:
        with owner.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        owner.dispose()


def _approved_actions(owner: Engine, requester: UUID, approver: UUID) -> tuple[UUID, UUID]:
    with owner.begin() as db:
        incident = db.execute(
            text("INSERT INTO incidents (title) VALUES ('switch worker case') RETURNING id")
        ).scalar_one()
        automatic = db.execute(
            text(
                "INSERT INTO response_actions "
                "(incident_id, action_type, target, params, level, approval_mode, requested_by) "
                "VALUES (:incident, 'notify', CAST(:target AS jsonb), CAST(:params AS jsonb), "
                "1, 'automatic', :requester) RETURNING id"
            ),
            {
                "incident": incident,
                "target": json.dumps({"value": "analysts"}),
                "params": json.dumps({"message": "Review"}),
                "requester": requester,
            },
        ).scalar_one()
        db.execute(
            text("UPDATE response_actions SET status='approved' WHERE id=:id"), {"id": automatic}
        )
        manual = db.execute(
            text(
                "INSERT INTO response_actions "
                "(incident_id, action_type, target, params, level, approval_mode, requested_by) "
                "VALUES (:incident, 'isolate_host', CAST(:target AS jsonb), '{}'::jsonb, "
                "3, 'manual', :requester) RETURNING id"
            ),
            {
                "incident": incident,
                "target": json.dumps({"agent_id": "004", "ip": "8.8.8.8"}),
                "requester": requester,
            },
        ).scalar_one()
        db.execute(
            text("UPDATE response_actions SET status='pending_approval' WHERE id=:id"),
            {"id": manual},
        )
        db.execute(
            text(
                "INSERT INTO response_approvals (action_id, approver_id, decision) "
                "VALUES (:id, :actor, 'approved')"
            ),
            {"id": manual, "actor": approver},
        )
        db.execute(
            text("UPDATE response_actions SET status='approved', decided_by=:actor WHERE id=:id"),
            {"id": manual, "actor": approver},
        )
        return automatic, manual


def _action_state(owner: Engine, action: UUID) -> tuple[str, int]:
    with owner.connect() as db:
        row = db.execute(
            text(
                "SELECT status, (SELECT count(*) FROM executed_commands WHERE action_id=:id) "
                "FROM response_actions WHERE id=:id"
            ),
            {"id": action},
        ).one()
        return row[0], row[1]


def test_switch_propagates_to_already_running_worker_and_queued_automation(pb2_api: PB2API) -> None:
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    admin = pb2_api.login("admin")
    automatic, manual = _approved_actions(
        owner, pb2_api.accounts["analyst"].id, pb2_api.accounts["senior"].id
    )
    started, release = threading.Event(), threading.Event()
    condition = threading.Condition()
    events: list[tuple[str, str, object]] = []

    @app.state.celery.task(name="tests.hold_response_worker", shared=False)
    def hold_worker() -> None:
        started.set()
        if not release.wait(15):
            raise RuntimeError("Test did not release worker")

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
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            try:
                hold_worker.apply_async(headers={"initiator": "service:test"}, retry=False)
                assert started.wait(10)
                app.state.celery.send_task(
                    EXECUTE_RESPONSE_TASK,
                    args=[str(automatic)],
                    headers={"initiator": "service:test"},
                    retry=False,
                )
                assert _post(pb2_api, admin, {"engaged": True}).status_code == 200
                engaged_at = monotonic()
                release.set()
                with condition:
                    assert condition.wait_for(lambda: len(events) >= 1, timeout=20)
                propagation_seconds = monotonic() - engaged_at
                assert events[0] == (EXECUTE_RESPONSE_TASK, "SUCCESS", {"result": "paused"})
                # This is an observed target in an uncongested test worker, not
                # a guarantee under database, broker or worker contention.
                assert propagation_seconds <= 1.5
                assert _action_state(owner, automatic) == ("approved", 0)
                app.state.celery.send_task(
                    EXECUTE_RESPONSE_TASK,
                    args=[str(manual)],
                    headers={"initiator": "service:test"},
                    retry=False,
                )
                with condition:
                    assert condition.wait_for(lambda: len(events) >= 2, timeout=20)
                assert events[1] == (EXECUTE_RESPONSE_TASK, "SUCCESS", {"result": "executed"})
                assert _action_state(owner, manual) == ("executed", 1)
                assert _post(pb2_api, admin, {"engaged": False}).status_code == 200
                scheduler = Scheduler(app=app.state.celery)
                scheduler.apply_async(
                    scheduler.schedule[RECONCILE_RESPONSE_SCHEDULE], advance=False
                )
                with condition:
                    assert condition.wait_for(lambda: len(events) >= 3, timeout=20)
                assert events[2][0:2] == (RECONCILE_RESPONSE_TASK, "SUCCESS")
                assert events[2][2]["executed"] == 1
                assert _action_state(owner, automatic) == ("executed", 1)
            finally:
                release.set()
    finally:
        task_postrun.disconnect(observed)
        owner.dispose()
