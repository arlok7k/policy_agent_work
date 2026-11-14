"""Real-session Four-Eyes, state, authorization and concurrency regressions."""

import threading
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from app.auth.session import SESSION_COOKIE, SessionIdentity, identity_from_rows, session_rows
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.main import app
from app.response.gate import Decision, decide_action
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def _principal(api: PB2API, role: str) -> tuple[SessionIdentity, Redacted]:
    headers = api.login(role)
    cookie = headers["Cookie"].reveal()
    pieces = dict(part.strip().split("=", 1) for part in cookie.split(";"))
    token = Redacted(pieces[SESSION_COOKIE])
    with app.state.session_factory() as db:
        rows = session_rows(db, app.state.settings, token.reveal())
        assert rows is not None
        return identity_from_rows(rows), token


def _pending(api: PB2API, requester: UUID) -> UUID:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            incident = db.execute(
                text("INSERT INTO incidents (title) VALUES ('gate case') RETURNING id")
            ).scalar_one()
            action = db.execute(
                text(
                    "INSERT INTO response_actions "
                    "(incident_id, action_type, target, params, level, "
                    "approval_mode, requested_by) "
                    "VALUES (:incident, 'isolate_host', "
                    '\'{"agent_id":"004","ip":"8.8.8.8"}\'::jsonb, \'{}\'::jsonb, '
                    "3, 'manual', :requester) RETURNING id"
                ),
                {"incident": incident, "requester": requester},
            ).scalar_one()
            db.execute(
                text("UPDATE response_actions SET status='pending_approval' WHERE id=:id"),
                {"id": action},
            )
            return action
    finally:
        engine.dispose()


def _decide(
    actor: SessionIdentity, token: Redacted, action: UUID, decision: Decision = "approved"
) -> str:
    with app.state.session_factory() as db:
        result = decide_action(
            db,
            app.state.settings,
            actor,
            token.reveal(),
            app.state.legacy_policy["response_decide"],
            action,
            decision,
            "reviewed",
            128,
            ip_address("127.0.0.1"),
        )
        return result.status


def _counts(api: PB2API, action: UUID) -> tuple[str, int, int]:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            status = db.execute(
                text("SELECT status FROM response_actions WHERE id=:id"), {"id": action}
            ).scalar_one()
            decisions = db.execute(
                text("SELECT count(*) FROM response_approvals WHERE action_id=:id"), {"id": action}
            ).scalar_one()
            commands = db.execute(
                text("SELECT count(*) FROM executed_commands WHERE action_id=:id"), {"id": action}
            ).scalar_one()
            return status, decisions, commands
    finally:
        engine.dispose()


def test_self_approval_and_non_senior_role_are_denied_without_mutation(pb2_api: PB2API) -> None:
    senior, senior_token = _principal(pb2_api, "senior")
    analyst, analyst_token = _principal(pb2_api, "analyst")
    action = _pending(pb2_api, senior.user_id)
    with pytest.raises(Forbidden):
        _decide(senior, senior_token, action)
    with pytest.raises(Forbidden):
        _decide(analyst, analyst_token, action)
    assert _counts(pb2_api, action) == ("pending_approval", 0, 0)
    with pytest.raises(NotFound):
        _decide(senior, senior_token, uuid4())


def test_reject_then_approve_is_forbidden_and_own_rejection_is_permitted(pb2_api: PB2API) -> None:
    admin, admin_token = _principal(pb2_api, "admin")
    senior, senior_token = _principal(pb2_api, "senior")
    action = _pending(pb2_api, admin.user_id)
    assert _decide(admin, admin_token, action, "rejected") == "rejected"
    with pytest.raises(Conflict):
        _decide(senior, senior_token, action)
    assert _counts(pb2_api, action) == ("rejected", 1, 0)


def test_approval_while_switch_engaged_is_recorded_without_execution(pb2_api: PB2API) -> None:
    senior, token = _principal(pb2_api, "senior")
    action = _pending(pb2_api, pb2_api.accounts["analyst"].id)
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE kill_switch_state SET engaged=true WHERE id=1"))
        assert _decide(senior, token, action) == "approved"
        assert _counts(pb2_api, action) == ("approved", 1, 0)
    finally:
        engine.dispose()


def test_two_eligible_approvers_race_to_one_decision(pb2_api: PB2API) -> None:
    senior, senior_token = _principal(pb2_api, "senior")
    admin, admin_token = _principal(pb2_api, "admin")
    action = _pending(pb2_api, pb2_api.accounts["analyst"].id)
    barrier = threading.Barrier(2)

    def attempt(actor: SessionIdentity, token: Redacted) -> int:
        barrier.wait(timeout=10)
        try:
            _decide(actor, token, action)
            return 200
        except Conflict:
            return 409

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(attempt, senior, senior_token)
        second = executor.submit(attempt, admin, admin_token)
        statuses = [first.result(timeout=15), second.result(timeout=15)]
    assert sorted(statuses) == [200, 409]
    assert _counts(pb2_api, action) == ("approved", 1, 0)
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            count = db.execute(
                text(
                    "SELECT count(*) FROM case_activities "
                    "WHERE action='response.transition' AND target=:target"
                ),
                {"target": f"response_action:{action}"},
            ).scalar_one()
            assert count == 1
    finally:
        engine.dispose()


def test_role_revalidation_and_audit_failure_leave_no_decision(pb2_api: PB2API) -> None:
    senior, senior_token = _principal(pb2_api, "senior")
    admin, admin_token = _principal(pb2_api, "admin")
    action = _pending(pb2_api, pb2_api.accounts["analyst"].id)
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='analyst') "
                    "WHERE id=:id"
                ),
                {"id": senior.user_id},
            )
        with pytest.raises(Forbidden):
            _decide(senior, senior_token, action)
        assert _counts(pb2_api, action) == ("pending_approval", 0, 0)
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        with pytest.raises(SQLAlchemyError):
            _decide(admin, admin_token, action)
        assert _counts(pb2_api, action) == ("pending_approval", 0, 0)
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()
