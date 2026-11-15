"""Adversarial PB3 endpoint, audit, revalidation and disclosure regressions."""

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import UUID, uuid4

import pytest
from kombu.exceptions import OperationalError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.auth.legacy_policy import load_legacy_policy
from app.core.pb3_config import load_pb3_settings
from app.main import app
from app.response.execution import execute_approved
from app.response.manual_rollback import pending_manual_rollbacks, perform_manual_rollback
from tests.contract.assertions import assert_response_contract
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted, assert_not_disclosed


def _incident(api: PB2API) -> UUID:
    owner = create_engine(api.database_url, hide_parameters=True)
    try:
        with owner.begin() as db:
            return db.execute(
                text("INSERT INTO incidents (title) VALUES ('security case') RETURNING id")
            ).scalar_one()
    finally:
        owner.dispose()


def _create(api: PB2API, headers: dict[str, Redacted], body: dict[str, object]) -> object:
    api.client.cookies.clear()
    return api.client.post("/api/response/actions", headers=headers, json=body)


def test_unauthenticated_cross_object_csrf_and_error_contracts(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    incident = _incident(pb2_api)
    base = {
        "incident_id": str(incident),
        "action_type": "isolate_host",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    own = _create(pb2_api, senior, base).json()["id"]
    other = _create(pb2_api, analyst, base).json()["id"]
    missing = str(uuid4())
    for route, method, payload in (
        ("/api/response/catalog", "GET", None),
        ("/api/response/actions", "GET", None),
        ("/api/response/actions", "POST", base),
        (f"/api/response/actions/{other}/approve", "POST", {}),
        (f"/api/response/actions/{other}/reject", "POST", {}),
        (f"/api/response/actions/{other}/rollback", "POST", {}),
        ("/api/response/kill-switch", "POST", {"engaged": True}),
    ):
        client.cookies.clear()
        assert client.request(method, route, json=payload).status_code == 401
    for action in (own, other, missing):
        for operation in ("approve", "reject", "rollback"):
            client.cookies.clear()
            denied = client.post(
                f"/api/response/actions/{action}/{operation}", headers=analyst, json={}
            )
            assert denied.status_code == 403
            assert_response_contract(
                "POST", f"/api/response/actions/{{action_id}}/{operation}", denied
            )
    for operation in ("approve", "reject", "rollback"):
        client.cookies.clear()
        not_found = client.post(
            f"/api/response/actions/{missing}/{operation}", headers=admin, json={}
        )
        assert not_found.status_code == 404
        assert_response_contract(
            "POST", f"/api/response/actions/{{action_id}}/{operation}", not_found
        )
        for value in ("bad-uuid", "1", "../../not-an-id"):
            client.cookies.clear()
            expected = 404 if "/" in value else 400
            assert (
                client.post(
                    f"/api/response/actions/{value}/{operation}", headers=admin, json={}
                ).status_code
                == expected
            )
    cookie_only = {"Cookie": admin["Cookie"]}
    for route, payload in (
        ("/api/response/actions", base),
        (f"/api/response/actions/{other}/approve", {}),
        (f"/api/response/actions/{other}/reject", {}),
        (f"/api/response/actions/{other}/rollback", {}),
        ("/api/response/kill-switch", {"engaged": True}),
    ):
        client.cookies.clear()
        assert client.post(route, headers=cookie_only, json=payload).status_code == 403
    client.cookies.clear()
    assert (
        client.post(f"/api/response/actions/{own}/approve", headers=senior, json={}).status_code
        == 403
    )
    assert (
        client.post(f"/api/response/actions/{other}/approve", headers=senior, json={}).status_code
        == 200
    )
    client.cookies.clear()
    listing = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst)
    assert {row["id"] for row in listing.json()["items"]} == {own, other}


def test_action_and_manual_intent_audit_failure_are_atomic(
    pb2_api: PB2API, runtime_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst, admin = (pb2_api.login(role) for role in ("analyst", "admin"))
    incident = _incident(pb2_api)
    body = {
        "incident_id": str(incident),
        "action_type": "firewall_allow",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
        "mode": "automatic",
    }
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OperationalError("unavailable")

    def failed_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    try:
        with monkeypatch.context() as patch:
            patch.setattr("app.response.service.append_activity", failed_audit)
            assert _create(pb2_api, analyst, body).status_code == 500
        with owner.connect() as db:
            assert db.execute(text("SELECT count(*) FROM response_actions")).scalar_one() == 0
            assert (
                db.execute(
                    text("SELECT count(*) FROM case_activities WHERE action LIKE 'response.%'")
                ).scalar_one()
                == 0
            )
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            created = _create(pb2_api, analyst, body)
        action = UUID(created.json()["id"])
        with Session(runtime) as db, db.begin():
            assert (
                execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                == "executed"
            )
        with monkeypatch.context() as patch:
            patch.setattr("app.response.manual_rollback.append_activity", failed_audit)
            client.cookies.clear()
            assert (
                client.post(
                    f"/api/response/actions/{action}/rollback", headers=admin, json={}
                ).status_code
                == 500
            )
        with owner.connect() as db:
            actor, requested_at, status = db.execute(
                text(
                    "SELECT rollback_requested_by, rollback_requested_at, status "
                    "FROM response_actions WHERE id=:id"
                ),
                {"id": action},
            ).one()
            assert actor is None and requested_at is None and status == "executed"
            assert (
                db.execute(
                    text("SELECT count(*) FROM executed_commands WHERE action_id=:id"),
                    {"id": action},
                ).scalar_one()
                == 1
            )
            assert (
                db.execute(
                    text(
                        "SELECT count(*) FROM case_activities "
                        "WHERE action='response.rollback_requested'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        owner.dispose()
        runtime.dispose()


def test_manual_rollback_request_and_duplicate_worker_delivery_are_serialized(
    pb2_api: PB2API, runtime_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst, admin = (pb2_api.login(role) for role in ("analyst", "admin"))
    incident = _incident(pb2_api)
    body = {
        "incident_id": str(incident),
        "action_type": "firewall_drop",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
        "mode": "automatic",
    }
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OperationalError("unavailable")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            created = _create(pb2_api, analyst, body)
            action = UUID(created.json()["id"])
            with Session(runtime) as db, db.begin():
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "executed"
                )
            client.cookies.clear()
            request = client.post(
                f"/api/response/actions/{action}/rollback", headers=admin, json={}
            )
        assert request.status_code == 202
        at = datetime.fromisoformat(request.json()["rollback_requested_at"])
        actor = pb2_api.accounts["admin"].id
        barrier = threading.Barrier(2)

        def deliver() -> str:
            barrier.wait(timeout=10)
            with Session(runtime) as db, db.begin():
                return perform_manual_rollback(db, action, actor, at, load_legacy_policy())

        with ThreadPoolExecutor(max_workers=2) as workers:
            first, second = workers.submit(deliver), workers.submit(deliver)
            assert sorted([first.result(timeout=20), second.result(timeout=20)]) == [
                "noop",
                "rolled_back",
            ]
        with Session(runtime) as db, db.begin():
            assert pending_manual_rollbacks(db, 10) == []
        with owner.connect() as db:
            assert (
                db.execute(
                    text(
                        "SELECT count(*) FROM executed_commands "
                        "WHERE action_id=:id AND phase='rollback'"
                    ),
                    {"id": action},
                ).scalar_one()
                == 1
            )
            assert (
                db.execute(
                    text(
                        "SELECT count(*) FROM case_activities WHERE target=:target "
                        "AND action='response.transition' AND details->>'to'='rolled_back'"
                    ),
                    {"target": f"response_action:{action}"},
                ).scalar_one()
                == 1
            )
    finally:
        owner.dispose()
        runtime.dispose()


def test_response_secrets_never_appear_in_api_errors_audit_or_publication_logs(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    analyst = pb2_api.login("analyst")
    incident = _incident(pb2_api)
    key = Redacted(f"key-{uuid4().hex}")
    body = {
        "incident_id": str(incident),
        "action_type": "ioc_add",
        "target": {"value": "indicator"},
        "params": {},
    }
    owner = create_engine(pb2_api.database_url, hide_parameters=True)

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OperationalError("unavailable")

    try:
        with caplog.at_level(logging.INFO), monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            created = _create(pb2_api, {**analyst, "Idempotency-Key": key}, body)
            replay = _create(pb2_api, {**analyst, "Idempotency-Key": key}, body)
            conflict = _create(
                pb2_api,
                {**analyst, "Idempotency-Key": key},
                {**body, "target": {"value": "different"}},
            )
            rejected = _create(pb2_api, analyst, {**body, "extra": key})
        assert [
            created.status_code,
            replay.status_code,
            conflict.status_code,
            rejected.status_code,
        ] == [201, 200, 409, 400]
        values = (
            key,
            *analyst.values(),
            *(account.password for account in pb2_api.accounts.values()),
        )
        for response in (created, replay, conflict, rejected):
            assert_not_disclosed("Response", response.text, *values)
        assert_not_disclosed("Logs", caplog.text, *values)
        with owner.connect() as db:
            activities = db.execute(
                text("SELECT username, action, target, details::text FROM case_activities")
            ).all()
            assert_not_disclosed(
                "Activity log", json.dumps([list(row) for row in activities]), *values
            )
    finally:
        owner.dispose()


def test_concurrent_key_reuse_with_different_payloads_conflicts_atomically(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst = pb2_api.login("analyst")
    incident = _incident(pb2_api)
    key = Redacted(f"key-{uuid4().hex}")
    headers = {**analyst, "Idempotency-Key": key}
    bodies = [
        {
            "incident_id": str(incident),
            "action_type": "advisory",
            "target": {"value": value},
            "params": {"message": "Review"},
        }
        for value in ("first", "second")
    ]
    barrier = threading.Barrier(2)
    client.cookies.clear()

    def submit(body: dict[str, object]) -> object:
        barrier.wait(timeout=10)
        return client.post("/api/response/actions", headers=headers, json=body)

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(submit, bodies[0])
        second = workers.submit(submit, bodies[1])
        responses = [first.result(timeout=20), second.result(timeout=20)]
    assert sorted(response.status_code for response in responses) == [201, 409]
    winner = next(index for index, response in enumerate(responses) if response.status_code == 201)
    replay = _create(pb2_api, headers, bodies[winner])
    assert replay.status_code == 200
    assert replay.json()["id"] == responses[winner].json()["id"]
    assert _create(pb2_api, headers, bodies[1 - winner]).status_code == 409
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with owner.connect() as db:
            assert db.execute(text("SELECT count(*) FROM response_actions")).scalar_one() == 1
            assert (
                db.execute(
                    text("SELECT count(*) FROM case_activities WHERE action='response.requested'")
                ).scalar_one()
                == 1
            )
    finally:
        owner.dispose()


def test_unexpected_publication_failure_does_not_misreport_committed_work(
    pb2_api: PB2API, runtime_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    incident = _incident(pb2_api)
    auto = {
        "incident_id": str(incident),
        "action_type": "ioc_add",
        "target": {"value": "indicator"},
        "params": {},
    }
    manual = {
        "incident_id": str(incident),
        "action_type": "isolate_host",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    runtime = create_engine(runtime_url, hide_parameters=True)

    def unavailable(*args: object, **kwargs: object) -> None:
        raise RuntimeError("publisher stopped unexpectedly")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            created = _create(pb2_api, analyst, auto)
            assert created.status_code == 201 and created.json()["status"] == "approved"
            pending = _create(pb2_api, analyst, manual)
            assert pending.status_code == 201 and pending.json()["status"] == "pending_approval"
            action = UUID(pending.json()["id"])
            client.cookies.clear()
            approved = client.post(
                f"/api/response/actions/{action}/approve", headers=senior, json={}
            )
            assert approved.status_code == 200 and approved.json()["status"] == "approved"
            with Session(runtime) as db, db.begin():
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "executed"
                )
            client.cookies.clear()
            rollback = client.post(
                f"/api/response/actions/{action}/rollback", headers=admin, json={}
            )
            assert (
                rollback.status_code == 202
                and rollback.json()["rollback_request_status"] == "pending"
            )
        with Session(runtime) as db, db.begin():
            assert len(pending_manual_rollbacks(db, 10)) == 1
    finally:
        runtime.dispose()


def test_mandatory_safeguards_are_rechecked_even_for_preexisting_approved_rows(
    pb2_api: PB2API, runtime_url: str
) -> None:
    analyst = pb2_api.login("analyst")
    incident = _incident(pb2_api)
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    fixtures = (
        ("firewall_drop", {"agent_id": "000", "ip": "8.8.8.8"}, 2),
        ("firewall_drop", {"agent_id": "004", "ip": "10.0.0.5"}, 2),
        ("firewall_drop", {"agent_id": "004", "ip": "127.0.0.1"}, 2),
        ("ioc_add", {"value": "; rm -rf"}, 1),
    )
    try:
        for name, target, level in fixtures:
            payload = {
                "incident_id": str(incident),
                "action_type": name,
                "target": target,
                "params": {},
                **({"mode": "automatic"} if level == 2 else {}),
            }
            assert _create(pb2_api, analyst, payload).status_code == 422
            # This bypasses HTTP to model an old or compromised stored request;
            # the worker must not trust that request-time safeguards ran.
            with owner.begin() as db:
                action = db.execute(
                    text(
                        "INSERT INTO response_actions "
                        "(incident_id, action_type, target, params, level, approval_mode, "
                        "requested_by, ttl_seconds) VALUES "
                        "(:incident, :name, CAST(:target AS jsonb), '{}'::jsonb, :level, "
                        "'automatic', :requester, :ttl) RETURNING id"
                    ),
                    {
                        "incident": incident,
                        "name": name,
                        "target": json.dumps(target),
                        "level": level,
                        "requester": pb2_api.accounts["analyst"].id,
                        "ttl": 60 if level == 2 else None,
                    },
                ).scalar_one()
                db.execute(
                    text("UPDATE response_actions SET status='approved' WHERE id=:id"),
                    {"id": action},
                )
            with Session(runtime) as db, db.begin():
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "failed"
                )
            with Session(runtime) as db, db.begin():
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "noop"
                )
            with owner.connect() as db:
                assert (
                    db.execute(
                        text("SELECT status FROM response_actions WHERE id=:id"), {"id": action}
                    ).scalar_one()
                    == "failed"
                )
                assert (
                    db.execute(
                        text("SELECT count(*) FROM executed_commands WHERE action_id=:id"),
                        {"id": action},
                    ).scalar_one()
                    == 0
                )
                assert (
                    db.execute(
                        text(
                            "SELECT details->>'reason' FROM case_activities "
                            "WHERE action='response.execution_refused' AND target=:target"
                        ),
                        {"target": f"response_action:{action}"},
                    ).scalar_one()
                    == "safeguard"
                )
    finally:
        owner.dispose()
        runtime.dispose()


def test_manual_approval_can_race_switch_engagement_without_partial_effects(
    pb2_api: PB2API,
) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    incident = _incident(pb2_api)
    pending = _create(
        pb2_api,
        analyst,
        {
            "incident_id": str(incident),
            "action_type": "isolate_host",
            "target": {"agent_id": "004", "ip": "8.8.8.8"},
            "params": {},
        },
    )
    assert pending.status_code == 201
    action = pending.json()["id"]
    barrier = threading.Barrier(2)
    client.cookies.clear()

    def decide() -> object:
        barrier.wait(timeout=10)
        return client.post(f"/api/response/actions/{action}/approve", headers=senior, json={})

    def engage() -> object:
        barrier.wait(timeout=10)
        return client.post("/api/response/kill-switch", headers=admin, json={"engaged": True})

    with ThreadPoolExecutor(max_workers=2) as workers:
        decision, switch = workers.submit(decide), workers.submit(engage)
        results = [decision.result(timeout=20), switch.result(timeout=20)]
    assert [result.status_code for result in results] == [200, 200]
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with owner.connect() as db:
            assert (
                db.execute(text("SELECT engaged FROM kill_switch_state WHERE id=1")).scalar_one()
                is True
            )
            assert (
                db.execute(
                    text("SELECT status FROM response_actions WHERE id=:id"), {"id": UUID(action)}
                ).scalar_one()
                == "approved"
            )
            assert (
                db.execute(
                    text("SELECT count(*) FROM response_approvals WHERE action_id=:id"),
                    {"id": UUID(action)},
                ).scalar_one()
                == 1
            )
            assert (
                db.execute(
                    text("SELECT count(*) FROM executed_commands WHERE action_id=:id"),
                    {"id": UUID(action)},
                ).scalar_one()
                == 0
            )
            assert (
                db.execute(
                    text("SELECT count(*) FROM case_activities WHERE action='response.kill_switch'")
                ).scalar_one()
                == 1
            )
    finally:
        owner.dispose()


def test_configured_incident_text_limit_applies_to_response_fields_and_decisions(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst, senior = (pb2_api.login(role) for role in ("analyst", "senior"))
    incident = _incident(pb2_api)
    pending = _create(
        pb2_api,
        analyst,
        {
            "incident_id": str(incident),
            "action_type": "isolate_host",
            "target": {"agent_id": "004", "ip": "8.8.8.8"},
            "params": {},
        },
    )
    assert pending.status_code == 201
    action = pending.json()["id"]
    small = app.state.pb2_settings.model_copy(update={"incident_max_text_chars": 8})
    with monkeypatch.context() as patch:
        patch.setitem(app.state._state, "pb2_settings", small)
        advisory = {
            "incident_id": str(incident),
            "action_type": "advisory",
            "target": {"value": "12345678"},
            "params": {"message": "12345678"},
        }
        assert _create(pb2_api, analyst, advisory).status_code == 201
        assert (
            _create(pb2_api, analyst, {**advisory, "target": {"value": "123456789"}}).status_code
            == 422
        )
        assert (
            _create(pb2_api, analyst, {**advisory, "params": {"message": "123456789"}}).status_code
            == 422
        )
        client.cookies.clear()
        refused = client.post(
            f"/api/response/actions/{action}/approve",
            headers=senior,
            json={"reason": "123456789"},
        )
        assert refused.status_code == 400
        assert_response_contract("POST", "/api/response/actions/{action_id}/approve", refused)
        owner = create_engine(pb2_api.database_url, hide_parameters=True)
        try:
            with owner.connect() as db:
                assert (
                    db.execute(
                        text("SELECT status FROM response_actions WHERE id=:id"),
                        {"id": UUID(action)},
                    ).scalar_one()
                    == "pending_approval"
                )
                assert (
                    db.execute(
                        text("SELECT count(*) FROM response_approvals WHERE action_id=:id"),
                        {"id": UUID(action)},
                    ).scalar_one()
                    == 0
                )
        finally:
            owner.dispose()
        assert (
            client.post(
                f"/api/response/actions/{action}/approve",
                headers=senior,
                json={"reason": "12345678"},
            ).status_code
            == 200
        )
