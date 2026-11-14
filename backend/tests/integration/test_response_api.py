"""PB3 response API contracts, idempotency and durable manual rollback."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import UUID, uuid4

import pytest
from celery.beat import Scheduler
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from kombu.exceptions import OperationalError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.auth.legacy_policy import load_legacy_policy
from app.core.pb3_config import load_pb3_settings
from app.jobs.celery_app import (
    EXECUTE_RESPONSE_TASK,
    MANUAL_ROLLBACK_TASK,
    RECONCILE_RESPONSE_SCHEDULE,
    RECONCILE_RESPONSE_TASK,
)
from app.main import app
from app.response.execution import execute_approved
from app.response.manual_rollback import pending_manual_rollbacks, perform_manual_rollback
from tests.contract.assertions import assert_response_contract
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted, assert_not_disclosed


def _incident(api: PB2API) -> UUID:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            return db.execute(
                text("INSERT INTO incidents (title) VALUES ('API case') RETURNING id")
            ).scalar_one()
    finally:
        engine.dispose()


def _create(api: PB2API, headers: dict[str, Redacted], body: dict[str, object]) -> object:
    api.client.cookies.clear()
    return api.client.post("/api/response/actions", headers=headers, json=body)


def _action_counts(api: PB2API) -> tuple[int, int]:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            actions = db.execute(text("SELECT count(*) FROM response_actions")).scalar_one()
            commands = db.execute(text("SELECT count(*) FROM executed_commands")).scalar_one()
            return actions, commands
    finally:
        engine.dispose()


def test_request_ladder_and_safeguards_run_before_persistence(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst = pb2_api.login("analyst")
    admin = pb2_api.login("admin")
    incident = _incident(pb2_api)
    l0 = {
        "incident_id": str(incident),
        "action_type": "advisory",
        "target": {"value": "review"},
        "params": {"message": "Consider review"},
    }
    l1 = {
        "incident_id": str(incident),
        "action_type": "ioc_add",
        "target": {"value": "indicator"},
        "params": {},
    }
    l2 = {
        "incident_id": str(incident),
        "action_type": "firewall_drop",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    l3 = {
        "incident_id": str(incident),
        "action_type": "isolate_host",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    for body, state in (
        (l0, "advised"),
        (l1, "approved"),
        ({**l2, "mode": "automatic"}, "approved"),
        (l3, "pending_approval"),
    ):
        result = _create(pb2_api, analyst, body)
        assert result.status_code == 201
        assert result.json()["status"] == state
        assert_response_contract("POST", "/api/response/actions", result)
        if body["action_type"] == "firewall_drop":
            assert result.json()["ttl_seconds"] == 3600
            assert result.json()["ttl_expires_at"] is None
    assert _action_counts(pb2_api) == (4, 0)
    invalid = (
        (l2, 422),
        ({**l2, "mode": "automatic", "ttl_seconds": 0}, 422),
        ({**l2, "mode": "automatic", "ttl_seconds": 86401}, 422),
        ({**l2, "mode": "automatic", "ttl_seconds": True}, 400),
        ({**l1, "ttl_seconds": 60}, 422),
        ({**l3, "mode": "automatic"}, 422),
        ({**l2, "mode": "automatic", "target": {"agent_id": "000", "ip": "8.8.8.8"}}, 422),
        ({**l2, "mode": "automatic", "target": {"agent_id": "004", "ip": "10.0.0.5"}}, 422),
        ({**l2, "mode": "automatic", "target": {"agent_id": "004", "ip": "127.0.0.1"}}, 422),
        ({**l1, "target": {"value": "; rm -rf"}}, 422),
        ({**l2, "mode": "automatic", "params": {"command": "safe; evil"}}, 422),
        (
            {
                **l2,
                "mode": "automatic",
                "target": {"agent_id": "004", "ip": "8.8.8.8", "command": "x"},
            },
            422,
        ),
        ({**l2, "action_type": "release_host", "mode": "automatic"}, 422),
        ({**l2, "incident_id": str(uuid4()), "mode": "automatic"}, 404),
        ({"action_type": "ioc_add", "target": {"value": "x"}}, 400),
        ({**l1, "target": {"value": "x" * 129}}, 422),
    )
    for body, expected in invalid:
        response = _create(pb2_api, analyst, body)
        assert response.status_code == expected
        assert_response_contract("POST", "/api/response/actions", response)
    client.cookies.clear()
    assert (
        client.post("/api/response/kill-switch", headers=admin, json={"engaged": True}).status_code
        == 200
    )
    assert _create(pb2_api, analyst, l1).status_code == 409
    assert _create(pb2_api, analyst, {**l2, "mode": "manual"}).status_code == 201
    assert _create(pb2_api, analyst, l3).status_code == 201
    assert _action_counts(pb2_api) == (6, 0)


def test_idempotency_replays_conflicts_concurrency_and_user_scope(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst = pb2_api.login("analyst")
    senior = pb2_api.login("senior")
    incident = _incident(pb2_api)
    key = Redacted(f"key-{uuid4().hex}")
    body = {
        "incident_id": str(incident),
        "action_type": "ioc_add",
        "target": {"value": "indicator"},
        "params": {},
    }
    headers = {**analyst, "Idempotency-Key": key}
    first = _create(pb2_api, headers, body)
    second = _create(pb2_api, headers, body)
    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json()["id"] == second.json()["id"]
    assert_response_contract("POST", "/api/response/actions", second, key)
    assert_not_disclosed("Idempotent replay", second.text, key)
    assert _create(pb2_api, headers, {**body, "target": {"value": "different"}}).status_code == 409
    assert _create(pb2_api, {**senior, "Idempotency-Key": key}, body).status_code == 201
    assert (
        _create(pb2_api, {**analyst, "Idempotency-Key": Redacted("bad key")}, body).status_code
        == 400
    )
    race_key = Redacted(f"race-{uuid4().hex}")
    race_headers = {**analyst, "Idempotency-Key": race_key}
    barrier = threading.Barrier(2)
    client.cookies.clear()

    def submit() -> object:
        barrier.wait(timeout=10)
        return client.post("/api/response/actions", headers=race_headers, json=body)

    with ThreadPoolExecutor(max_workers=2) as workers:
        one, two = workers.submit(submit), workers.submit(submit)
        results = [one.result(timeout=20), two.result(timeout=20)]
    assert sorted(result.status_code for result in results) == [200, 201]
    assert len({result.json()["id"] for result in results}) == 1
    assert _action_counts(pb2_api) == (3, 0)


def test_four_eyes_rejection_bola_and_shared_listing(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    incident = _incident(pb2_api)
    body = {
        "incident_id": str(incident),
        "action_type": "isolate_host",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    pending = _create(pb2_api, senior, body)
    assert pending.status_code == 201
    action = pending.json()["id"]
    for identifier in (action, str(uuid4())):
        client.cookies.clear()
        assert (
            client.post(
                f"/api/response/actions/{identifier}/approve", headers=analyst, json={}
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/api/response/actions/{identifier}/rollback", headers=analyst, json={}
            ).status_code
            == 403
        )
    missing = uuid4()
    client.cookies.clear()
    assert (
        client.post(f"/api/response/actions/{missing}/approve", headers=admin, json={}).status_code
        == 404
    )
    assert (
        client.post(f"/api/response/actions/{action}/approve", headers=senior, json={}).status_code
        == 403
    )
    approved = client.post(
        f"/api/response/actions/{action}/approve", headers=admin, json={"reason": "reviewed"}
    )
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert (
        client.post(f"/api/response/actions/{action}/approve", headers=admin, json={}).status_code
        == 409
    )
    rejected = _create(pb2_api, analyst, body).json()["id"]
    client.cookies.clear()
    assert (
        client.post(f"/api/response/actions/{rejected}/reject", headers=senior, json={}).status_code
        == 200
    )
    assert (
        client.post(f"/api/response/actions/{rejected}/approve", headers=admin, json={}).status_code
        == 409
    )
    assert (
        client.get(f"/api/response/actions?incident_id={incident}", headers=analyst).status_code
        == 200
    )
    listed = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst).json()[
        "items"
    ]
    assert {item["id"] for item in listed} == {action, rejected}
    assert _action_counts(pb2_api) == (2, 0)


def test_publication_failure_returns_durable_action_and_beat_recovers(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst = pb2_api.login("analyst")
    incident = _incident(pb2_api)
    body = {
        "incident_id": str(incident),
        "action_type": "ioc_add",
        "target": {"value": "indicator"},
        "params": {},
    }

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OperationalError("unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(app.state.celery, "send_task", unavailable)
        response = _create(pb2_api, analyst, body)
    assert response.status_code == 201 and response.json()["status"] == "approved"
    action_id = response.json()["id"]
    assert _action_counts(pb2_api) == (1, 0)
    condition = threading.Condition()
    events: list[tuple[str, object]] = []

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        if getattr(sender, "name", None) == RECONCILE_RESPONSE_TASK:
            with condition:
                events.append((state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    try:
        scheduler = Scheduler(app=app.state.celery)
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            scheduler.apply_async(scheduler.schedule[RECONCILE_RESPONSE_SCHEDULE], advance=False)
            with condition:
                assert condition.wait_for(lambda: bool(events), timeout=20)
        assert events[0][0] == "SUCCESS" and events[0][1]["executed"] == 1
        client.cookies.clear()
        listed = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst)
        assert listed.json()["items"][0]["id"] == action_id
        assert listed.json()["items"][0]["status"] == "executed"
    finally:
        task_postrun.disconnect(observed)


@pytest.mark.parametrize("changed", ["role", "safeguard"])
def test_refused_manual_rollback_requires_fresh_request_and_can_recover(
    pb2_api: PB2API, runtime_url: str, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
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

    try:
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            created = _create(pb2_api, analyst, body)
            assert created.status_code == 201
            action = UUID(created.json()["id"])
            with Session(runtime) as db, db.begin():
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "executed"
                )
            client.cookies.clear()
            requested = client.post(
                f"/api/response/actions/{action}/rollback", headers=senior, json={}
            )
        assert (
            requested.status_code == 202
            and requested.json()["rollback_request_status"] == "pending"
        )
        stamp = datetime.fromisoformat(requested.json()["rollback_requested_at"])
        actor = pb2_api.accounts["senior"].id
        with Session(runtime) as db, db.begin():
            assert pending_manual_rollbacks(db, 10) == [(action, actor, stamp)]
        with owner.begin() as db:
            if changed == "role":
                db.execute(
                    text(
                        "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='analyst') "
                        "WHERE id=:id"
                    ),
                    {"id": actor},
                )
            else:
                db.execute(
                    text(
                        "INSERT INTO response_safeguard_rule (code, kind, value) "
                        "VALUES ('new-protection', 'network', '8.8.8.0/24')"
                    )
                )
        with Session(runtime) as db, db.begin():
            assert (
                perform_manual_rollback(db, action, actor, stamp, load_legacy_policy()) == "refused"
            )
        with Session(runtime) as db, db.begin():
            assert pending_manual_rollbacks(db, 10) == []
        client.cookies.clear()
        listed = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst)
        assert listed.json()["items"][0]["rollback_request_status"] == "refused"
        with owner.begin() as db:
            if changed == "role":
                db.execute(
                    text(
                        "UPDATE users SET role_id=(SELECT id FROM roles "
                        "WHERE name='senior_analyst') WHERE id=:id"
                    ),
                    {"id": actor},
                )
            else:
                db.execute(text("DELETE FROM response_safeguard_rule WHERE code='new-protection'"))
        with Session(runtime) as db, db.begin():
            assert perform_manual_rollback(db, action, actor, stamp, load_legacy_policy()) == "noop"
        client.cookies.clear()
        assert (
            client.post(
                "/api/response/kill-switch", headers=admin, json={"engaged": True}
            ).status_code
            == 200
        )
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            client.cookies.clear()
            retry = client.post(f"/api/response/actions/{action}/rollback", headers=admin, json={})
        assert retry.status_code == 202 and retry.json()["rollback_request_status"] == "pending"
        new_stamp = datetime.fromisoformat(retry.json()["rollback_requested_at"])
        with Session(runtime) as db, db.begin():
            assert perform_manual_rollback(db, action, actor, stamp, load_legacy_policy()) == "noop"
        with Session(runtime) as db, db.begin():
            assert (
                perform_manual_rollback(
                    db, action, pb2_api.accounts["admin"].id, new_stamp, load_legacy_policy()
                )
                == "rolled_back"
            )
        client.cookies.clear()
        listed = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst)
        assert listed.json()["items"][0]["rollback_request_status"] == "resolved"
        assert (
            client.post(
                f"/api/response/actions/{action}/rollback", headers=admin, json={}
            ).status_code
            == 409
        )
    finally:
        owner.dispose()
        runtime.dispose()


def test_manual_l3_execution_and_rollback_go_through_a_running_worker(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    incident = _incident(pb2_api)
    body = {
        "incident_id": str(incident),
        "action_type": "isolate_host",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    condition = threading.Condition()
    events: list[tuple[str, str, object]] = []

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        name = getattr(sender, "name", "")
        if name in {EXECUTE_RESPONSE_TASK, MANUAL_ROLLBACK_TASK}:
            with condition:
                events.append((name, state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    try:
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            pending = _create(pb2_api, analyst, body)
            assert pending.status_code == 201 and pending.json()["status"] == "pending_approval"
            action = pending.json()["id"]
            client.cookies.clear()
            assert (
                client.post(
                    "/api/response/kill-switch", headers=admin, json={"engaged": True}
                ).status_code
                == 200
            )
            approved = client.post(
                f"/api/response/actions/{action}/approve", headers=senior, json={}
            )
            assert approved.status_code == 200
            with condition:
                assert condition.wait_for(lambda: len(events) >= 1, timeout=20)
            assert events[0] == (EXECUTE_RESPONSE_TASK, "SUCCESS", {"result": "executed"})
            client.cookies.clear()
            rollback = client.post(
                f"/api/response/actions/{action}/rollback", headers=admin, json={}
            )
            assert rollback.status_code == 202
            with condition:
                assert condition.wait_for(lambda: len(events) >= 2, timeout=20)
            assert events[1] == (MANUAL_ROLLBACK_TASK, "SUCCESS", {"result": "rolled_back"})
        client.cookies.clear()
        listing = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst)
        assert listing.json()["items"][0]["status"] == "rolled_back"
    finally:
        task_postrun.disconnect(observed)


def test_action_list_uses_bounded_cursor_and_incident_filter(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst = pb2_api.login("analyst")
    first_incident = _incident(pb2_api)
    second_incident = _incident(pb2_api)
    identifiers: set[str] = set()
    for index in range(3):
        response = _create(
            pb2_api,
            analyst,
            {
                "incident_id": str(first_incident),
                "action_type": "advisory",
                "target": {"value": f"item-{index}"},
                "params": {"message": "Review"},
            },
        )
        assert response.status_code == 201
        identifiers.add(response.json()["id"])
    other = _create(
        pb2_api,
        analyst,
        {
            "incident_id": str(second_incident),
            "action_type": "advisory",
            "target": {"value": "other"},
            "params": {"message": "Review"},
        },
    )
    assert other.status_code == 201
    found: list[str] = []
    cursor = None
    for _ in range(4):
        query = {"incident_id": str(first_incident), "limit": "1"}
        if cursor is not None:
            query["cursor"] = cursor
        client.cookies.clear()
        page = client.get("/api/response/actions", headers=analyst, params=query)
        assert page.status_code == 200
        assert_response_contract("GET", "/api/response/actions", page)
        found.extend(item["id"] for item in page.json()["items"])
        cursor = page.json()["next_cursor"]
        if cursor is None:
            break
    else:
        pytest.fail("Action pagination did not terminate")
    assert len(found) == len(set(found)) == 3 and set(found) == identifiers
    client.cookies.clear()
    assert client.get("/api/response/actions?cursor=bad", headers=analyst).status_code == 400
    assert client.get("/api/response/actions?limit=5", headers=analyst).status_code == 422
    empty = client.get(f"/api/response/actions?incident_id={uuid4()}", headers=analyst)
    assert empty.status_code == 200 and empty.json()["items"] == []


def test_beat_recovers_lost_manual_rollback_while_switch_engaged(
    pb2_api: PB2API, runtime_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    incident = _incident(pb2_api)
    body = {
        "incident_id": str(incident),
        "action_type": "isolate_host",
        "target": {"agent_id": "004", "ip": "8.8.8.8"},
        "params": {},
    }
    runtime = create_engine(runtime_url, hide_parameters=True)
    condition = threading.Condition()
    events: list[tuple[str, object]] = []

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OperationalError("unavailable")

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        if getattr(sender, "name", None) == RECONCILE_RESPONSE_TASK:
            with condition:
                events.append((state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            pending = _create(pb2_api, analyst, body)
            assert pending.status_code == 201
            action = UUID(pending.json()["id"])
            client.cookies.clear()
            assert (
                client.post(
                    "/api/response/kill-switch", headers=admin, json={"engaged": True}
                ).status_code
                == 200
            )
            approved = client.post(
                f"/api/response/actions/{action}/approve", headers=senior, json={}
            )
            assert approved.status_code == 200
            with Session(runtime) as db, db.begin():
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "executed"
                )
            client.cookies.clear()
            rollback = client.post(
                f"/api/response/actions/{action}/rollback", headers=admin, json={}
            )
            assert rollback.status_code == 202
        scheduler = Scheduler(app=app.state.celery)
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            scheduler.apply_async(scheduler.schedule[RECONCILE_RESPONSE_SCHEDULE], advance=False)
            with condition:
                assert condition.wait_for(lambda: bool(events), timeout=20)
        assert events[0][0] == "SUCCESS" and events[0][1]["manual_rolled_back"] == 1
        client.cookies.clear()
        listing = client.get(f"/api/response/actions?incident_id={incident}", headers=analyst)
        assert listing.json()["items"][0]["status"] == "rolled_back"
    finally:
        task_postrun.disconnect(observed)
        runtime.dispose()
