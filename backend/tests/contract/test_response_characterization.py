"""Independent end-to-end PB3 legacy response characterization baseline."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any
from uuid import UUID

import pytest
from celery.beat import Scheduler
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.jobs.celery_app import (
    EXECUTE_RESPONSE_TASK,
    MANUAL_ROLLBACK_TASK,
    TTL_SWEEP_SCHEDULE,
    TTL_SWEEP_TASK,
)
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def _incident(owner: Engine) -> UUID:
    with owner.begin() as db:
        return db.execute(
            text("INSERT INTO incidents (title) VALUES ('legacy characterization') RETURNING id")
        ).scalar_one()


def _create(api: PB2API, headers: dict[str, Redacted], body: dict[str, Any]) -> object:
    api.client.cookies.clear()
    return api.client.post("/api/response/actions", headers=headers, json=body)


def _command_rows(owner: Engine, action: str) -> list[tuple[str, str, str, bool]]:
    with owner.connect() as db:
        return list(
            db.execute(
                text(
                    "SELECT phase, connector, command, simulated FROM executed_commands "
                    "WHERE action_id=:id ORDER BY id"
                ),
                {"id": UUID(action)},
            ).all()
        )


def test_full_ladder_and_ttl_switch_are_frozen_through_api_and_worker(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    incident = _incident(owner)
    events: list[tuple[str, str, object]] = []
    condition = threading.Condition()

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        name = getattr(sender, "name", "")
        if name in {EXECUTE_RESPONSE_TASK, MANUAL_ROLLBACK_TASK, TTL_SWEEP_TASK}:
            with condition:
                events.append((name, state, retval))
                condition.notify_all()

    def await_event(name: str, number: int) -> tuple[str, str, object]:
        with condition:
            assert condition.wait_for(
                lambda: sum(event[0] == name for event in events) >= number, timeout=20
            )
            return [event for event in events if event[0] == name][number - 1]

    # This table is intentionally independent of the application catalog.
    cases = (
        ("advisory", 0, {"value": "review"}, {"message": "Review"}, None, "advised", None, None),
        ("ioc_add", 1, {"value": "indicator"}, {}, None, "approved", "internal", "ioc_add"),
        ("ioc_update", 1, {"value": "indicator"}, {}, None, "approved", "internal", "ioc_update"),
        ("fp_mute", 1, {"value": "rule"}, {}, None, "approved", "internal", "fp_mute"),
        (
            "escalate",
            1,
            {"value": "team"},
            {"message": "Review"},
            None,
            "approved",
            "internal",
            "escalate",
        ),
        (
            "notify",
            1,
            {"value": "team"},
            {"message": "Review"},
            None,
            "approved",
            "internal",
            "notify",
        ),
        (
            "firewall_drop",
            2,
            {"agent_id": "004", "ip": "8.8.8.8"},
            {},
            "automatic",
            "approved",
            "simulated_wazuh",
            "firewall_drop",
        ),
        (
            "firewall_allow",
            2,
            {"agent_id": "004", "ip": "8.8.4.4"},
            {},
            "manual",
            "pending_approval",
            "simulated_wazuh",
            "firewall_allow",
        ),
        (
            "isolate_host",
            3,
            {"agent_id": "004", "ip": "1.1.1.1"},
            {},
            None,
            "pending_approval",
            "simulated_wazuh",
            "isolate_host",
        ),
        (
            "permanent_block",
            3,
            {"agent_id": "004", "ip": "9.9.9.9"},
            {},
            None,
            "pending_approval",
            "simulated_wazuh",
            "firewall_drop",
        ),
    )
    identifiers: dict[str, str] = {}
    executions = 0
    task_postrun.connect(observed, weak=False)
    try:
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            for name, level, target, params, mode, initial, connector, command in cases:
                body: dict[str, Any] = {
                    "incident_id": str(incident),
                    "action_type": name,
                    "target": target,
                    "params": params,
                }
                if mode is not None:
                    body["mode"] = mode
                if level == 2:
                    body["ttl_seconds"] = 60
                created = _create(pb2_api, analyst, body)
                assert created.status_code == 201
                action = created.json()["id"]
                identifiers[name] = action
                assert created.json()["level"] == level and created.json()["status"] == initial
                if initial == "pending_approval":
                    client.cookies.clear()
                    approved = client.post(
                        f"/api/response/actions/{action}/approve", headers=senior, json={}
                    )
                    assert approved.status_code == 200 and approved.json()["status"] == "approved"
                if level == 0:
                    assert _command_rows(owner, action) == []
                    continue
                executions += 1
                assert await_event(EXECUTE_RESPONSE_TASK, executions) == (
                    EXECUTE_RESPONSE_TASK,
                    "SUCCESS",
                    {"result": "executed"},
                )
                assert _command_rows(owner, action) == [("execute", connector, command, True)]
            l2_ids = (identifiers["firewall_drop"], identifiers["firewall_allow"])
            with owner.connect() as db:
                deadlines = [
                    db.execute(
                        text("SELECT ttl_expires_at FROM response_actions WHERE id=:id"),
                        {"id": UUID(identifier)},
                    ).scalar_one()
                    for identifier in l2_ids
                ]
            frozen: datetime = max(deadlines)
            monkeypatch.setattr("app.response.ttl.database_now", lambda _db: frozen)
            client.cookies.clear()
            assert (
                client.post(
                    "/api/response/kill-switch", headers=admin, json={"engaged": True}
                ).status_code
                == 200
            )
            scheduler = Scheduler(app=app.state.celery)
            scheduler.apply_async(scheduler.schedule[TTL_SWEEP_SCHEDULE], advance=False)
            first_sweep = await_event(TTL_SWEEP_TASK, 1)
            assert first_sweep[1] == "SUCCESS" and first_sweep[2]["rolled_back"] == 0
            assert all(len(_command_rows(owner, identifier)) == 1 for identifier in l2_ids)
            # A human rollback is still allowed while automation is halted.
            isolate = identifiers["isolate_host"]
            client.cookies.clear()
            assert (
                client.post(
                    f"/api/response/actions/{isolate}/rollback", headers=admin, json={}
                ).status_code
                == 202
            )
            assert await_event(MANUAL_ROLLBACK_TASK, 1) == (
                MANUAL_ROLLBACK_TASK,
                "SUCCESS",
                {"result": "rolled_back"},
            )
            assert _command_rows(owner, isolate)[-1] == (
                "rollback",
                "simulated_wazuh",
                "release_host",
                True,
            )
            client.cookies.clear()
            assert (
                client.post(
                    "/api/response/kill-switch", headers=admin, json={"engaged": False}
                ).status_code
                == 200
            )
            scheduler.apply_async(scheduler.schedule[TTL_SWEEP_SCHEDULE], advance=False)
            second_sweep = await_event(TTL_SWEEP_TASK, 2)
            assert second_sweep[1] == "SUCCESS" and second_sweep[2]["rolled_back"] == 2
            assert _command_rows(owner, l2_ids[0])[-1] == (
                "rollback",
                "simulated_wazuh",
                "firewall_allow",
                True,
            )
            assert _command_rows(owner, l2_ids[1])[-1] == (
                "rollback",
                "simulated_wazuh",
                "firewall_drop",
                True,
            )
            client.cookies.clear()
            assert (
                client.post(
                    f"/api/response/actions/{identifiers['permanent_block']}/rollback",
                    headers=admin,
                    json={},
                ).status_code
                == 409
            )
        with owner.connect() as db:
            for name, level, _, _, _, initial, _, _ in cases:
                rows = (
                    db.execute(
                        text(
                            "SELECT details->>'to' FROM case_activities "
                            "WHERE action='response.transition' AND target=:target ORDER BY id"
                        ),
                        {"target": f"response_action:{identifiers[name]}"},
                    )
                    .scalars()
                    .all()
                )
                expected = [initial]
                if initial == "pending_approval":
                    expected.append("approved")
                if level > 0:
                    expected.extend(["executing", "executed"])
                if name in {"firewall_drop", "firewall_allow", "isolate_host"}:
                    expected.append("rolled_back")
                assert rows == expected
                assert (
                    db.execute(
                        text(
                            "SELECT count(*) FROM case_activities "
                            "WHERE action='response.requested' AND target=:target"
                        ),
                        {"target": f"response_action:{identifiers[name]}"},
                    ).scalar_one()
                    == 1
                )
    finally:
        task_postrun.disconnect(observed)
        owner.dispose()


def test_double_approve_race_through_http_has_one_immutable_decision(pb2_api: PB2API) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        incident = _incident(owner)
        body = {
            "incident_id": str(incident),
            "action_type": "isolate_host",
            "target": {"agent_id": "004", "ip": "8.8.8.8"},
            "params": {},
        }
        pending = _create(pb2_api, analyst, body)
        assert pending.status_code == 201
        action = pending.json()["id"]
        barrier = threading.Barrier(2)
        client.cookies.clear()

        def approve(headers: dict[str, Redacted]) -> object:
            barrier.wait(timeout=10)
            return client.post(f"/api/response/actions/{action}/approve", headers=headers, json={})

        with ThreadPoolExecutor(max_workers=2) as pool:
            one, two = pool.submit(approve, senior), pool.submit(approve, admin)
            results = [one.result(timeout=20), two.result(timeout=20)]
        assert sorted(result.status_code for result in results) == [200, 409]
        with owner.connect() as db:
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
                    text(
                        "SELECT count(*) FROM case_activities WHERE action='response.transition' "
                        "AND target=:target AND details->>'to'='approved'"
                    ),
                    {"target": f"response_action:{action}"},
                ).scalar_one()
                == 1
            )
    finally:
        owner.dispose()


def test_worker_refuses_changed_safeguards_and_demoted_approver_after_http_approval(
    pb2_api: PB2API,
) -> None:
    client = pb2_api.client
    analyst, senior, admin = (pb2_api.login(role) for role in ("analyst", "senior", "admin"))
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    events: list[tuple[str, object]] = []
    condition = threading.Condition()

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        if getattr(sender, "name", None) == EXECUTE_RESPONSE_TASK:
            with condition:
                events.append((state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    try:
        incident = _incident(owner)
        base = {
            "incident_id": str(incident),
            "action_type": "isolate_host",
            "target": {"agent_id": "004", "ip": "8.8.8.8"},
            "params": {},
        }
        protected = _create(pb2_api, analyst, base).json()["id"]
        demoted = _create(
            pb2_api, analyst, {**base, "target": {"agent_id": "005", "ip": "8.8.4.4"}}
        ).json()["id"]
        unapproved = _create(
            pb2_api, analyst, {**base, "target": {"agent_id": "006", "ip": "1.1.1.1"}}
        ).json()["id"]
        client.cookies.clear()
        assert (
            client.post(
                f"/api/response/actions/{protected}/approve", headers=senior, json={}
            ).status_code
            == 200
        )
        assert (
            client.post(
                f"/api/response/actions/{demoted}/approve", headers=admin, json={}
            ).status_code
            == 200
        )
        with owner.begin() as db:
            db.execute(
                text(
                    "INSERT INTO response_safeguard_rule (code, kind, value) "
                    "VALUES ('post-approval', 'agent', '004')"
                )
            )
            db.execute(
                text(
                    "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='analyst') "
                    "WHERE id=:id"
                ),
                {"id": pb2_api.accounts["admin"].id},
            )
        app.state.celery.send_task(
            EXECUTE_RESPONSE_TASK,
            args=[unapproved],
            headers={"initiator": "service:untrusted-test"},
            retry=False,
        )
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            with condition:
                assert condition.wait_for(lambda: len(events) == 3, timeout=20)
        assert sorted(event[1]["result"] for event in events) == ["failed", "failed", "noop"]
        assert all(event[0] == "SUCCESS" for event in events)
        with owner.connect() as db:
            statuses = db.execute(
                text("SELECT id, status FROM response_actions WHERE incident_id=:incident"),
                {"incident": incident},
            ).all()
            assert {str(identifier): status for identifier, status in statuses} == {
                protected: "failed",
                demoted: "failed",
                unapproved: "pending_approval",
            }
            assert db.execute(text("SELECT count(*) FROM executed_commands")).scalar_one() == 0
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
        task_postrun.disconnect(observed)
        owner.dispose()
