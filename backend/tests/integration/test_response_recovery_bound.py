"""A response recovery run respects one shared, fair configured batch bound."""

import threading
from datetime import datetime
from typing import Any
from uuid import UUID

import pytest
from celery.beat import Scheduler
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from kombu.exceptions import OperationalError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.auth.legacy_policy import load_legacy_policy
from app.core.pb2_config import load_pb2_settings
from app.core.pb3_config import load_pb3_settings
from app.jobs.celery_app import (
    RECONCILE_RESPONSE_SCHEDULE,
    RECONCILE_RESPONSE_TASK,
    create_celery,
)
from app.main import app
from app.response.execution import execute_approved
from tests.integration.conftest import PB2API


@pytest.mark.parametrize("batch_size", [1, 2])
def test_mixed_recovery_is_bounded_and_makes_progress_with_a_real_worker(
    pb2_api: PB2API, runtime_url: str, monkeypatch: pytest.MonkeyPatch, batch_size: int
) -> None:
    client = pb2_api.client
    analyst, admin = (pb2_api.login(role) for role in ("analyst", "admin"))
    owner = create_engine(pb2_api.database_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    condition = threading.Condition()
    events: list[tuple[str, dict[str, int]]] = []

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OperationalError("broker temporarily unavailable")

    def observed(sender: object = None, state: str = "", retval: Any = None, **_: object) -> None:
        if getattr(sender, "name", None) == RECONCILE_RESPONSE_TASK:
            with condition:
                events.append((state, retval))
                condition.notify_all()

    celery = None
    task_postrun.connect(observed, weak=False)
    try:
        with owner.begin() as db:
            incident = db.execute(
                text("INSERT INTO incidents (title) VALUES ('recovery bound') RETURNING id")
            ).scalar_one()
        l1 = {
            "incident_id": str(incident),
            "action_type": "ioc_add",
            "target": {"value": "same unkeyed request"},
            "params": {},
        }
        l2 = {
            "incident_id": str(incident),
            "action_type": "firewall_drop",
            "target": {"agent_id": "004", "ip": "8.8.8.8"},
            "params": {},
            "mode": "automatic",
        }
        work: list[tuple[UUID, str]] = []
        with monkeypatch.context() as patch:
            patch.setattr(app.state.celery, "send_task", unavailable)
            for _ in range(2):
                client.cookies.clear()
                approved = client.post("/api/response/actions", headers=analyst, json=l1)
                assert approved.status_code == 201
                work.append((UUID(approved.json()["id"]), "execute"))
                client.cookies.clear()
                executed = client.post("/api/response/actions", headers=analyst, json=l2)
                assert executed.status_code == 201
                action = UUID(executed.json()["id"])
                with Session(runtime) as db, db.begin():
                    assert (
                        execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                        == "executed"
                    )
                client.cookies.clear()
                requested = client.post(
                    f"/api/response/actions/{action}/rollback", headers=admin, json={}
                )
                assert requested.status_code == 202
                assert datetime.fromisoformat(requested.json()["rollback_requested_at"]).tzinfo
                work.append((action, "rollback"))
        assert len({identifier for identifier, _ in work}) == 4
        response_settings = load_pb3_settings({"RESPONSE_SWEEP_BATCH_SIZE": str(batch_size)})
        celery = create_celery(load_pb2_settings(), response_settings)
        scheduler = Scheduler(app=celery)
        runs = (len(work) + batch_size - 1) // batch_size
        with start_worker(celery, pool="solo", perform_ping_check=False, loglevel="ERROR"):
            for index in range(runs):
                scheduler.apply_async(
                    scheduler.schedule[RECONCILE_RESPONSE_SCHEDULE], advance=False
                )
                with condition:
                    assert condition.wait_for(lambda index=index: len(events) > index, timeout=20)
                state, counts = events[index]
                assert state == "SUCCESS"
                assert sum(counts.values()) == min(batch_size, len(work) - index * batch_size)
                completed = min((index + 1) * batch_size, len(work))
                with owner.connect() as db:
                    for position, (identifier, kind) in enumerate(work):
                        status = db.execute(
                            text("SELECT status FROM response_actions WHERE id=:id"),
                            {"id": identifier},
                        ).scalar_one()
                        expected = (
                            ("executed" if kind == "execute" else "rolled_back")
                            if position < completed
                            else ("approved" if kind == "execute" else "executed")
                        )
                        assert status == expected
        assert sum(event[1]["executed"] for event in events) == 2
        assert sum(event[1]["manual_rolled_back"] for event in events) == 2
        with owner.connect() as db:
            assert db.execute(text("SELECT count(*) FROM executed_commands")).scalar_one() == 6
    finally:
        task_postrun.disconnect(observed)
        if celery is not None:
            celery.close()
        owner.dispose()
        runtime.dispose()
