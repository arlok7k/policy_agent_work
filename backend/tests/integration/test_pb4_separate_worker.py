"""A separately started deployment worker executes and recovers L3 actions."""

import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from scripts.run_compose_e2e import Redacted, redact_output
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.jobs.celery_app import RECONCILE_INITIATOR, RECONCILE_RESPONSE_TASK
from app.main import app
from tests.integration.conftest import PB2API


def _worker_target() -> str:
    compose = yaml.safe_load(Path("infra/docker-compose.yml").read_text(encoding="utf-8"))
    return str(compose["services"]["celery-worker"]["command"][2])


def _wait_for_worker(process: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if " ready." in log_path.read_text(encoding="utf-8"):
            return
        if process.poll() is not None:
            raise AssertionError("The standalone worker exited before it became ready")
        time.sleep(0.1)
    raise AssertionError("The standalone worker did not become ready")


def _wait_for_command(owner: Engine, process: subprocess.Popen[bytes], action_id: UUID) -> None:
    deadline = time.monotonic() + 30
    last = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("The standalone worker exited before executing the action")
        with owner.connect() as db:
            last = db.execute(
                text(
                    "SELECT status, (SELECT count(*) FROM executed_commands "
                    "WHERE action_id=:id AND phase='execute' AND command='isolate_host' "
                    "AND simulated) AS commands FROM response_actions WHERE id=:id"
                ),
                {"id": action_id},
            ).one()
        if last.status == "executed" and last.commands == 1:
            return
        if last.status == "failed" or last.commands > 1:
            break
        time.sleep(0.2)
    raise AssertionError(f"Expected one executed simulated command; last state: {last}")


def test_fresh_prefork_worker_dispatch_and_reconciliation(
    pb2_api: PB2API, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Do not let the API process's imports supply the worker's metadata."""
    api = pb2_api
    analyst, senior = api.login("analyst"), api.login("senior")
    secret_names = (
        "DATABASE_URL",
        "SESSION_SIGNING_SECRET",
        "CELERY_BROKER_URL",
        "REDIS_CACHE_URL",
    )
    protected = [Redacted(value) for key in secret_names if (value := os.environ.get(key))]
    protected.extend(Redacted(value.reveal()) for value in (*analyst.values(), *senior.values()))
    for account in api.accounts.values():
        protected.extend((Redacted(account.password.reveal()), Redacted(account.digest.reveal())))
    webhook = Path(os.environ["WEBHOOK_SECRET_FILE"]).read_text(encoding="utf-8").rstrip("\r\n")
    protected.append(Redacted(webhook))
    environ = dict(os.environ, PYTHONPATH=str(Path("backend").resolve()), PYTHONUNBUFFERED="1")
    owner = create_engine(api.database_url, hide_parameters=True)
    log_path = tmp_path / "standalone-worker.log"
    try:
        with owner.begin() as db:
            incident = db.execute(
                text("INSERT INTO incidents (title) VALUES ('standalone worker') RETURNING id")
            ).scalar_one()
        command = [
            sys.executable,
            "-m",
            "celery",
            "-A",
            _worker_target(),
            "worker",
            "--loglevel=INFO",
            "--concurrency=2",
            "--hostname=pb4-test@%h",
            "--without-gossip",
            "--without-mingle",
            "--without-heartbeat",
        ]
        with log_path.open("wb") as log:
            process = subprocess.Popen(  # noqa: S603
                command,
                env=environ,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                _wait_for_worker(process, log_path)

                def request_action(value: str) -> UUID:
                    api.client.cookies.clear()
                    response = api.client.post(
                        "/api/response/actions",
                        headers=analyst,
                        json={
                            "incident_id": str(incident),
                            "action_type": "isolate_host",
                            "target": {"agent_id": value, "ip": "8.8.8.8"},
                            "params": {},
                        },
                    )
                    assert response.status_code == 201
                    assert response.json()["status"] == "pending_approval"
                    return UUID(response.json()["id"])

                def approve(action: UUID) -> None:
                    api.client.cookies.clear()
                    response = api.client.post(
                        f"/api/response/actions/{action}/approve", headers=senior, json={}
                    )
                    assert response.status_code == 200
                    assert response.json()["status"] == "approved"

                direct = request_action("004")
                approve(direct)
                _wait_for_command(owner, process, direct)

                # A committed approval survives publication loss and is picked
                # up by the same standalone worker's reconciliation task.
                recovered = request_action("005")

                def unavailable(*args: object, **kwargs: object) -> None:
                    raise OSError("simulated broker publication failure")

                with monkeypatch.context() as patch:
                    patch.setattr(app.state.celery, "send_task", unavailable)
                    approve(recovered)
                with owner.connect() as db:
                    before = db.execute(
                        text(
                            "SELECT status, (SELECT count(*) FROM executed_commands "
                            "WHERE action_id=:id) AS commands FROM response_actions WHERE id=:id"
                        ),
                        {"id": recovered},
                    ).one()
                assert (before.status, before.commands) == ("approved", 0)
                app.state.celery.send_task(
                    RECONCILE_RESPONSE_TASK,
                    headers={"initiator": RECONCILE_INITIATOR},
                    queue="default",
                    retry=False,
                )
                _wait_for_command(owner, process, recovered)
                api.client.cookies.clear()
                commands = api.client.get(
                    f"/api/response/commands?action_id={recovered}", headers=senior
                )
                assert commands.status_code == 200
                assert [
                    (row["command"], row["phase"], row["simulated"])
                    for row in commands.json()["items"]
                ] == [("isolate_host", "execute", True)]
            except BaseException:
                log.flush()
                diagnostic = redact_output(log_path.read_text(encoding="utf-8"), protected)
                print(f"Standalone worker diagnostics:\n{diagnostic}", file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        with suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                # Also clean up any children if a worker died unexpectedly.
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
    finally:
        owner.dispose()
