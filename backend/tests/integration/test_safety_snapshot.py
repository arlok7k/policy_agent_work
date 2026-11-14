"""Safety snapshots serialize rule writes and observe newly protected targets."""

import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.response.rules import lock_safety_snapshot
from app.response.safeguards import SafeguardAction, check_safeguards


def test_snapshot_observes_rule_changes_and_serializes_concurrent_writes(
    migrated_url: str, runtime_url: str
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    started = threading.Event()
    action = {"agent_id": "005", "ip": "8.8.8.8"}
    try:
        with Session(runtime) as db, db.begin():
            first = lock_safety_snapshot(db)
            assert first.kill_switch_engaged is False
            assert check_safeguards(SafeguardAction("firewall_drop", action, {}, first.rules)).ok

        def add_rule() -> None:
            started.set()
            with owner.begin() as db:
                db.execute(
                    text(
                        "INSERT INTO response_safeguard_rule (code, kind, value) "
                        "VALUES ('additional-agent', 'agent', '005')"
                    )
                )

        with Session(runtime) as db:
            transaction = db.begin()
            try:
                locked = lock_safety_snapshot(db)
                assert check_safeguards(
                    SafeguardAction("firewall_drop", action, {}, locked.rules)
                ).ok
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(add_rule)
                    try:
                        assert started.wait(5)
                        with pytest.raises(FutureTimeoutError):
                            future.result(timeout=0.2)
                    finally:
                        transaction.commit()
                    future.result(timeout=10)
            finally:
                if transaction.is_active:
                    transaction.rollback()
        with Session(runtime) as db, db.begin():
            fresh = lock_safety_snapshot(db)
            result = check_safeguards(SafeguardAction("firewall_drop", action, {}, fresh.rules))
            assert result.ok is False and result.reason == "protected_agent"
    finally:
        owner.dispose()
        runtime.dispose()
