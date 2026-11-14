"""Bounded database-clock cleanup, login races and actual Beat publication."""

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from ipaddress import ip_address

import pytest
from celery import Celery
from celery.beat import Scheduler
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from sqlalchemy import create_engine, text

from app.auth.service import AuthFailure, login
from app.auth.throttle import cleanup_expired_buckets
from app.core.security import credential_digest
from app.jobs.celery_app import CLEANUP_SCHEDULE, CLEANUP_THROTTLE_TASK
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def _synthetic_bucket(index: int) -> bytes:
    # These fixed labels are not derived from credentials or real throttle keys.
    return index.to_bytes(32, byteorder="big")


def _seed_bucket(api: PB2API, digest: bytes, age_seconds: int, failures: int = 1) -> None:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "INSERT INTO auth_login_throttle "
                    "(bucket_digest, failure_count, window_started_at) "
                    "VALUES (:digest, :count, clock_timestamp() - :age * interval '1 second')"
                ),
                {"digest": digest, "count": failures, "age": age_seconds},
            )
    finally:
        engine.dispose()


def _cleanup(window: int = 60, batch: int = 3) -> int:
    with app.state.session_factory.begin() as db:
        return cleanup_expired_buckets(db, window_seconds=window, batch_size=batch)


def _digests(api: PB2API) -> set[bytes]:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            return set(db.execute(text("SELECT bucket_digest FROM auth_login_throttle")).scalars())
    finally:
        engine.dispose()


def _seed_login_buckets(api: PB2API) -> None:
    settings = app.state.settings
    source = Redacted(
        credential_digest(settings.session_signing_secret, "throttle-ip", "127.0.0.1").hex()
    )
    account = Redacted(
        credential_digest(settings.session_signing_secret, "throttle-account", "analyst").hex()
    )
    _seed_bucket(api, bytes.fromhex(source.reveal()), 120, failures=1)
    _seed_bucket(api, bytes.fromhex(account.reveal()), 120, failures=1)


def test_cleanup_uses_database_clock_and_never_exceeds_batch(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index, age in enumerate((120, 119, 118, 117, 116, 0)):
        _seed_bucket(pb2_api, _synthetic_bucket(index), age)
    with monkeypatch.context() as patch:
        patch.setattr(time, "time", lambda: 2**40)
        assert _cleanup() == 3
    assert _digests(pb2_api) == {_synthetic_bucket(index) for index in (3, 4, 5)}
    with monkeypatch.context() as patch:
        patch.setattr(time, "time", lambda: 0.0)
        assert _cleanup() == 2
    assert _cleanup() == 0
    assert _digests(pb2_api) == {_synthetic_bucket(5)}
    for invalid in ((0, 3), (60, 0), (-1, 3), (60, -1)):
        with app.state.session_factory.begin() as db, pytest.raises(ValueError):
            cleanup_expired_buckets(db, window_seconds=invalid[0], batch_size=invalid[1])


def test_active_failure_limit_survives_scheduled_cleanup(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = app.state.settings.model_copy(update={"login_failure_limit": 1})
    bad = Redacted.random()
    with monkeypatch.context() as patch:
        patch.setitem(app.state._state, "settings", settings)
        pb2_api.client.cookies.clear()
        first = pb2_api.client.post(
            "/api/auth/login", json={"username": "analyst", "password": bad}
        )
        assert first.status_code == 401
        assert _cleanup() == 0
        second = pb2_api.client.post(
            "/api/auth/login", json={"username": "analyst", "password": bad}
        )
        assert second.status_code == 429


def test_cleanup_skips_expired_rows_locked_by_a_concurrent_login(pb2_api: PB2API) -> None:
    _seed_login_buckets(pb2_api)
    settings = app.state.settings.model_copy(update={"login_failure_limit": 1})
    passwords = app.state.passwords
    reached = threading.Event()
    resume = threading.Event()
    bad = Redacted.random()

    class BlockingPasswords:
        def verify(self, candidate: str, digest: str | None) -> bool:
            reached.set()
            assert resume.wait(10)
            return passwords.verify(candidate, digest)

    def attempt() -> object:
        with app.state.session_factory() as db:
            return login(
                db,
                settings,
                BlockingPasswords(),
                "analyst",
                bad.reveal(),
                ip_address("127.0.0.1"),
                None,
            )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(attempt)
        try:
            assert reached.wait(10)
            # The login holds both rows even though their prior windows expired.
            assert _cleanup() == 0
        finally:
            resume.set()
        assert future.result(timeout=15) == AuthFailure.INVALID
    assert _cleanup() == 0
    with app.state.session_factory() as db:
        outcome = login(
            db, settings, passwords, "analyst", bad.reveal(), ip_address("127.0.0.1"), None
        )
    assert outcome == AuthFailure.THROTTLED


def test_login_waiting_for_cleanup_starts_a_new_protected_window(pb2_api: PB2API) -> None:
    _seed_login_buckets(pb2_api)
    settings = app.state.settings.model_copy(update={"login_failure_limit": 1})
    passwords = app.state.passwords
    bad = Redacted.random()
    started = threading.Event()
    held = app.state.session_factory()
    transaction = held.begin()
    try:
        assert cleanup_expired_buckets(held, window_seconds=60, batch_size=3) == 2

        def attempt() -> object:
            started.set()
            with app.state.session_factory() as db:
                return login(
                    db, settings, passwords, "analyst", bad.reveal(), ip_address("127.0.0.1"), None
                )

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(attempt)
            try:
                assert started.wait(10)
                with pytest.raises(FutureTimeoutError):
                    future.result(timeout=0.2)
            finally:
                transaction.commit()
            assert future.result(timeout=15) == AuthFailure.INVALID
        assert _cleanup() == 0
        with app.state.session_factory() as db:
            second = login(
                db, settings, passwords, "analyst", bad.reveal(), ip_address("127.0.0.1"), None
            )
        assert second == AuthFailure.THROTTLED
    finally:
        if transaction.is_active:
            transaction.rollback()
        held.close()


def test_parallel_cleanup_invocations_are_each_bounded(pb2_api: PB2API) -> None:
    for index in range(5):
        _seed_bucket(pb2_api, _synthetic_bucket(index), 120)
    _seed_bucket(pb2_api, _synthetic_bucket(5), 0)
    barrier = threading.Barrier(2)

    def run() -> int:
        barrier.wait(timeout=10)
        return _cleanup(batch=2)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run) for _ in range(2)]
        counts = [future.result(timeout=15) for future in futures]
    assert counts == [2, 2]
    remaining = _digests(pb2_api)
    assert len(remaining) == 2 and _synthetic_bucket(5) in remaining
    assert _cleanup(batch=2) == 1
    assert _digests(pb2_api) == {_synthetic_bucket(5)}


def test_real_beat_dispatch_requires_initiator_and_worker_runs_cleanup(pb2_api: PB2API) -> None:
    _seed_bucket(pb2_api, _synthetic_bucket(0), 120)
    events: list[tuple[str, object]] = []
    condition = threading.Condition()

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        if getattr(sender, "name", None) == CLEANUP_THROTTLE_TASK:
            with condition:
                events.append((state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    publisher = Celery("untrusted-test-publisher", broker=os.environ["TEST_REDIS_BROKER_URL"])
    try:
        scheduler = Scheduler(app=app.state.celery)
        assert set(scheduler.schedule) == {CLEANUP_SCHEDULE}
        entry = scheduler.schedule[CLEANUP_SCHEDULE]
        assert entry.options["headers"]["initiator"] == "service:test-throttle-cleanup"
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            publisher.send_task(
                CLEANUP_THROTTLE_TASK,
                queue="default",
                retry=False,
                argsrepr="<redacted>",
                kwargsrepr="<redacted>",
            )
            with condition:
                assert condition.wait_for(lambda: len(events) == 1, timeout=20)
            assert events[0][0] == "FAILURE" and _digests(pb2_api) == {_synthetic_bucket(0)}
            scheduler.apply_async(entry, advance=False)
            with condition:
                assert condition.wait_for(lambda: len(events) == 2, timeout=20)
        assert events[1] == ("SUCCESS", {"deleted": 1})
        assert _digests(pb2_api) == set()
    finally:
        publisher.close()
        task_postrun.disconnect(observed)
