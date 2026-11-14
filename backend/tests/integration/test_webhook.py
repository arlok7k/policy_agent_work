"""Authenticated webhook boundary against disposable PostgreSQL and Redis."""

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Condition
from uuid import UUID, uuid4

import pytest
from celery import Celery
from celery.contrib.testing.worker import start_worker
from celery.signals import task_postrun
from kombu.exceptions import OperationalError
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import create_engine, text

from app.core.logging import logger
from app.main import app
from tests.sensitive import Redacted, SecretAwareTestClient, assert_not_disclosed, reveal


@dataclass(frozen=True)
class WebhookHarness:
    client: SecretAwareTestClient
    signing: Redacted
    broker: Redis[bytes]
    cache: Redis[bytes]
    database_url: str


@pytest.fixture
def webhook(
    runtime_url: str, migrated_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[WebhookHarness]:
    if os.environ.get("TEST_REDIS_DISPOSABLE") != "1":
        pytest.fail("TEST_REDIS_DISPOSABLE=1 requires two genuinely disposable Redis instances")
    broker_url = os.environ.get("TEST_REDIS_BROKER_URL")
    broker_client_url = os.environ.get("TEST_REDIS_BROKER_CLIENT_URL")
    cache_url = os.environ.get("TEST_REDIS_CACHE_URL")
    if not broker_url or not broker_client_url or not cache_url:
        pytest.fail("Configure disposable Redis broker, broker-client and cache URLs")
    broker: Redis[bytes] = Redis.from_url(broker_client_url, socket_timeout=2)
    cache: Redis[bytes] = Redis.from_url(cache_url, socket_timeout=2)
    if any(client.connection_pool.connection_kwargs.get("db") != 15 for client in (broker, cache)):
        pytest.fail("Redis tests require explicitly disposable database 15")
    # These are brand-new disposable instances, and the explicit guard above is mandatory.
    broker.flushdb()
    cache.flushdb()
    signing = Redacted.random(48)
    secret_file = tmp_path / "webhook-key"
    secret_file.write_text(signing.reveal(), encoding="utf-8")
    values: dict[str, str | Redacted] = {
        "ENV": "test",
        "DATABASE_URL": runtime_url,
        "SESSION_SIGNING_SECRET": Redacted.random(48),
        "SESSION_TTL_SECONDS": "3600",
        "LOGIN_FAILURE_LIMIT": "5",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "20",
        "MAX_PAGE_SIZE": "50",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "3600",
        "WEBHOOK_SECRET_FILE": str(secret_file),
        "WEBHOOK_INITIATOR": "service:test-webhook",
        "WEBHOOK_MAX_BODY_BYTES": "1024",
        "WEBHOOK_MAX_FIELD_CHARS": "128",
        "WEBHOOK_MAX_CLOCK_SKEW_SECONDS": "60",
        "REDIS_TIMEOUT_SECONDS": "2",
        "CELERY_BROKER_URL": broker_url,
        "REDIS_CACHE_URL": cache_url,
    }
    for key in ("DATABASE_URL_FILE", "SESSION_SIGNING_SECRET_FILE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, reveal(value))
    try:
        with SecretAwareTestClient(app, base_url="https://testserver") as client:
            yield WebhookHarness(client, signing, broker, cache, migrated_url)
    finally:
        broker.flushdb()
        cache.flushdb()
        broker.close()
        cache.close()


def _body(**overrides: object) -> bytes:
    payload: dict[str, object] = {
        "source": "sensor",
        "rule_id": "rule-42",
        "severity": "high",
        "src_ip": "2001:db8::1",
        "raw": {"message": "<script>alert('plain data')</script>; ' OR 1=1 --"},
    }
    payload.update(overrides)
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _headers(
    secret: Redacted, body: bytes, *, event_id: UUID | None = None, timestamp: int | None = None
) -> dict[str, str | Redacted]:
    event = str(event_id or uuid4())
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    message = stamp.encode("ascii") + b"." + event.encode("ascii") + b"." + body
    signature = Redacted(
        "sha256=" + hmac.new(secret.reveal().encode("utf-8"), message, hashlib.sha256).hexdigest()
    )
    return {
        "X-Webhook-Timestamp": stamp,
        "X-Webhook-Id": event,
        "X-Webhook-Signature": signature,
        "Content-Type": "application/json",
    }


def _counts(webhook: WebhookHarness) -> tuple[int, int, int]:
    engine = create_engine(webhook.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            alerts = db.execute(text("SELECT count(*) FROM alerts")).scalar_one()
        return alerts, webhook.broker.llen("default"), webhook.cache.dbsize()
    finally:
        engine.dispose()


def test_valid_signature_enqueues_one_redacted_celery_message(webhook: WebhookHarness) -> None:
    body = _body()
    headers = _headers(webhook.signing, body)
    response = webhook.client.post("/api/alerts/webhook", content=body, headers=headers)
    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    assert response.headers["Cache-Control"] == "no-store"
    assert _counts(webhook) == (0, 1, 1)
    queued = webhook.broker.lrange("default", 0, -1)
    assert len(queued) == 1
    message = json.loads(queued[0])
    assert message["headers"]["task"] == "app.jobs.normalize_alert"
    assert message["headers"]["initiator"] == "service:test-webhook"
    assert message["headers"]["argsrepr"] == "<redacted>"
    args, kwargs, _ = json.loads(base64.b64decode(message["body"]))
    assert kwargs == {}
    assert args[0]["src_ip"] == "2001:db8::1"
    assert args[0]["raw"]["message"] == "<script>alert('plain data')</script>; ' OR 1=1 --"
    assert_not_disclosed("Webhook response", response.text, webhook.signing)


def test_missing_or_bad_signature_has_no_side_effects_and_logs_attempt(
    webhook: WebhookHarness, caplog: pytest.LogCaptureFixture
) -> None:
    body = _body()
    missing = _headers(webhook.signing, body)
    del missing["X-Webhook-Signature"]
    bad = _headers(webhook.signing, body)
    bad_signature = Redacted.random()
    bad["X-Webhook-Signature"] = bad_signature
    logger.addHandler(caplog.handler)
    try:
        before = _counts(webhook)
        for headers in (missing, bad):
            response = webhook.client.post("/api/alerts/webhook", content=body, headers=headers)
            assert response.status_code == 401
            assert set(response.json()) == {"type", "title", "status", "code", "correlation_id"}
            assert _counts(webhook) == before
            assert_not_disclosed("Webhook rejection", response.text, webhook.signing, bad_signature)
        events = [
            json.loads(record.getMessage())
            for record in caplog.records
            if record.name == "smart_soc"
        ]
        assert len(events) == 2
        assert all(event["op"] == "POST /api/alerts/webhook" for event in events)
        assert all(event["status"] == 401 and event["outcome"] == "denied" for event in events)
        assert_not_disclosed("Webhook logs", caplog.text, webhook.signing, bad_signature)
        assert "plain data" not in caplog.text
    finally:
        logger.removeHandler(caplog.handler)


def test_replay_and_concurrent_replay_do_not_enqueue_again(webhook: WebhookHarness) -> None:
    body = _body()
    event_id = uuid4()
    headers = _headers(webhook.signing, body, event_id=event_id)
    with ThreadPoolExecutor(max_workers=6) as workers:
        responses = list(
            workers.map(
                lambda _: webhook.client.post("/api/alerts/webhook", content=body, headers=headers),
                range(6),
            )
        )
    assert sorted(response.status_code for response in responses) == [202, 409, 409, 409, 409, 409]
    assert _counts(webhook) == (0, 1, 1)
    changed = _body(rule_id="different-rule")
    same_event = _headers(webhook.signing, changed, event_id=event_id)
    assert (
        webhook.client.post("/api/alerts/webhook", content=changed, headers=same_event).status_code
        == 409
    )
    assert _counts(webhook) == (0, 1, 1)


@pytest.mark.parametrize("offset", [-120, 120])
def test_stale_or_future_signature_is_rejected(webhook: WebhookHarness, offset: int) -> None:
    body = _body()
    headers = _headers(webhook.signing, body, timestamp=int(time.time()) + offset)
    response = webhook.client.post("/api/alerts/webhook", content=body, headers=headers)
    assert response.status_code == 401
    assert _counts(webhook) == (0, 0, 0)


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        b'{"source":"a","source":"b","rule_id":"r","severity":"high"}',
        b'{"source":"a","rule_id":"r","severity":"high","raw":{"n":NaN}}',
        b'{"source":"a","rule_id":"r","severity":"high","raw":{"n":1e999}}',
        b'{"source":"a","rule_id":"r","severity":"high","src_ip":"not-an-ip"}',
        b'{"source":"a","rule_id":"r","severity":"high","unexpected":true}',
        b'{"source":"a","rule_id":"r","severity":"high","raw":{"n":"\\u0000"}}',
    ],
)
def test_signed_malformed_or_invalid_payload_has_no_side_effects(
    webhook: WebhookHarness, body: bytes
) -> None:
    response = webhook.client.post(
        "/api/alerts/webhook", content=body, headers=_headers(webhook.signing, body)
    )
    assert response.status_code == 400
    assert _counts(webhook) == (0, 0, 0)


def test_oversized_and_extremely_long_fields_are_rejected_before_side_effects(
    webhook: WebhookHarness,
) -> None:
    oversized = b"x" * 1025
    response = webhook.client.post(
        "/api/alerts/webhook", content=oversized, headers=_headers(webhook.signing, oversized)
    )
    assert response.status_code == 413
    long_field = _body(source="a" * 129)
    response = webhook.client.post(
        "/api/alerts/webhook", content=long_field, headers=_headers(webhook.signing, long_field)
    )
    assert response.status_code == 400
    assert _counts(webhook) == (0, 0, 0)


def test_cache_failure_fails_closed_before_publication(
    webhook: WebhookHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _body()

    def fail(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(app.state.redis_cache, "set", fail)
        response = webhook.client.post(
            "/api/alerts/webhook", content=body, headers=_headers(webhook.signing, body)
        )
    assert response.status_code == 503
    assert _counts(webhook) == (0, 0, 0)


def test_ambiguous_publication_failure_keeps_reservation(
    webhook: WebhookHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _body()
    headers = _headers(webhook.signing, body)

    def fail(*args: object, **kwargs: object) -> None:
        raise OperationalError("unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(app.state.celery, "send_task", fail)
        response = webhook.client.post("/api/alerts/webhook", content=body, headers=headers)
    assert response.status_code == 503
    assert _counts(webhook) == (0, 0, 1)
    assert (
        webhook.client.post("/api/alerts/webhook", content=body, headers=headers).status_code == 409
    )
    assert _counts(webhook) == (0, 0, 1)


def test_webhook_to_worker_to_database_deduplicates_and_preserves_data(
    webhook: WebhookHarness,
) -> None:
    completed: list[tuple[str, object]] = []
    condition = Condition()

    def observed(
        sender: object = None, state: str = "", retval: object = None, **_: object
    ) -> None:
        if getattr(sender, "name", None) == "app.jobs.normalize_alert":
            with condition:
                completed.append((state, retval))
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    body = _body()
    try:
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            for _ in range(2):
                response = webhook.client.post(
                    "/api/alerts/webhook", content=body, headers=_headers(webhook.signing, body)
                )
                assert response.status_code == 202
            with condition:
                assert condition.wait_for(lambda: len(completed) == 2, timeout=20)
        assert [state for state, _ in completed] == ["SUCCESS", "SUCCESS"]
        returned = [result for _, result in completed]
        assert all(isinstance(result, dict) for result in returned)
        assert {result["created"] for result in returned if isinstance(result, dict)} == {
            True,
            False,
        }
        assert len({result["id"] for result in returned if isinstance(result, dict)}) == 1
        engine = create_engine(webhook.database_url, hide_parameters=True)
        try:
            with engine.connect() as db:
                rows = db.execute(text("SELECT src_ip, agent, raw FROM alerts")).all()
            assert len(rows) == 1 and str(rows[0].src_ip) == "2001:db8::1"
            assert rows[0].agent is None
            assert rows[0].raw["message"] == "<script>alert('plain data')</script>; ' OR 1=1 --"
        finally:
            engine.dispose()
    finally:
        task_postrun.disconnect(observed)


def test_worker_rejects_a_broker_message_without_an_initiator(webhook: WebhookHarness) -> None:
    completed: list[str] = []
    condition = Condition()

    def observed(sender: object = None, state: str = "", **_: object) -> None:
        if getattr(sender, "name", None) == "app.jobs.normalize_alert":
            with condition:
                completed.append(state)
                condition.notify_all()

    task_postrun.connect(observed, weak=False)
    publisher = Celery("untrusted-test-publisher", broker=os.environ["TEST_REDIS_BROKER_URL"])
    try:
        with start_worker(
            app.state.celery, pool="solo", perform_ping_check=False, loglevel="ERROR"
        ):
            publisher.send_task(
                "app.jobs.normalize_alert",
                args=[json.loads(_body())],
                queue="default",
                retry=False,
                argsrepr="<redacted>",
                kwargsrepr="<redacted>",
            )
            with condition:
                assert condition.wait_for(lambda: len(completed) == 1, timeout=20)
        assert completed == ["FAILURE"]
        assert _counts(webhook) == (0, 0, 0)
    finally:
        publisher.close()
        task_postrun.disconnect(observed)
