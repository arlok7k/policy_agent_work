"""HMAC-authenticated, bounded and replay-protected alert ingestion."""

from __future__ import annotations

import hmac
import re
import time
from uuid import NAMESPACE_URL, UUID, uuid5

from celery import Celery
from fastapi import APIRouter, Request, Response, status
from kombu.exceptions import KombuError
from pydantic import SecretStr
from redis import Redis
from redis.exceptions import RedisError
from starlette.concurrency import run_in_threadpool

from app.alerts.schemas import WebhookAccepted, WebhookAlert
from app.alerts.validation import validate_alert
from app.core.exceptions import BadRequest, Conflict, PayloadTooLarge, Unauthenticated, Unavailable
from app.core.logging import mark_principal
from app.core.pb2_config import PB2Settings
from app.jobs.celery_app import NORMALIZE_ALERT_TASK

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
_SIGNATURE = re.compile(r"sha256=([0-9a-f]{64})\Z", re.ASCII)


def _single_header(request: Request, name: str) -> str:
    values = request.headers.getlist(name)
    if len(values) != 1:
        raise Unauthenticated()
    return values[0]


async def _bounded_body(request: Request, maximum: int) -> bytes:
    length = request.headers.get("Content-Length")
    if length is not None:
        if not length.isascii() or not length.isdecimal():
            raise BadRequest()
        if len(length) > 20 or int(length) > maximum:
            raise PayloadTooLarge()
    result = bytearray()
    async for chunk in request.stream():
        if len(result) + len(chunk) > maximum:
            raise PayloadTooLarge()
        result.extend(chunk)
    return bytes(result)


def verify_webhook_signature(
    secret: SecretStr, timestamp: str, event_id: str, signature: str, body: bytes, *, skew: int
) -> UUID:
    """Authenticate exactly the canonical event ID, supplied timestamp and body."""
    matched = _SIGNATURE.fullmatch(signature)
    if (
        matched is None
        or not timestamp.isascii()
        or not timestamp.isdecimal()
        or len(timestamp) > 20
    ):
        raise Unauthenticated()
    try:
        identifier = UUID(event_id)
        if str(identifier) != event_id or abs(time.time() - int(timestamp)) > skew:
            raise Unauthenticated()
        signed = timestamp.encode("ascii") + b"." + event_id.encode("ascii") + b"." + body
        expected = hmac.digest(secret.get_secret_value().encode("utf-8"), signed, "sha256")
        if not hmac.compare_digest(expected, bytes.fromhex(matched.group(1))):
            raise Unauthenticated()
    except ValueError, UnicodeError, OverflowError:
        raise Unauthenticated() from None
    return identifier


@router.post(
    "/webhook",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=WebhookAccepted,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": WebhookAlert.model_json_schema()}},
        },
        "parameters": [
            {"name": name, "in": "header", "required": True, "schema": {"type": "string"}}
            for name in ("X-Webhook-Timestamp", "X-Webhook-Id", "X-Webhook-Signature")
        ],
    },
)
async def accept_webhook(request: Request, response: Response) -> WebhookAccepted:
    settings: PB2Settings = request.app.state.pb2_settings
    body = await _bounded_body(request, settings.webhook_max_body_bytes)
    timestamp = _single_header(request, "X-Webhook-Timestamp")
    event_id = _single_header(request, "X-Webhook-Id")
    signature = _single_header(request, "X-Webhook-Signature")
    identifier = verify_webhook_signature(
        settings.webhook_secret,
        timestamp,
        event_id,
        signature,
        body,
        skew=settings.webhook_max_clock_skew_seconds,
    )
    payload = validate_alert(body, max_field_chars=settings.webhook_max_field_chars)
    mark_principal(request, "service", uuid5(NAMESPACE_URL, settings.webhook_initiator))

    cache: Redis = request.app.state.redis_cache
    try:
        reserved = await run_in_threadpool(
            cache.set,
            f"webhook:replay:{identifier}",
            b"1",
            nx=True,
            ex=2 * settings.webhook_max_clock_skew_seconds + 1,
        )
    except RedisError:
        raise Unavailable() from None
    if not reserved:
        raise Conflict()

    celery: Celery = request.app.state.celery
    try:
        await run_in_threadpool(
            celery.send_task,
            NORMALIZE_ALERT_TASK,
            args=[payload.model_dump(mode="json")],
            headers={"initiator": settings.webhook_initiator},
            queue="default",
            retry=False,
            argsrepr="<redacted>",
            kwargsrepr="<redacted>",
        )
    except KombuError, RedisError, OSError:
        # Do not release the reservation: publication may have succeeded.
        raise Unavailable() from None
    response.headers["Cache-Control"] = "no-store"
    return WebhookAccepted()
