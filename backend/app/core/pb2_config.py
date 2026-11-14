"""Required, secret-safe configuration for the PB2 webhook and its transports."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, PositiveInt, SecretStr, ValidationError, field_validator

from app.core.config import ConfigurationError, _read_secret


class PB2Settings(BaseModel):
    """Validate the webhook boundary and two distinct Redis instances."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    webhook_secret: SecretStr
    webhook_initiator: str
    webhook_max_body_bytes: PositiveInt
    webhook_max_field_chars: PositiveInt
    webhook_max_clock_skew_seconds: PositiveInt
    redis_timeout_seconds: PositiveInt
    celery_broker_url: SecretStr
    redis_cache_url: SecretStr

    @field_validator("webhook_secret")
    @classmethod
    def validate_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) < hashlib.sha256().digest_size:
            raise ValueError("webhook secret is too short")
        return value

    @field_validator("webhook_initiator")
    @classmethod
    def validate_initiator(cls, value: str) -> str:
        if re.fullmatch(r"service:[A-Za-z0-9][A-Za-z0-9._:-]*", value, flags=re.ASCII) is None:
            raise ValueError("invalid webhook service initiator")
        return value


def _redis_endpoint(value: SecretStr, *, broker: bool) -> tuple[str, str, int | None]:
    """Return nonsecret endpoint identity, rejecting unsupported transport schemes."""
    try:
        parsed = urlsplit(value.get_secret_value())
        if broker and parsed.scheme == "redis+socket":
            if parsed.netloc or not parsed.path.startswith("/"):
                raise ValueError("invalid broker socket")
            return ("unix", parsed.path, None)
        if not broker and parsed.scheme == "unix":
            if parsed.netloc or not parsed.path.startswith("/"):
                raise ValueError("invalid cache socket")
            return ("unix", parsed.path, None)
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError("invalid Redis URL")
        return ("tcp", parsed.hostname.lower(), parsed.port or 6379)
    except ValueError:
        raise ConfigurationError("Invalid Redis configuration") from None


def load_pb2_settings(environ: Mapping[str, str] | None = None) -> PB2Settings:
    """Load PB2 settings; webhook signing material is permitted only in a file."""
    source = os.environ if environ is None else environ
    if source.get("WEBHOOK_SECRET") is not None:
        raise ConfigurationError("Webhook signing material must come from a secret file")
    try:
        settings = PB2Settings.model_validate(
            {
                "webhook_secret": SecretStr(_read_secret("WEBHOOK_SECRET", source)),
                "webhook_initiator": source.get("WEBHOOK_INITIATOR", ""),
                "webhook_max_body_bytes": source.get("WEBHOOK_MAX_BODY_BYTES"),
                "webhook_max_field_chars": source.get("WEBHOOK_MAX_FIELD_CHARS"),
                "webhook_max_clock_skew_seconds": source.get("WEBHOOK_MAX_CLOCK_SKEW_SECONDS"),
                "redis_timeout_seconds": source.get("REDIS_TIMEOUT_SECONDS"),
                "celery_broker_url": SecretStr(_read_secret("CELERY_BROKER_URL", source)),
                "redis_cache_url": SecretStr(_read_secret("REDIS_CACHE_URL", source)),
            }
        )
        broker = _redis_endpoint(settings.celery_broker_url, broker=True)
        cache = _redis_endpoint(settings.redis_cache_url, broker=False)
        if broker == cache:
            raise ConfigurationError("Broker and cache must use separate Redis instances")
        return settings
    except ValidationError:
        raise ConfigurationError("Invalid PB2 configuration") from None
