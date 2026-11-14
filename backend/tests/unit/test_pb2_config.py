"""PB2 secrets and Redis configuration fail closed without disclosure."""

from pathlib import Path

import pytest

from app.core.config import ConfigurationError
from app.core.pb2_config import load_pb2_settings
from tests.sensitive import Redacted, assert_not_disclosed, reveal


@pytest.fixture
def pb2_env(tmp_path: Path) -> tuple[dict[str, str | Redacted], Redacted]:
    signing = Redacted.random(48)
    secret_file = tmp_path / "signing"
    secret_file.write_text(signing.reveal() + "\n", encoding="utf-8")
    credential = Redacted.random(32)
    broker = Redacted(f"redis://:{credential.reveal()}@broker.invalid:6379/0")
    cache = Redacted(f"redis://:{credential.reveal()}@cache.invalid:6379/0")
    return (
        {
            "WEBHOOK_SECRET_FILE": str(secret_file),
            "WEBHOOK_INITIATOR": "service:example",
            "WEBHOOK_MAX_BODY_BYTES": "4096",
            "WEBHOOK_MAX_FIELD_CHARS": "128",
            "WEBHOOK_MAX_CLOCK_SKEW_SECONDS": "60",
            "REDIS_TIMEOUT_SECONDS": "1",
            "THREAT_INTEL_TIMEOUT_SECONDS": "0.1",
            "THREAT_INTEL_CACHE_TTL_SECONDS": "60",
            "THREAT_INTEL_BULK_MAX_ITEMS": "3",
            "INCIDENT_MAX_ALERTS": "3",
            "INCIDENT_MAX_TEXT_CHARS": "128",
            "CELERY_BROKER_URL": broker,
            "REDIS_CACHE_URL": cache,
        },
        signing,
    )


def test_pb2_file_secret_and_redis_urls_are_redacted(
    pb2_env: tuple[dict[str, str | Redacted], Redacted],
) -> None:
    values, signing = pb2_env
    settings = load_pb2_settings(reveal(values))
    matches = settings.webhook_secret.get_secret_value() == signing.reveal()
    assert matches
    broker, cache = values["CELERY_BROKER_URL"], values["REDIS_CACHE_URL"]
    assert isinstance(broker, Redacted) and isinstance(cache, Redacted)
    assert_not_disclosed("PB2 settings representation", repr(settings), signing, broker, cache)


def test_webhook_signing_secret_must_be_in_a_readable_file(
    pb2_env: tuple[dict[str, str | Redacted], Redacted], tmp_path: Path
) -> None:
    values, signing = pb2_env
    values["WEBHOOK_SECRET"] = signing
    with pytest.raises(ConfigurationError):
        load_pb2_settings(reveal(values))
    del values["WEBHOOK_SECRET"]
    values["WEBHOOK_SECRET_FILE"] = str(tmp_path / "absent")
    with pytest.raises(ConfigurationError):
        load_pb2_settings(reveal(values))
    short_file = tmp_path / "short"
    short = Redacted(signing.reveal()[:5])
    short_file.write_text(short.reveal(), encoding="utf-8")
    values["WEBHOOK_SECRET_FILE"] = str(short_file)
    with pytest.raises(ConfigurationError) as error:
        load_pb2_settings(reveal(values))
    assert_not_disclosed("PB2 configuration exception", str(error.value), signing, short)


@pytest.mark.parametrize(
    "key",
    [
        "WEBHOOK_MAX_BODY_BYTES",
        "WEBHOOK_MAX_FIELD_CHARS",
        "WEBHOOK_MAX_CLOCK_SKEW_SECONDS",
        "REDIS_TIMEOUT_SECONDS",
        "THREAT_INTEL_TIMEOUT_SECONDS",
        "THREAT_INTEL_CACHE_TTL_SECONDS",
        "THREAT_INTEL_BULK_MAX_ITEMS",
        "INCIDENT_MAX_ALERTS",
        "INCIDENT_MAX_TEXT_CHARS",
    ],
)
def test_limits_are_required_positive_values(
    pb2_env: tuple[dict[str, str | Redacted], Redacted], key: str
) -> None:
    values, _ = pb2_env
    values[key] = "0"
    with pytest.raises(ConfigurationError):
        load_pb2_settings(reveal(values))
    del values[key]
    with pytest.raises(ConfigurationError):
        load_pb2_settings(reveal(values))


def test_two_redis_instances_and_a_service_initiator_are_required(
    pb2_env: tuple[dict[str, str | Redacted], Redacted],
) -> None:
    values, _ = pb2_env
    values["REDIS_CACHE_URL"] = values["CELERY_BROKER_URL"]
    with pytest.raises(ConfigurationError, match="separate Redis"):
        load_pb2_settings(reveal(values))
    values["REDIS_CACHE_URL"] = "https://cache.invalid"
    with pytest.raises(ConfigurationError):
        load_pb2_settings(reveal(values))
    values["REDIS_CACHE_URL"] = "redis://cache.invalid:6379/0"
    values["WEBHOOK_INITIATOR"] = "user:forged"
    with pytest.raises(ConfigurationError):
        load_pb2_settings(reveal(values))
