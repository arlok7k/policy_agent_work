"""Configuration must fail closed without exposing supplied secrets."""

import os
import subprocess
import sys
from ipaddress import ip_address
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import ConfigurationError, Settings, load_database_url, load_settings
from app.main import app
from tests.sensitive import Redacted, assert_not_disclosed, reveal


@pytest.fixture
def env_values() -> dict[str, str | Redacted]:
    return {
        "ENV": "test",
        "DATABASE_URL": "postgresql+psycopg:///disposable_test",
        "SESSION_SIGNING_SECRET": Redacted.random(48),
        "SESSION_TTL_SECONDS": "28800",
        "LOGIN_FAILURE_LIMIT": "5",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "50",
        "MAX_PAGE_SIZE": "100",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "2592000",
    }


def test_valid_inline_settings_are_typed_and_masked(env_values: dict[str, str | Redacted]) -> None:
    settings = load_settings(reveal(env_values))
    assert isinstance(settings, Settings)
    assert settings.environment == "test"
    assert settings.database_url.get_secret_value() == env_values["DATABASE_URL"]
    secret = env_values["SESSION_SIGNING_SECRET"]
    assert isinstance(secret, Redacted)
    assert_not_disclosed("Settings representation", repr(settings), secret)


def test_migrations_can_load_only_a_database_secret(env_values: dict[str, str | Redacted]) -> None:
    assert (
        load_database_url({"DATABASE_URL": env_values["DATABASE_URL"]}).get_secret_value()
        == (env_values["DATABASE_URL"])
    )
    with pytest.raises(ConfigurationError, match="Invalid database"):
        load_database_url({"DATABASE_URL": "invalid"})


def test_secret_files_load_without_terminal_newline(
    env_values: dict[str, str | Redacted], tmp_path: Path
) -> None:
    secret_file = tmp_path / "secret"
    secret = env_values.pop("SESSION_SIGNING_SECRET")
    assert isinstance(secret, Redacted)
    secret_file.write_text(secret.reveal() + "\n", encoding="utf-8")
    env_values["SESSION_SIGNING_SECRET_FILE"] = str(secret_file)
    loaded = Redacted(load_settings(reveal(env_values)).session_signing_secret.get_secret_value())
    file_value = Redacted(secret_file.read_text(encoding="utf-8").removesuffix("\n"))
    matches = loaded.reveal() == file_value.reveal()
    assert matches


@pytest.mark.parametrize("key", ["DATABASE_URL", "SESSION_SIGNING_SECRET"])
def test_missing_required_secrets_fail(env_values: dict[str, str | Redacted], key: str) -> None:
    del env_values[key]
    with pytest.raises(ConfigurationError, match="exactly one source"):
        load_settings(reveal(env_values))


def test_secret_file_failure_and_conflict_are_closed(
    env_values: dict[str, str | Redacted], tmp_path: Path
) -> None:
    env_values["SESSION_SIGNING_SECRET_FILE"] = str(tmp_path / "nonexistent")
    with pytest.raises(ConfigurationError, match="exactly one source"):
        load_settings(reveal(env_values))
    del env_values["SESSION_SIGNING_SECRET"]
    with pytest.raises(ConfigurationError, match="Unable to read"):
        load_settings(reveal(env_values))


@pytest.mark.parametrize("key", ["ENV", "DATABASE_URL", "SESSION_SIGNING_SECRET"])
def test_invalid_values_are_generic(env_values: dict[str, str | Redacted], key: str) -> None:
    marker = Redacted.random(48)
    bad_value = marker if key != "SESSION_SIGNING_SECRET" else Redacted(marker.reveal()[:12])
    env_values[key] = bad_value
    with pytest.raises(ConfigurationError) as error:
        load_settings(reveal(env_values))
    assert_not_disclosed(
        "Configuration exception", str(error.value) + repr(error.value), marker, bad_value
    )


@pytest.mark.parametrize(
    "key",
    ["SESSION_TTL_SECONDS", "LOGIN_FAILURE_LIMIT", "LOGIN_WINDOW_SECONDS", "PASSWORD_MIN_CHARS"],
)
def test_nonpositive_security_settings_fail(
    env_values: dict[str, str | Redacted], key: str
) -> None:
    env_values[key] = "0"
    with pytest.raises(ConfigurationError):
        load_settings(reveal(env_values))


def test_inverted_password_policy_fails(env_values: dict[str, str | Redacted]) -> None:
    env_values["PASSWORD_MIN_CHARS"] = str(int(env_values["PASSWORD_MAX_CHARS"]) + 1)
    with pytest.raises(ConfigurationError):
        load_settings(reveal(env_values))


def test_application_refuses_startup_without_a_secret(
    monkeypatch: pytest.MonkeyPatch, env_values: dict[str, str | Redacted]
) -> None:
    for key, value in env_values.items():
        if key != "SESSION_SIGNING_SECRET":
            monkeypatch.setenv(key, reveal(value))
    monkeypatch.delenv("SESSION_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    with pytest.raises(RuntimeError, match="Application configuration is invalid"), TestClient(app):
        pass


def test_invalid_configuration_exits_a_process_without_printing_secrets(
    env_values: dict[str, str | Redacted],
) -> None:
    marker = env_values["SESSION_SIGNING_SECRET"]
    assert isinstance(marker, Redacted)
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "LD_LIBRARY_PATH")
        if key in os.environ
    }
    env.update(reveal(env_values))
    env.update({"ENV": "invalid", "PYTHONPATH": "backend"})
    program = (
        "from fastapi.testclient import TestClient; "
        "from app.main import app; TestClient(app).__enter__()"
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and program, no shell
        [sys.executable, "-c", program], env=env, capture_output=True, text=True, timeout=10
    )
    assert_not_disclosed("Startup process output", result.stdout + result.stderr, marker)
    assert result.returncode != 0
    assert "Application configuration is invalid" in result.stderr


@pytest.mark.parametrize(
    "key",
    [
        "DEFAULT_PAGE_SIZE",
        "MAX_PAGE_SIZE",
        "USERNAME_MAX_CHARS",
        "API_KEY_NAME_MAX_CHARS",
        "MAX_API_KEY_TTL_SECONDS",
    ],
)
def test_required_admin_settings_cannot_be_missing(
    env_values: dict[str, str | Redacted], key: str
) -> None:
    del env_values[key]
    with pytest.raises(ConfigurationError):
        load_settings(reveal(env_values))


def test_inverted_pagination_policy_fails(env_values: dict[str, str | Redacted]) -> None:
    env_values["DEFAULT_PAGE_SIZE"] = str(int(env_values["MAX_PAGE_SIZE"]) + 1)
    with pytest.raises(ConfigurationError):
        load_settings(reveal(env_values))


def test_proxy_addresses_are_exact_and_configuration_is_fail_closed(
    env_values: dict[str, str | Redacted],
) -> None:
    env_values["TRUSTED_PROXY_IPS"] = "192.0.2.10, 2001:db8::10"
    configured = load_settings(reveal(env_values))
    assert configured.trusted_proxy_ips == (ip_address("192.0.2.10"), ip_address("2001:db8::10"))
    for invalid in (
        "*",
        "192.0.2.0/24",
        "192.0.2.1,,192.0.2.2",
        "127.0.0.1,127.0.0.1",
        "::",
        "fe80::1%eth0",
    ):
        env_values["TRUSTED_PROXY_IPS"] = invalid
        with pytest.raises(ConfigurationError):
            load_settings(reveal(env_values))


def test_insecure_cookie_mode_is_explicit_and_development_only(
    env_values: dict[str, str | Redacted],
) -> None:
    env_values["ENV"] = "development"
    assert not load_settings(reveal(env_values)).dev_insecure_cookies
    env_values["DEV_INSECURE_COOKIES"] = "false"
    assert not load_settings(reveal(env_values)).dev_insecure_cookies
    env_values["DEV_INSECURE_COOKIES"] = "true"
    assert load_settings(reveal(env_values)).dev_insecure_cookies
    for invalid in ("", "1", "TRUE", "yes", "garbage"):
        env_values["DEV_INSECURE_COOKIES"] = invalid
        with pytest.raises(ConfigurationError):
            load_settings(reveal(env_values))
    for environment in ("production", "test"):
        env_values["ENV"] = environment
        for value in ("true", "false"):
            env_values["DEV_INSECURE_COOKIES"] = value
            with pytest.raises(ConfigurationError):
                load_settings(reveal(env_values))
        del env_values["DEV_INSECURE_COOKIES"]
        assert not load_settings(reveal(env_values)).dev_insecure_cookies
