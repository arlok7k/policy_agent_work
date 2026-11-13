"""Configuration must fail closed without exposing supplied secrets."""

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import ConfigurationError, Settings, load_database_url, load_settings
from app.main import app


@pytest.fixture
def env_values() -> dict[str, str]:
    return {
        "ENV": "test",
        "DATABASE_URL": "postgresql+psycopg:///disposable_test",
        "SESSION_SIGNING_SECRET": secrets.token_urlsafe(48),
    }


def test_valid_inline_settings_are_typed_and_masked(env_values: dict[str, str]) -> None:
    settings = load_settings(env_values)
    assert isinstance(settings, Settings)
    assert settings.environment == "test"
    assert settings.database_url.get_secret_value() == env_values["DATABASE_URL"]
    assert env_values["SESSION_SIGNING_SECRET"] not in repr(settings)


def test_migrations_can_load_only_a_database_secret(env_values: dict[str, str]) -> None:
    assert (
        load_database_url({"DATABASE_URL": env_values["DATABASE_URL"]}).get_secret_value()
        == (env_values["DATABASE_URL"])
    )
    with pytest.raises(ConfigurationError, match="Invalid database"):
        load_database_url({"DATABASE_URL": "invalid"})


def test_secret_files_load_without_terminal_newline(
    env_values: dict[str, str], tmp_path: Path
) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_text(env_values.pop("SESSION_SIGNING_SECRET") + "\n", encoding="utf-8")
    env_values["SESSION_SIGNING_SECRET_FILE"] = str(secret_file)
    assert load_settings(env_values).session_signing_secret.get_secret_value() == (
        secret_file.read_text(encoding="utf-8").removesuffix("\n")
    )


@pytest.mark.parametrize("key", ["DATABASE_URL", "SESSION_SIGNING_SECRET"])
def test_missing_required_secrets_fail(env_values: dict[str, str], key: str) -> None:
    del env_values[key]
    with pytest.raises(ConfigurationError, match="exactly one source"):
        load_settings(env_values)


def test_secret_file_failure_and_conflict_are_closed(
    env_values: dict[str, str], tmp_path: Path
) -> None:
    env_values["SESSION_SIGNING_SECRET_FILE"] = str(tmp_path / "nonexistent")
    with pytest.raises(ConfigurationError, match="exactly one source"):
        load_settings(env_values)
    del env_values["SESSION_SIGNING_SECRET"]
    with pytest.raises(ConfigurationError, match="Unable to read"):
        load_settings(env_values)


@pytest.mark.parametrize("key", ["ENV", "DATABASE_URL", "SESSION_SIGNING_SECRET"])
def test_invalid_values_are_generic(env_values: dict[str, str], key: str) -> None:
    marker = secrets.token_urlsafe(48)
    env_values[key] = marker if key != "SESSION_SIGNING_SECRET" else marker[:4]
    with pytest.raises(ConfigurationError) as error:
        load_settings(env_values)
    assert marker not in str(error.value)
    assert marker not in repr(error.value)


def test_application_refuses_startup_without_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg:///disposable_test")
    monkeypatch.delenv("SESSION_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    with pytest.raises(RuntimeError, match="Application configuration is invalid"), TestClient(app):
        pass


def test_invalid_configuration_exits_a_process_without_printing_secrets(
    env_values: dict[str, str],
) -> None:
    marker = env_values["SESSION_SIGNING_SECRET"]
    env = {**os.environ, **env_values, "ENV": "invalid", "PYTHONPATH": "backend"}
    program = (
        "from fastapi.testclient import TestClient; "
        "from app.main import app; TestClient(app).__enter__()"
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and program, no shell
        [sys.executable, "-c", program], env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode != 0
    assert "Application configuration is invalid" in result.stderr
    assert marker not in result.stdout + result.stderr
