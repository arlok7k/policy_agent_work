"""Exercise the development seed in a subprocess against disposable PostgreSQL."""

import os
import secrets
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import pytest
from argon2 import PasswordHasher
from scripts import seed_dev
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def seed_env(runtime_url: str) -> dict[str, str]:
    values = {
        **os.environ,
        "ENV": "development",
        "DATABASE_URL": runtime_url,
        "SESSION_SIGNING_SECRET": secrets.token_urlsafe(48),
        "SESSION_TTL_SECONDS": "3600",
        "LOGIN_FAILURE_LIMIT": "5",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "50",
        "MAX_PAGE_SIZE": "100",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "3600",
        "SEED_ADMIN_PASSWORD": secrets.token_urlsafe(32),
        "SEED_SENIOR_ANALYST_PASSWORD": secrets.token_urlsafe(32),
        "SEED_ANALYST_PASSWORD": secrets.token_urlsafe(32),
        "PYTHONPATH": str(ROOT / "backend"),
    }
    values.pop("DATABASE_URL_FILE", None)
    values.pop("SESSION_SIGNING_SECRET_FILE", None)
    return values


def run_seed(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and fixed script, no shell
        [sys.executable, str(ROOT / "scripts" / "seed_dev.py")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr
    sensitive_keys = ["SESSION_SIGNING_SECRET", "DATABASE_URL"]
    sensitive_keys.extend(
        key for key in env if key.startswith("SEED_") and key.endswith("_PASSWORD")
    )
    if any(env[key] and env[key] in output for key in sensitive_keys if key in env):
        raise AssertionError("Seed output disclosed environment credentials")
    return result


def test_seed_creates_one_argon2_user_per_role_with_correlated_audit(
    seed_env: dict[str, str], migrated_url: str
) -> None:
    result = run_seed(seed_env)
    assert result.returncode == 0
    assert "Development seed completed" in result.stdout
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            rows = db.execute(
                text(
                    "SELECT u.username, u.password_hash, u.is_active, r.name "
                    "FROM users u JOIN roles r ON r.id=u.role_id ORDER BY r.name"
                )
            ).all()
            activities = db.execute(
                text("SELECT username, ip, action, details FROM case_activities ORDER BY id")
            ).all()
        assert len(rows) == len(activities) == 3
        hashes = []
        for username, digest, active, role in rows:
            assert username == role and active is True and digest.startswith("$argon2id$")
            assert PasswordHasher().verify(digest, seed_env[f"SEED_{role.upper()}_PASSWORD"])
            hashes.append(digest)
        assert {row[3] for row in rows} == {"admin", "analyst", "senior_analyst"}
        assert all(
            row.username == "development-seed" and row.ip is None and row.action == "user.seed"
            for row in activities
        )
        correlations = {row.details["correlation_id"] for row in activities}
        assert len(correlations) == 1 and UUID(next(iter(correlations))).version == 4
        audit_text = str(activities)
        sensitive_values = hashes + [
            value
            for key, value in seed_env.items()
            if key.startswith("SEED_") and key.endswith("_PASSWORD")
        ]
        if any(
            value in audit_text or value in result.stdout + result.stderr
            for value in sensitive_values
        ):
            raise AssertionError("Seed leaked a password or hash")
        again = run_seed(seed_env)
        assert again.returncode != 0
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 3
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 3
    finally:
        engine.dispose()


@pytest.mark.parametrize("environment", ["production", "test", "", "PRODUCTION"])
def test_seed_refuses_non_development_before_configuration(environment: str) -> None:
    env = {**os.environ, "ENV": environment, "PYTHONPATH": str(ROOT / "backend")}
    for key in (
        "DATABASE_URL",
        "DATABASE_URL_FILE",
        "SESSION_SIGNING_SECRET",
        "SESSION_SIGNING_SECRET_FILE",
    ):
        env.pop(key, None)
    result = run_seed(env)
    assert result.returncode != 0
    assert "requires ENV=development" in result.stderr


def test_seed_with_missing_or_weak_password_is_atomic(
    seed_env: dict[str, str], migrated_url: str
) -> None:
    missing = dict(seed_env)
    del missing["SEED_SENIOR_ANALYST_PASSWORD"]
    assert run_seed(missing).returncode != 0
    weak = dict(seed_env)
    weak["SEED_ADMIN_PASSWORD"] = weak["SEED_ADMIN_PASSWORD"][:3]
    assert run_seed(weak).returncode != 0
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 0
    finally:
        engine.dispose()


def test_seed_refuses_database_owner_role(seed_env: dict[str, str], migrated_url: str) -> None:
    seed_env["DATABASE_URL"] = migrated_url
    result = run_seed(seed_env)
    assert result.returncode != 0
    assert "RuntimeDatabaseError" in result.stderr
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
    finally:
        engine.dispose()


def test_seed_rolls_back_partial_inserts_if_audit_fails(
    seed_env: dict[str, str], migrated_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = seed_dev.append_activity
    calls = 0

    def fail_second(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("Simulated audit failure")
        original(*args, **kwargs)

    monkeypatch.setattr(seed_dev, "append_activity", fail_second)
    with pytest.raises(RuntimeError, match="Simulated audit failure"):
        seed_dev.seed_dev(seed_env)
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 0
    finally:
        engine.dispose()


def test_concurrent_seeds_are_serialized_and_never_duplicate_users(
    seed_env: dict[str, str], migrated_url: str
) -> None:
    barrier = threading.Barrier(2)

    def run() -> int:
        barrier.wait(timeout=10)
        return run_seed(seed_env).returncode

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run) for _ in range(2)]
        codes = [future.result(timeout=40) for future in futures]
    assert sum(code == 0 for code in codes) == 1
    assert sum(code != 0 for code in codes) == 1
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 3
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 3
    finally:
        engine.dispose()
