"""Exercise the development seed in a subprocess against disposable PostgreSQL."""

import os
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

from tests.sensitive import Redacted, assert_not_disclosed, reveal

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def seed_env(runtime_url: str) -> dict[str, str | Redacted]:
    values = {
        "ENV": "development",
        "DATABASE_URL": Redacted(runtime_url),
        "SESSION_SIGNING_SECRET": Redacted.random(48),
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
        "SEED_ADMIN_PASSWORD": Redacted.random(),
        "SEED_SENIOR_ANALYST_PASSWORD": Redacted.random(),
        "SEED_ANALYST_PASSWORD": Redacted.random(),
        "PYTHONPATH": str(ROOT / "backend"),
    }
    values.pop("DATABASE_URL_FILE", None)
    values.pop("SESSION_SIGNING_SECRET_FILE", None)
    return values


def run_seed(env: dict[str, str | Redacted]) -> subprocess.CompletedProcess[str]:
    process_env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "LD_LIBRARY_PATH")
        if key in os.environ
    }
    process_env.update(reveal(env))
    result = subprocess.run(  # noqa: S603 - fixed interpreter and fixed script, no shell
        [sys.executable, str(ROOT / "scripts" / "seed_dev.py")],
        cwd=ROOT,
        env=process_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr
    protected = [value for value in env.values() if isinstance(value, Redacted)]
    assert_not_disclosed("Seed process output", output, *protected)
    return result


def test_seed_creates_one_argon2_user_per_role_with_correlated_audit(
    seed_env: dict[str, str | Redacted], migrated_url: str
) -> None:
    result = run_seed(seed_env)
    assert result.returncode == 0
    assert "Development seed completed" in result.stdout
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            rows = [
                (row.username, Redacted(row.password_hash), row.is_active, row.name)
                for row in db.execute(
                    text(
                        "SELECT u.username, u.password_hash, u.is_active, r.name "
                        "FROM users u JOIN roles r ON r.id=u.role_id ORDER BY r.name"
                    )
                )
            ]
            activities = db.execute(
                text("SELECT username, ip, action, details FROM case_activities ORDER BY id")
            ).all()
        assert len(rows) == len(activities) == 3
        hashes = []
        for username, digest, active, role in rows:
            is_argon2id = digest.reveal().startswith("$argon2id$")
            assert username == role and active is True and is_argon2id
            password = seed_env[f"SEED_{role.upper()}_PASSWORD"]
            assert isinstance(password, Redacted)
            verified = PasswordHasher().verify(digest.reveal(), password.reveal())
            assert verified
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
            if key.startswith("SEED_") and key.endswith("_PASSWORD") and isinstance(value, Redacted)
        ]
        assert_not_disclosed(
            "Seed audit or output", audit_text + result.stdout + result.stderr, *sensitive_values
        )
        again = run_seed(seed_env)
        assert again.returncode != 0
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 3
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 3
    finally:
        engine.dispose()


@pytest.mark.parametrize("environment", ["production", "test", "", "PRODUCTION"])
def test_seed_refuses_non_development_before_configuration(environment: str) -> None:
    env = {"ENV": environment, "PYTHONPATH": str(ROOT / "backend")}
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
    seed_env: dict[str, str | Redacted], migrated_url: str
) -> None:
    missing = dict(seed_env)
    del missing["SEED_SENIOR_ANALYST_PASSWORD"]
    assert run_seed(missing).returncode != 0
    weak = dict(seed_env)
    admin_password = weak["SEED_ADMIN_PASSWORD"]
    assert isinstance(admin_password, Redacted)
    weak["SEED_ADMIN_PASSWORD"] = Redacted(admin_password.reveal()[:3])
    assert run_seed(weak).returncode != 0
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 0
    finally:
        engine.dispose()


def test_seed_refuses_database_owner_role(
    seed_env: dict[str, str | Redacted], migrated_url: str
) -> None:
    seed_env["DATABASE_URL"] = Redacted(migrated_url)
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
    seed_env: dict[str, str | Redacted], migrated_url: str, monkeypatch: pytest.MonkeyPatch
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
        seed_dev.seed_dev(reveal(seed_env))
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
            assert db.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 0
    finally:
        engine.dispose()


def test_concurrent_seeds_are_serialized_and_never_duplicate_users(
    seed_env: dict[str, str | Redacted], migrated_url: str
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
