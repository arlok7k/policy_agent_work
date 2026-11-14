"""Fixtures that require an explicitly marked disposable PostgreSQL database."""

import os
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from tests.sensitive import Redacted


@pytest.fixture(autouse=True)
def pb2_test_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide harmless PB2 startup configuration; live Redis tests override it."""
    signing = Redacted.random(48)
    secret_file = tmp_path / "webhook-signing"
    secret_file.write_text(signing.reveal(), encoding="utf-8")
    values = {
        "WEBHOOK_SECRET_FILE": str(secret_file),
        "WEBHOOK_INITIATOR": "service:test-webhook",
        "WEBHOOK_MAX_BODY_BYTES": "4096",
        "WEBHOOK_MAX_FIELD_CHARS": "128",
        "WEBHOOK_MAX_CLOCK_SKEW_SECONDS": "60",
        "REDIS_TIMEOUT_SECONDS": "1",
        "THREAT_INTEL_TIMEOUT_SECONDS": "0.1",
        "THREAT_INTEL_CACHE_TTL_SECONDS": "60",
        "THREAT_INTEL_BULK_MAX_ITEMS": "3",
        "INCIDENT_MAX_ALERTS": "3",
        "INCIDENT_MAX_TEXT_CHARS": "128",
        "CELERY_BROKER_URL": "redis://127.0.0.1:1/0",
        "REDIS_CACHE_URL": "redis://127.0.0.1:2/0",
    }
    for key in ("WEBHOOK_SECRET", "CELERY_BROKER_URL_FILE", "REDIS_CACHE_URL_FILE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def disposable_database_url() -> Iterator[str]:
    raw_url = os.environ.get("TEST_DATABASE_URL")
    if not raw_url or os.environ.get("TEST_DATABASE_DISPOSABLE") != "1":
        pytest.fail("Set TEST_DATABASE_URL and TEST_DATABASE_DISPOSABLE=1 for a disposable DB")
    try:
        url = make_url(raw_url)
    except ArgumentError:
        pytest.fail("TEST_DATABASE_URL is invalid")
    if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
        pytest.fail("The disposable PostgreSQL database name must end in _test")
    engine = create_engine(url, hide_parameters=True)
    schema = f"test_{uuid4().hex}"
    # Only a generated hexadecimal identifier is interpolated, never user input.
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))  # noqa: S608
    try:
        scoped = url.update_query_dict({"options": f"-csearch_path={schema}"})
        yield scoped.render_as_string(hide_password=False)
    finally:
        # The explicitly disposable DB guard above is required before this DROP.
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))  # noqa: S608
        engine.dispose()


@pytest.fixture
def migrated_url(disposable_database_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("DATABASE_URL", disposable_database_url)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    command.upgrade(Config("alembic.ini"), "head")
    return disposable_database_url


@pytest.fixture
def runtime_url(migrated_url: str) -> Iterator[str]:
    if os.environ.get("TEST_PG_CLUSTER_DISPOSABLE") != "1":
        pytest.fail("Temporary role tests require TEST_PG_CLUSTER_DISPOSABLE=1")
    role = f"test_runtime_{uuid4().hex}"
    owner_engine = create_engine(migrated_url, hide_parameters=True)
    with owner_engine.begin() as connection:
        # The role name is generated solely from UUID hex, not user input.
        connection.execute(text(f'CREATE ROLE "{role}" LOGIN INHERIT'))  # noqa: S608
        connection.execute(text(f'GRANT hpb_app TO "{role}"'))  # noqa: S608
    try:
        runtime = make_url(migrated_url)._replace(username=role, password=None)
        yield runtime.render_as_string(hide_password=False)
    finally:
        # The explicit disposable-cluster guard is required before dropping roles.
        with owner_engine.begin() as connection:
            connection.execute(text(f'DROP ROLE "{role}"'))  # noqa: S608
        owner_engine.dispose()
