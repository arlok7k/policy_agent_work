"""Fixtures that require an explicitly marked disposable PostgreSQL database."""

import os
from collections.abc import Iterator
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


def pytest_terminal_summary(terminalreporter: object) -> None:
    """Report failing test names without exposing fixture values or tracebacks."""
    failures = terminalreporter.stats.get("failed", [])  # type: ignore[attr-defined]
    for report in failures:
        name = report.nodeid.split("[", 1)[0]
        terminalreporter.write_line(f"FAILED {name} ({report.when})")  # type: ignore[attr-defined]


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
