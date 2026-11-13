"""Fixtures that require an explicitly marked disposable PostgreSQL database."""

import os
from collections.abc import Iterator
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


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
