"""Restricted Compose runtime role provisioning against a disposable cluster."""

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from pydantic import SecretStr
from scripts.provision_runtime import ProvisionError, provision_runtime
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.core.db import validate_runtime_database_access
from tests.sensitive import Redacted


def test_runtime_role_provisioning_is_idempotent_and_unprivileged(migrated_url: str) -> None:
    if os.environ.get("TEST_PG_CLUSTER_DISPOSABLE") != "1":
        pytest.fail("Provisioning tests require a disposable PostgreSQL cluster")
    role = f"provision_{uuid4().hex}"
    password = Redacted.random()
    owner = SecretStr(migrated_url)
    url = make_url(migrated_url).set(username=role, password=password.reveal())
    runtime = SecretStr(url.render_as_string(hide_password=False))
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        provision_runtime(owner, runtime)
        provision_runtime(owner, runtime)
        restricted = create_engine(url, hide_parameters=True)
        try:
            validate_runtime_database_access(restricted)
            with restricted.connect() as connection:
                assert connection.execute(text("SELECT count(*) FROM roles")).scalar_one() == 3
                assert not connection.execute(
                    text("SELECT has_table_privilege(current_user, 'case_activities', 'UPDATE')")
                ).scalar_one()
        finally:
            restricted.dispose()
    finally:
        with engine.begin() as connection:
            raw: psycopg.Connection = connection.connection.driver_connection
            with raw.cursor() as cursor:
                cursor.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        engine.dispose()


def test_provisioning_refuses_existing_elevated_login(migrated_url: str) -> None:
    if os.environ.get("TEST_PG_CLUSTER_DISPOSABLE") != "1":
        pytest.fail("Provisioning tests require a disposable PostgreSQL cluster")
    role = f"provision_{uuid4().hex}"
    password = Redacted.random()
    runtime = make_url(migrated_url).set(username=role, password=password.reveal())
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as connection:
            raw: psycopg.Connection = connection.connection.driver_connection
            with raw.cursor() as cursor:
                cursor.execute(
                    sql.SQL("CREATE ROLE {} LOGIN SUPERUSER").format(sql.Identifier(role))
                )
        with pytest.raises(ProvisionError):
            provision_runtime(SecretStr(migrated_url), SecretStr(runtime.render_as_string(False)))
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname=:name"), {"name": role}
            ).scalar_one()
    finally:
        with engine.begin() as connection:
            raw = connection.connection.driver_connection
            with raw.cursor() as cursor:
                cursor.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        engine.dispose()


def test_provisioning_refuses_runtime_with_admin_grant(migrated_url: str) -> None:
    if os.environ.get("TEST_PG_CLUSTER_DISPOSABLE") != "1":
        pytest.fail("Provisioning tests require a disposable PostgreSQL cluster")
    role = f"provision_{uuid4().hex}"
    password = Redacted.random()
    runtime = make_url(migrated_url).set(username=role, password=password.reveal())
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as connection:
            raw: psycopg.Connection = connection.connection.driver_connection
            with raw.cursor() as cursor:
                cursor.execute(sql.SQL("CREATE ROLE {} LOGIN INHERIT").format(sql.Identifier(role)))
                cursor.execute(
                    sql.SQL("GRANT hpb_app TO {} WITH ADMIN OPTION").format(sql.Identifier(role))
                )
        with pytest.raises(ProvisionError):
            provision_runtime(SecretStr(migrated_url), SecretStr(runtime.render_as_string(False)))
    finally:
        with engine.begin() as connection:
            raw = connection.connection.driver_connection
            with raw.cursor() as cursor:
                cursor.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        engine.dispose()
