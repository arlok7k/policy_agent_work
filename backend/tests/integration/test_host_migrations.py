"""Test the host migrations and audit permissions on disposable PostgreSQL."""

import os
import secrets
from collections.abc import Iterator
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.core.db import RuntimeDatabaseError, validate_runtime_database_access
from app.main import app


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


def test_schema_and_seeded_roles(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        assert set(inspect(engine).get_table_names()) == {
            "alembic_version",
            "roles",
            "users",
            "auth_sessions",
            "api_keys",
            "auth_login_throttle",
            "case_activities",
        }
        with engine.connect() as connection:
            roles = set(connection.execute(text("SELECT name FROM roles")).scalars())
            assert roles == {"admin", "senior_analyst", "analyst"}
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == ("003_case_activities")
        session_columns = {
            column["name"] for column in inspect(engine).get_columns("auth_sessions")
        }
        key_columns = {column["name"] for column in inspect(engine).get_columns("api_keys")}
        assert {
            "token_digest",
            "csrf_digest",
            "expires_at",
            "revoked_at",
            "reauth_at",
        } <= session_columns
        assert {"key_digest", "prefix", "expires_at", "revoked_at"} <= key_columns
        assert not ({"token", "secret", "password"} & (session_columns | key_columns))
    finally:
        engine.dispose()


def test_user_constraints_require_normalized_username_and_argon2id(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    hashed = PasswordHasher().hash(secrets.token_urlsafe(32))
    insert = text(
        "INSERT INTO users (username, password_hash, role_id) "
        "VALUES (:username, :digest, (SELECT id FROM roles WHERE name = :role))"
    )
    try:
        with engine.begin() as connection:
            connection.execute(insert, {"username": "alice", "digest": hashed, "role": "analyst"})
        for username, digest in (("Alice", hashed), ("bob", "not-a-hash")):
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    insert, {"username": username, "digest": digest, "role": "analyst"}
                )
        with engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM users")).scalar_one() == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_audit_trigger_rejects_mutation_even_for_owner(migrated_url: str, operation: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    statements = {
        "UPDATE": "UPDATE case_activities SET action = 'changed'",
        "DELETE": "DELETE FROM case_activities",
        "TRUNCATE": "TRUNCATE case_activities",
    }
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO case_activities (username, action) VALUES ('tester', 'created')")
            )
        with pytest.raises(DBAPIError) as error, engine.begin() as connection:
            connection.execute(text(statements[operation]))
        assert getattr(error.value.orig, "sqlstate", None) == "55000"
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 1
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("privilege", ["UPDATE", "DELETE", "TRUNCATE"])
def test_runtime_role_has_no_audit_mutation_privileges(migrated_url: str, privilege: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as connection:
            assert not connection.execute(
                text("SELECT has_table_privilege('hpb_app', 'case_activities', :privilege)"),
                {"privilege": privilege},
            ).scalar_one()
        statement = {
            "UPDATE": "UPDATE case_activities SET action = 'changed'",
            "DELETE": "DELETE FROM case_activities",
            "TRUNCATE": "TRUNCATE case_activities",
        }[privilege]
        with pytest.raises(DBAPIError) as error, engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE hpb_app"))
            connection.execute(text(statement))
        assert getattr(error.value.orig, "sqlstate", None) == "42501"
    finally:
        engine.dispose()


def test_runtime_role_can_append_but_migrator_cannot_serve(
    migrated_url: str, runtime_url: str
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    try:
        with pytest.raises(RuntimeDatabaseError, match="overprivileged"):
            validate_runtime_database_access(owner)
        validate_runtime_database_access(runtime)
        with runtime.begin() as connection:
            connection.execute(
                text("INSERT INTO case_activities (username, action) VALUES ('tester', 'created')")
            )
            assert (
                connection.execute(text("SELECT count(*) FROM case_activities")).scalar_one() == 1
            )
    finally:
        owner.dispose()
        runtime.dispose()


def test_set_role_does_not_disguise_superuser(migrated_url: str) -> None:
    url = make_url(migrated_url)
    options = f"{url.query.get('options', '')} -crole=hpb_app"
    engine = create_engine(url.update_query_dict({"options": options}), hide_parameters=True)
    try:
        with pytest.raises(RuntimeDatabaseError, match="overprivileged"):
            validate_runtime_database_access(engine)
    finally:
        engine.dispose()


def test_application_starts_with_restricted_database_login(
    runtime_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("DATABASE_URL", runtime_url)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.setenv("SESSION_SIGNING_SECRET", secrets.token_urlsafe(48))
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    with TestClient(app) as client:
        assert client.get("/openapi.json").status_code == 200


def test_down_to_base_removes_all_host_objects(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        command.downgrade(Config("alembic.ini"), "base")
        assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT count(*) FROM alembic_version")).scalar_one() == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_proc p "
                        "JOIN pg_namespace n ON n.oid = p.pronamespace "
                        "WHERE n.nspname = current_schema() AND p.proname LIKE 'hpb_%'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()
