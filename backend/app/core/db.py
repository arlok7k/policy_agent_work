"""PostgreSQL engine and session lifecycle for the host application."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


class RuntimeDatabaseError(Exception):
    """The runtime database principal is unsafe or the database is unavailable."""


# Check both session and effective identities: SET ROLE from an owner or
# superuser must never make an unsafe login appear safe.
_RUNTIME_ACCESS_QUERY = text(
    """
    SELECT
      (s.rolsuper OR s.rolcreatedb OR s.rolcreaterole OR s.rolreplication OR s.rolbypassrls
       OR e.rolsuper OR e.rolcreatedb OR e.rolcreaterole OR e.rolreplication OR e.rolbypassrls)
        AS elevated,
      (pg_has_role(session_user, c.relowner, 'MEMBER') OR
       pg_has_role(current_user, c.relowner, 'MEMBER') OR
       pg_has_role(session_user, n.nspowner, 'MEMBER') OR
       pg_has_role(session_user, d.datdba, 'MEMBER')) AS owner_member,
      (has_schema_privilege(session_user, n.oid, 'CREATE') OR
       has_schema_privilege(current_user, n.oid, 'CREATE')) AS can_create_in_schema,
      (has_table_privilege(session_user, c.oid, 'UPDATE') OR
       has_table_privilege(session_user, c.oid, 'DELETE') OR
       has_table_privilege(session_user, c.oid, 'TRUNCATE') OR
       has_table_privilege(current_user, c.oid, 'UPDATE') OR
       has_table_privilege(current_user, c.oid, 'DELETE') OR
       has_table_privilege(current_user, c.oid, 'TRUNCATE')) AS can_mutate_audit,
      (has_table_privilege(current_user, c.oid, 'SELECT') AND
       has_table_privilege(current_user, c.oid, 'INSERT')) AS can_read_and_append,
      c.relkind IN ('r', 'p') AS is_table
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_database d ON d.datname = current_database()
    JOIN pg_roles s ON s.rolname = session_user
    JOIN pg_roles e ON e.rolname = current_user
    WHERE c.oid = to_regclass('case_activities')
    """
)


def validate_runtime_database_access(engine: Engine) -> None:
    """Refuse to serve with a missing audit table or overprivileged login."""
    try:
        with engine.connect() as connection:
            access = connection.execute(_RUNTIME_ACCESS_QUERY).mappings().one_or_none()
    except SQLAlchemyError:
        raise RuntimeDatabaseError("Runtime database validation failed") from None
    if access is None or not access["is_table"] or not access["can_read_and_append"]:
        raise RuntimeDatabaseError("Runtime database access is incomplete")
    if any(
        access[key]
        for key in ("elevated", "owner_member", "can_create_in_schema", "can_mutate_audit")
    ):
        raise RuntimeDatabaseError("Runtime database access is overprivileged")


def create_db_engine(settings: Settings) -> Engine:
    return create_engine(
        settings.database_url.get_secret_value(), pool_pre_ping=True, hide_parameters=True
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def get_db(request: Request) -> Iterator[Session]:
    """Yield one session; an uncommitted transaction is rolled back on close."""
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session
