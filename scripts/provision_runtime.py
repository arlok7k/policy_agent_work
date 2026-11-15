"""Provision an unprivileged runtime login after host migrations.

The migration container receives both URL secrets. Application containers only
receive the runtime URL. The login may inherit only the restricted hpb_app role.
"""

from __future__ import annotations

import re
import sys
from typing import Any, cast

import psycopg
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

from app.core.config import _read_secret, load_database_url


class ProvisionError(Exception):
    """Unsafe provisioning input or an unexpectedly privileged existing role."""


def _validate_urls(owner: SecretStr, runtime: SecretStr) -> tuple[URL, URL]:
    try:
        admin_url = make_url(owner.get_secret_value())
        runtime_url = make_url(runtime.get_secret_value())
        if (
            admin_url.drivername != runtime_url.drivername
            or admin_url.host != runtime_url.host
            or (admin_url.port or 5432) != (runtime_url.port or 5432)
            or admin_url.database != runtime_url.database
            or admin_url.query != runtime_url.query
            or admin_url.drivername != "postgresql+psycopg"
            or not admin_url.database
            or not runtime_url.username
            or not runtime_url.password
            or runtime_url.username == admin_url.username
            or re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", runtime_url.username, re.ASCII) is None
        ):
            raise ProvisionError("Invalid runtime database identity")
        return admin_url, runtime_url
    except ArgumentError:
        raise ProvisionError("Invalid runtime database identity") from None


def provision_runtime(owner: SecretStr, runtime: SecretStr) -> None:
    admin_url, runtime_url = _validate_urls(owner, runtime)
    name = runtime_url.username
    password = runtime_url.password
    if name is None or password is None:
        raise ProvisionError("Invalid runtime database identity")
    engine = create_engine(admin_url, hide_parameters=True)
    try:
        with engine.begin() as connection:
            raw = cast(psycopg.Connection[Any], connection.connection.driver_connection)
            with raw.cursor() as cursor:
                cursor.execute(
                    "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls FROM pg_roles WHERE rolname=%s",
                    (name,),
                )
                existing = cursor.fetchone()
                if existing is not None:
                    can_login, inherits, *elevated = existing
                    if not can_login or not inherits or any(elevated):
                        raise ProvisionError("Existing runtime login is unsafe")
                    cursor.execute(
                        "SELECT parent.rolname, membership.admin_option "
                        "FROM pg_auth_members AS membership "
                        "JOIN pg_roles AS member ON member.oid=membership.member "
                        "JOIN pg_roles AS parent ON parent.oid=membership.roleid "
                        "WHERE member.rolname=%s",
                        (name,),
                    )
                    if any(row[0] != "hpb_app" or row[1] for row in cursor.fetchall()):
                        raise ProvisionError("Existing runtime membership is unsafe")
                    cursor.execute(
                        sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                            sql.Identifier(name), sql.Literal(password)
                        )
                    )
                else:
                    cursor.execute(
                        sql.SQL(
                            "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                            "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                        ).format(sql.Identifier(name), sql.Literal(password))
                    )
                cursor.execute(sql.SQL("GRANT hpb_app TO {}").format(sql.Identifier(name)))
    finally:
        engine.dispose()


def main() -> int:
    import os

    try:
        provision_runtime(
            load_database_url(), SecretStr(_read_secret("RUNTIME_DATABASE_URL", os.environ))
        )
    except Exception as error:
        # Database errors and tracebacks can contain credentials or query text.
        print(f"Runtime provisioning failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print("Restricted runtime login provisioned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
