"""Create initial development-only users from operator-supplied environment values."""

import os
import sys
from collections.abc import Mapping

from sqlalchemy import select, text

from app.core.activity import append_activity
from app.core.config import load_settings
from app.core.context import correlation_id, safe_correlation_id
from app.core.db import create_db_engine, create_session_factory, validate_runtime_database_access
from app.core.security import PasswordService
from app.users.models import Role, User
from app.users.validation import normalize_username, valid_password


class SeedError(Exception):
    """A development seed precondition was not met."""


def seed_dev(environ: Mapping[str, str]) -> None:
    if environ.get("ENV") != "development":
        raise SeedError("Development seed requires ENV=development")
    settings = load_settings(environ)
    engine = create_db_engine(settings)
    context_token = correlation_id.set(safe_correlation_id(None))
    try:
        validate_runtime_database_access(engine)
        factory = create_session_factory(engine)
        passwords = PasswordService()
        with factory.begin() as db:
            # Prevent a concurrent insert after the empty-database check.
            db.execute(text("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE"))
            if db.execute(select(User.id).limit(1)).first() is not None:
                raise SeedError("Development seed requires an empty user table")
            roles = db.execute(select(Role).order_by(Role.name)).scalars().all()
            if not roles:
                raise SeedError("Development role catalogue is empty")
            entries: list[tuple[Role, str, str]] = []
            for role in roles:
                username = normalize_username(role.name, settings)
                password = environ.get(f"SEED_{role.name.upper()}_PASSWORD", "")
                if username != role.name or not valid_password(password, settings):
                    raise SeedError("Development seed credentials or role names are invalid")
                entries.append((role, username, password))
            for role, username, password in entries:
                user = User(
                    username=username,
                    password_hash=passwords.hash_password(password),
                    role_id=role.id,
                    is_active=True,
                )
                db.add(user)
                db.flush()
                append_activity(
                    db,
                    username="development-seed",
                    ip=None,
                    action="user.seed",
                    target=str(user.id),
                )
    finally:
        correlation_id.reset(context_token)
        engine.dispose()


def main() -> int:
    try:
        seed_dev(os.environ)
    except SeedError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:
        # Exception text and tracebacks may contain URLs, password hashes or inputs.
        print(f"Development seed failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print("Development seed completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
