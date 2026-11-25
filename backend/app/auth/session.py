"""Lookup of revocable, database-clock-bound cookie sessions."""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.models import AuthSession
from app.core.config import Settings
from app.core.security import credential_digest
from app.users.models import Role, User

SESSION_COOKIE = "__Host-soc_session"
CSRF_COOKIE = "__Host-soc_csrf"
CSRF_HEADER = "X-CSRF-Token"
DEV_SESSION_COOKIE = "soc_dev_session"
DEV_CSRF_COOKIE = "soc_dev_csrf"


def cookie_names(settings: Settings) -> tuple[str, str]:
    return (
        (DEV_SESSION_COOKIE, DEV_CSRF_COOKIE)
        if settings.dev_insecure_cookies
        else (
            SESSION_COOKIE,
            CSRF_COOKIE,
        )
    )


def request_session_token(request: Request) -> str | None:
    settings: Settings = request.app.state.settings
    return request.cookies.get(cookie_names(settings)[0])


def request_csrf_token(request: Request) -> str | None:
    settings: Settings = request.app.state.settings
    return request.cookies.get(cookie_names(settings)[1])


def session_digest(settings: Settings, token: str) -> bytes:
    # Insecure dev sessions cannot be replayed in a secure environment even if
    # an operator accidentally shares the same database and signing secret.
    purpose = "dev-session" if settings.dev_insecure_cookies else "session"
    return credential_digest(settings.session_signing_secret, purpose, token)


@dataclass(frozen=True)
class SessionIdentity:
    session_id: UUID
    user_id: UUID
    username: str
    role: str
    reauth_at: datetime | None
    csrf_digest: bytes = field(repr=False)


def session_rows(
    db: Session, settings: Settings, token: str, *, lock: bool = False
) -> tuple[AuthSession, User, Role] | None:
    digest = session_digest(settings, token)
    query = (
        select(AuthSession, User, Role)
        .join(User, AuthSession.user_id == User.id)
        .join(Role, User.role_id == Role.id)
        .where(
            AuthSession.token_digest == digest,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > func.clock_timestamp(),
            User.is_active.is_(True),
        )
    )
    if lock:
        query = query.with_for_update(of=[AuthSession, User])
    row = db.execute(query).one_or_none()
    return (row[0], row[1], row[2]) if row is not None else None


def identity_from_rows(rows: tuple[AuthSession, User, Role]) -> SessionIdentity:
    auth_session, user, role = rows
    return SessionIdentity(
        session_id=auth_session.id,
        user_id=user.id,
        username=user.username,
        role=role.name,
        reauth_at=auth_session.reauth_at,
        csrf_digest=auth_session.csrf_digest,
    )
