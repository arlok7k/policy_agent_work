"""Lookup of revocable, database-clock-bound cookie sessions."""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.models import AuthSession
from app.core.config import Settings
from app.core.security import credential_digest
from app.users.models import Role, User

SESSION_COOKIE = "__Host-soc_session"
CSRF_COOKIE = "__Host-soc_csrf"
CSRF_HEADER = "X-CSRF-Token"


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
    digest = credential_digest(settings.session_signing_secret, "session", token)
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
