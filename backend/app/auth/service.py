"""Transactional login, logout and password step-up services."""

from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.models import AuthSession
from app.auth.schemas import PrincipalResponse
from app.auth.session import SessionIdentity, session_rows
from app.auth.throttle import acquire_buckets, blocked, record_failure
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.security import PasswordService, credential_digest, new_opaque_token
from app.users.models import Role, User

PeerIP = IPv4Address | IPv6Address


class AuthFailure(StrEnum):
    INVALID = "invalid"
    THROTTLED = "throttled"


@dataclass(frozen=True)
class LoginSuccess:
    principal: PrincipalResponse
    session_token: str = field(repr=False)
    csrf_token: str = field(repr=False)


def normalize_username(value: str) -> str:
    return value.strip().lower()


def _candidate(password: str, settings: Settings) -> tuple[str, bool]:
    return password[: settings.password_max_chars], len(password) <= settings.password_max_chars


def _find_user(db: Session, username: str) -> tuple[User, Role] | None:
    query = (
        select(User, Role)
        .join(Role, User.role_id == Role.id)
        .where(User.username == username)
        .with_for_update(of=User)
    )
    row = db.execute(query).one_or_none()
    return (row[0], row[1]) if row is not None else None


def _new_login(
    db: Session,
    settings: Settings,
    user: User,
    role: Role,
    ip: PeerIP,
    previous_token: str | None,
) -> LoginSuccess:
    now = db.execute(select(func.clock_timestamp())).scalar_one()
    if previous_token:
        previous = session_rows(db, settings, previous_token, lock=True)
        if previous is not None:
            previous[0].revoked_at = now
    session_token = new_opaque_token()
    csrf_token = new_opaque_token()
    db.add(
        AuthSession(
            user_id=user.id,
            token_digest=credential_digest(
                settings.session_signing_secret, "session", session_token
            ),
            csrf_digest=credential_digest(settings.session_signing_secret, "csrf", csrf_token),
            expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
        )
    )
    append_activity(db, username=user.username, ip=ip, action="auth.login", target=str(user.id))
    return LoginSuccess(
        principal=PrincipalResponse(
            kind="user", id=user.id, username=user.username, roles=[role.name], reauth_at=None
        ),
        session_token=session_token,
        csrf_token=csrf_token,
    )


def login(
    db: Session,
    settings: Settings,
    passwords: PasswordService,
    username: str,
    password: str,
    ip: PeerIP,
    previous_token: str | None,
) -> LoginSuccess | AuthFailure:
    normalized = normalize_username(username)
    valid_name = bool(normalized) and len(normalized) <= settings.password_max_chars
    account = normalized[: settings.password_max_chars] or "unknown"
    candidate, valid_length = _candidate(password, settings)
    with db.begin():
        buckets = acquire_buckets(db, settings, account, ip)
        if blocked(buckets, settings):
            # The supplied username is untrusted and could itself contain a secret.
            append_activity(db, username="anonymous", ip=ip, action="auth.login_throttled")
            return AuthFailure.THROTTLED
        found = _find_user(db, account) if valid_name else None
        user = found[0] if found is not None else None
        verified = passwords.verify(candidate, user.password_hash if user is not None else None)
        if not (valid_length and verified and user is not None and user.is_active):
            record_failure(buckets)
            append_activity(db, username="anonymous", ip=ip, action="auth.login_failed")
            return AuthFailure.INVALID
        if found is None:
            return AuthFailure.INVALID
        return _new_login(db, settings, user, found[1], ip, previous_token)


def logout(db: Session, settings: Settings, token: str, ip: PeerIP) -> bool:
    with db.begin():
        found = session_rows(db, settings, token, lock=True)
        if found is None:
            return False
        auth_session, user, _ = found
        auth_session.revoked_at = db.execute(select(func.clock_timestamp())).scalar_one()
        append_activity(
            db, username=user.username, ip=ip, action="auth.logout", target=str(user.id)
        )
        return True


def reauthenticate(
    db: Session,
    settings: Settings,
    passwords: PasswordService,
    identity: SessionIdentity,
    token: str,
    password: str,
    ip: PeerIP,
) -> AuthFailure | None:
    candidate, valid_length = _candidate(password, settings)
    with db.begin():
        buckets = acquire_buckets(db, settings, identity.username, ip)
        if blocked(buckets, settings):
            append_activity(db, username=identity.username, ip=ip, action="auth.reauth_throttled")
            return AuthFailure.THROTTLED
        found = session_rows(db, settings, token, lock=True)
        if found is None or found[0].id != identity.session_id:
            return AuthFailure.INVALID
        auth_session, user, _ = found
        verified = passwords.verify(candidate, user.password_hash)
        if not (verified and valid_length):
            record_failure(buckets)
            append_activity(db, username=user.username, ip=ip, action="auth.reauth_failed")
            return AuthFailure.INVALID
        auth_session.reauth_at = db.execute(select(func.clock_timestamp())).scalar_one()
        append_activity(
            db, username=user.username, ip=ip, action="auth.reauth", target=str(user.id)
        )
        return None
