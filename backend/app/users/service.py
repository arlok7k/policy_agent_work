"""Admin-only user operations with transactional authorization and audit."""

from collections.abc import Sequence

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.auth.models import ApiKey, AuthSession
from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.http import PeerIP
from app.core.security import PasswordService
from app.users.models import Role, User
from app.users.schemas import UserCreate, UserPage, UserPatch, UserView
from app.users.validation import normalize_username, valid_password


def _view(user: User, role: Role) -> UserView:
    return UserView(
        id=user.id,
        username=user.username,
        role=role.name,
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def _role(db: Session, name: str) -> Role:
    role = db.execute(select(Role).where(Role.name == name)).scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=422, detail="Invalid request")
    return role


def list_users(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    limit: int,
    offset: int,
) -> UserPage:
    with db.begin():
        lock_authorized_actor(db, settings, token, identity, roles)
        query = (
            select(User, Role)
            .join(Role, User.role_id == Role.id)
            .order_by(User.username, User.id)
            .limit(limit)
            .offset(offset)
        )
        rows = db.execute(query).all()
        return UserPage(items=[_view(row[0], row[1]) for row in rows], limit=limit, offset=offset)


def create_user(
    db: Session,
    settings: Settings,
    passwords: PasswordService,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    body: UserCreate,
    ip: PeerIP,
) -> UserView:
    username = normalize_username(body.username, settings)
    password = body.password.get_secret_value()
    if username is None or not valid_password(password, settings):
        raise HTTPException(status_code=422, detail="Invalid request")
    password_hash = passwords.hash_password(password)
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, token, identity, roles)
        role = _role(db, body.role)
        user = User(username=username, password_hash=password_hash, role_id=role.id, is_active=True)
        db.add(user)
        db.flush()
        append_activity(
            db, username=actor.username, ip=ip, action="user.create", target=str(user.id)
        )
        return _view(user, role)


def update_user(
    db: Session,
    settings: Settings,
    passwords: PasswordService,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    body: UserPatch,
    ip: PeerIP,
) -> UserView:
    password_hash: str | None = None
    if body.password is not None:
        password = body.password.get_secret_value()
        if not valid_password(password, settings):
            raise HTTPException(status_code=422, detail="Invalid request")
        password_hash = passwords.hash_password(password)
    with db.begin():
        actor, users = lock_authorized_actor(
            db, settings, token, identity, roles, other_user_ids=[body.id]
        )
        user = users.get(body.id)
        if user is None:
            raise HTTPException(status_code=404, detail="Not found")
        if body.id == actor.user_id and (
            body.is_active is False or (body.role is not None and body.role != actor.role)
        ):
            raise HTTPException(status_code=409, detail="Request denied")
        role = _role(db, body.role) if body.role is not None else db.get_one(Role, user.role_id)
        if body.role is not None:
            user.role_id = role.id
        if body.is_active is not None:
            user.is_active = body.is_active
        if password_hash is not None:
            user.password_hash = password_hash
        if password_hash is not None or body.is_active is False:
            db.execute(
                update(AuthSession)
                .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
                .values(revoked_at=func.clock_timestamp())
            )
        if body.is_active is False:
            db.execute(
                update(ApiKey)
                .where(ApiKey.owner_user_id == user.id, ApiKey.revoked_at.is_(None))
                .values(revoked_at=func.clock_timestamp())
            )
        db.flush()
        db.refresh(user)
        append_activity(
            db, username=actor.username, ip=ip, action="user.update", target=str(user.id)
        )
        return _view(user, role)
