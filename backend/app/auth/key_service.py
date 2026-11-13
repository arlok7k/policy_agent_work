"""Administrator-owned API-key creation, listing and revocation."""

from collections.abc import Sequence
from datetime import timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.key_credentials import new_key_credential
from app.auth.key_schemas import KeyCreate, KeyIssued, KeyPage, KeyView
from app.auth.models import ApiKey
from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.exceptions import NotFound, SemanticError
from app.core.http import PeerIP


def _view(key: ApiKey) -> KeyView:
    return KeyView(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        created_at=key.created_at,
        expires_at=key.expires_at,
        revoked_at=key.revoked_at,
    )


def list_keys(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    limit: int,
    offset: int,
) -> KeyPage:
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, token, identity, roles)
        query = (
            select(ApiKey)
            .where(ApiKey.owner_user_id == actor.user_id)
            .order_by(ApiKey.created_at, ApiKey.id)
            .limit(limit)
            .offset(offset)
        )
        return KeyPage(
            items=[_view(key) for key in db.execute(query).scalars()], limit=limit, offset=offset
        )


def create_key(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    body: KeyCreate,
    ip: PeerIP,
) -> KeyIssued:
    name = body.name.strip()
    try:
        name.encode("utf-8")
    except UnicodeError:
        raise SemanticError() from None
    if not name or len(name) > settings.api_key_name_max_chars:
        raise SemanticError()
    if not 0 < body.ttl_seconds <= settings.max_api_key_ttl_seconds:
        raise SemanticError()
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, token, identity, roles)
        now = db.execute(select(func.clock_timestamp())).scalar_one()
        try:
            expires_at = now + timedelta(seconds=body.ttl_seconds)
        except OverflowError:
            raise SemanticError() from None
        credential = new_key_credential(settings)
        key = ApiKey(
            owner_user_id=actor.user_id,
            name=name,
            prefix=credential.prefix,
            key_digest=credential.digest,
            expires_at=expires_at,
        )
        db.add(key)
        db.flush()
        append_activity(
            db, username=actor.username, ip=ip, action="api_key.create", target=str(key.id)
        )
        return KeyIssued(key=_view(key), secret=credential.secret)


def revoke_key(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    key_id: UUID,
    ip: PeerIP,
) -> None:
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, token, identity, roles)
        query = (
            select(ApiKey)
            .where(ApiKey.id == key_id, ApiKey.owner_user_id == actor.user_id)
            .with_for_update()
        )
        key = db.execute(query).scalar_one_or_none()
        if key is None:
            raise NotFound()
        if key.revoked_at is None:
            key.revoked_at = db.execute(select(func.clock_timestamp())).scalar_one()
            append_activity(
                db, username=actor.username, ip=ip, action="api_key.revoke", target=str(key.id)
            )
