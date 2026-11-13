"""Issue and verify opaque, domain-separated API-key credentials."""

import hmac
import re
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.auth.models import ApiKey
from app.core.config import Settings
from app.core.security import credential_digest, new_opaque_token
from app.users.models import User

_TOKEN = re.compile(r"soc_([0-9a-f]{32})\.([A-Za-z0-9_-]{43})\Z", flags=re.ASCII)


@dataclass(frozen=True)
class NewKeyCredential:
    prefix: str
    secret: str = field(repr=False)
    digest: bytes = field(repr=False)


def new_key_credential(settings: Settings) -> NewKeyCredential:
    prefix = uuid4().hex
    secret = f"soc_{prefix}.{new_opaque_token()}"
    return NewKeyCredential(
        prefix=prefix,
        secret=secret,
        digest=credential_digest(settings.session_signing_secret, "api-key", secret),
    )


def authenticate_api_key(request: Request) -> UUID:
    """Return only a live service-principal key ID; never fall back to cookies."""
    header = request.headers.get("Authorization", "")
    scheme, separator, secret = header.partition(" ")
    matched = _TOKEN.fullmatch(secret) if scheme.lower() == "bearer" and separator else None
    if matched is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    digest = credential_digest(settings.session_signing_secret, "api-key", secret)
    try:
        with factory() as db:
            query = (
                select(ApiKey)
                .join(User, ApiKey.owner_user_id == User.id)
                .where(
                    ApiKey.prefix == matched.group(1),
                    ApiKey.revoked_at.is_(None),
                    ApiKey.expires_at > func.clock_timestamp(),
                    User.is_active.is_(True),
                )
            )
            key = db.execute(query).scalar_one_or_none()
            stored = key.key_digest if key is not None else bytes(len(digest))
            valid = hmac.compare_digest(stored, digest)
            if key is None or not valid:
                raise HTTPException(status_code=401, detail="Authentication failed")
            return key.id
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
