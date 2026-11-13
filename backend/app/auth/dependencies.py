"""Cookie-session identity resolution shared by authentication endpoints."""

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.auth.key_credentials import authenticate_api_key
from app.auth.schemas import PrincipalResponse
from app.auth.session import SESSION_COOKIE, SessionIdentity, identity_from_rows, session_rows
from app.core.config import Settings
from app.core.exceptions import Forbidden, Unauthenticated, Unavailable
from app.core.logging import mark_principal


def current_user(request: Request) -> SessionIdentity:
    token = request.cookies.get(SESSION_COOKIE)
    authorization = request.headers.get("Authorization")
    if token and authorization is not None:
        raise Unauthenticated()
    if not token:
        if authorization is not None:
            key_id = authenticate_api_key(request)
            mark_principal(request, "service", key_id)
            raise Forbidden()
        raise Unauthenticated()
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    try:
        with factory() as db:
            rows = session_rows(db, settings, token)
            if rows is None:
                raise Unauthenticated()
            identity = identity_from_rows(rows)
            mark_principal(request, "user", identity.user_id)
            return identity
    except SQLAlchemyError:
        raise Unavailable() from None


def current_principal(request: Request) -> PrincipalResponse:
    authorization = request.headers.get("Authorization")
    if authorization is not None:
        if request.cookies.get(SESSION_COOKIE):
            raise Unauthenticated()
        key_id = authenticate_api_key(request)
        mark_principal(request, "service", key_id)
        return PrincipalResponse(
            kind="service",
            id=key_id,
            username=None,
            roles=[],
            reauth_at=None,
        )
    user = current_user(request)
    return PrincipalResponse(
        kind="user",
        id=user.user_id,
        username=user.username,
        roles=[user.role],
        reauth_at=user.reauth_at,
    )
