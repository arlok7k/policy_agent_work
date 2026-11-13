"""Cookie-session identity resolution shared by authentication endpoints."""

from fastapi import HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.auth.key_credentials import authenticate_api_key
from app.auth.schemas import PrincipalResponse
from app.auth.session import SESSION_COOKIE, SessionIdentity, identity_from_rows, session_rows
from app.core.config import Settings


def current_user(request: Request) -> SessionIdentity:
    token = request.cookies.get(SESSION_COOKIE)
    authorization = request.headers.get("Authorization")
    if token and authorization is not None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    if not token:
        if authorization is not None:
            authenticate_api_key(request)
            raise HTTPException(status_code=403, detail="Request denied")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed"
        )
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    try:
        with factory() as db:
            rows = session_rows(db, settings, token)
            if rows is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed"
                )
            return identity_from_rows(rows)
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None


def current_principal(request: Request) -> PrincipalResponse:
    authorization = request.headers.get("Authorization")
    if authorization is not None:
        if request.cookies.get(SESSION_COOKIE):
            raise HTTPException(status_code=401, detail="Authentication failed")
        return PrincipalResponse(
            kind="service",
            id=authenticate_api_key(request),
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
