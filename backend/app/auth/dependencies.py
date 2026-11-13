"""Cookie-session identity resolution shared by authentication endpoints."""

from fastapi import HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.auth.session import SESSION_COOKIE, SessionIdentity, identity_from_rows, session_rows
from app.core.config import Settings


def current_user(request: Request) -> SessionIdentity:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
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
