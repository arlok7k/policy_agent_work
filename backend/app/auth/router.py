"""Host authentication routes. Authentication state is changed by services."""

from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.dependencies import current_user
from app.auth.schemas import AuthResponse, LoginRequest, PrincipalResponse, ReauthRequest
from app.auth.service import AuthFailure, LoginSuccess, login, logout, reauthenticate
from app.auth.session import CSRF_COOKIE, SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.security import PasswordService

router = APIRouter(prefix="/api/auth", tags=["authentication"])
Database = Annotated[Session, Depends(get_db)]
CookieSession = Annotated[SessionIdentity, Depends(current_user)]


def _peer_ip(request: Request) -> IPv4Address | IPv6Address:
    try:
        if request.client is None:
            raise ValueError("missing peer")
        return ip_address(request.client.host)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request") from None


def _failure(result: AuthFailure) -> NoReturn:
    if result == AuthFailure.THROTTLED:
        raise HTTPException(status_code=429, detail="Authentication temporarily unavailable")
    raise HTTPException(status_code=401, detail="Authentication failed")


def _set_auth_cookies(response: Response, result: LoginSuccess, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        result.session_token,
        max_age=settings.session_ttl_seconds,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE,
        result.csrf_token,
        max_age=settings.session_ttl_seconds,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"


@router.post("/login", response_model=AuthResponse)
def login_route(
    body: LoginRequest, request: Request, response: Response, db: Database
) -> AuthResponse:
    settings: Settings = request.app.state.settings
    passwords: PasswordService = request.app.state.passwords
    try:
        result = login(
            db,
            settings,
            passwords,
            body.username,
            body.password.get_secret_value(),
            _peer_ip(request),
            request.cookies.get(SESSION_COOKIE),
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    if isinstance(result, AuthFailure):
        _failure(result)
    _set_auth_cookies(response, result, settings)
    return AuthResponse(principal=result.principal)


@router.get("/me", response_model=AuthResponse)
def me_route(response: Response, identity: CookieSession) -> AuthResponse:
    response.headers["Cache-Control"] = "no-store"
    return AuthResponse(
        principal=PrincipalResponse(
            kind="user",
            id=identity.user_id,
            username=identity.username,
            roles=[identity.role],
            reauth_at=identity.reauth_at,
        )
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout_route(request: Request, identity: CookieSession, db: Database) -> Response:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(SESSION_COOKIE, "")
    try:
        revoked = logout(db, settings, token, _peer_ip(request))
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    if not revoked:
        raise HTTPException(status_code=401, detail="Authentication failed")
    response = Response(
        status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"}
    )
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=True, httponly=False, samesite="strict")
    return response


@router.post("/reauth", status_code=status.HTTP_204_NO_CONTENT)
def reauth_route(
    body: ReauthRequest, request: Request, identity: CookieSession, db: Database
) -> Response:
    settings: Settings = request.app.state.settings
    passwords: PasswordService = request.app.state.passwords
    try:
        outcome = reauthenticate(
            db,
            settings,
            passwords,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            body.password.get_secret_value(),
            _peer_ip(request),
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    if outcome is not None:
        _failure(outcome)
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
