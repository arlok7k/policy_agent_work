"""Host authentication routes. Authentication state is changed by services."""

from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.dependencies import current_principal, current_user
from app.auth.schemas import AuthResponse, LoginRequest, PrincipalResponse, ReauthRequest
from app.auth.service import AuthFailure, LoginSuccess, login, logout, reauthenticate
from app.auth.session import CSRF_COOKIE, SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import Throttled, Unauthenticated, Unavailable
from app.core.http import request_peer_ip
from app.core.logging import mark_principal
from app.core.security import PasswordService

router = APIRouter(prefix="/api/auth", tags=["authentication"])
Database = Annotated[Session, Depends(get_db)]
CookieSession = Annotated[SessionIdentity, Depends(current_user)]
CurrentPrincipal = Annotated[PrincipalResponse, Depends(current_principal)]


def _failure(result: AuthFailure) -> NoReturn:
    if result == AuthFailure.THROTTLED:
        raise Throttled()
    raise Unauthenticated()


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
            request_peer_ip(request),
            request.cookies.get(SESSION_COOKIE),
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    if isinstance(result, AuthFailure):
        _failure(result)
    mark_principal(request, "user", result.principal.id)
    _set_auth_cookies(response, result, settings)
    return AuthResponse(principal=result.principal)


@router.get("/me", response_model=AuthResponse)
def me_route(response: Response, principal: CurrentPrincipal) -> AuthResponse:
    response.headers["Cache-Control"] = "no-store"
    return AuthResponse(principal=principal)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout_route(request: Request, identity: CookieSession, db: Database) -> Response:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(SESSION_COOKIE, "")
    try:
        revoked = logout(db, settings, token, request_peer_ip(request))
    except SQLAlchemyError:
        raise Unavailable() from None
    if not revoked:
        raise Unauthenticated()
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
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    if outcome is not None:
        _failure(outcome)
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
