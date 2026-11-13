"""Central double-submit CSRF enforcement for cookie-authenticated mutations."""

import hmac
from collections.abc import Awaitable, Callable

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response

from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, session_rows
from app.core.config import Settings
from app.core.security import credential_digest

CallNext = Callable[[Request], Awaitable[Response]]


def _check_csrf(request: Request, token: str) -> int | None:
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    try:
        with factory() as db:
            rows = session_rows(db, settings, token)
            if rows is None:
                # A stale browser cookie must not prevent a fresh public login.
                return None if request.url.path == "/api/auth/login" else 401
            cookie = request.cookies.get(CSRF_COOKIE)
            header = request.headers.get(CSRF_HEADER)
            if cookie is None or header is None:
                return 403
            if not hmac.compare_digest(cookie.encode("utf-8"), header.encode("utf-8")):
                return 403
            digest = credential_digest(settings.session_signing_secret, "csrf", header)
            if not hmac.compare_digest(rows[0].csrf_digest, digest):
                return 403
    except SQLAlchemyError:
        return 503
    return None


async def csrf_guard(request: Request, call_next: CallNext) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token and request.headers.get("Authorization") is not None:
        return JSONResponse({"detail": "Authentication failed"}, status_code=401)
    if token and request.method not in {"GET", "HEAD", "OPTIONS"}:
        status = await run_in_threadpool(_check_csrf, request, token)
        if status is not None:
            detail = "Service unavailable" if status == 503 else "Request denied"
            return JSONResponse({"detail": detail}, status_code=status)
    return await call_next(request)
