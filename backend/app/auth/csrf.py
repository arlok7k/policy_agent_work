"""Central double-submit CSRF enforcement for cookie-authenticated mutations."""

import hmac
from collections.abc import Awaitable, Callable

from fastapi import Request
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, session_rows
from app.core.config import Settings
from app.core.errors import problem_response
from app.core.security import credential_digest

CallNext = Callable[[Request], Awaitable[Response]]


def csrf_matches(
    secret: SecretStr, expected_digest: bytes, cookie: str | None, header: str | None
) -> bool:
    if cookie is None or header is None:
        return False
    try:
        cookie_bytes = cookie.encode("utf-8")
        header_bytes = header.encode("utf-8")
    except UnicodeError:
        return False
    if not hmac.compare_digest(cookie_bytes, header_bytes):
        return False
    digest = credential_digest(secret, "csrf", header)
    return hmac.compare_digest(expected_digest, digest)


def _check_csrf(request: Request, token: str) -> int | None:
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    try:
        with factory() as db:
            rows = session_rows(db, settings, token)
            if rows is None:
                # A stale browser cookie must not prevent a fresh public login.
                return None if request.url.path == "/api/auth/login" else 401
            if not csrf_matches(
                settings.session_signing_secret,
                rows[0].csrf_digest,
                request.cookies.get(CSRF_COOKIE),
                request.headers.get(CSRF_HEADER),
            ):
                return 403
    except SQLAlchemyError:
        return 503
    return None


async def csrf_guard(request: Request, call_next: CallNext) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token and request.headers.get("Authorization") is not None:
        return problem_response(request, 401)
    if token and request.method not in {"GET", "HEAD", "OPTIONS"}:
        status = await run_in_threadpool(_check_csrf, request, token)
        if status is not None:
            return problem_response(request, status)
    return await call_next(request)
