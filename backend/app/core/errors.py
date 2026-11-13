"""Generic RFC 9457 problem responses and correlation middleware."""

from collections.abc import Awaitable, Callable
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from app.core.context import correlation_id, safe_correlation_id
from app.core.logging import log_request

CallNext = Callable[[Request], Awaitable[Response]]


def problem_response(
    request: Request, status: int, headers: dict[str, str] | None = None
) -> JSONResponse:
    try:
        title = HTTPStatus(status).phrase
    except ValueError:
        title = "Request failed"
    current = getattr(request.state, "correlation_id", None) or safe_correlation_id(None)
    return JSONResponse(
        {
            "type": "about:blank",
            "title": title,
            "status": status,
            "code": f"GOV-HTTP-{status:03d}",
            "correlation_id": current,
        },
        status_code=status,
        media_type="application/problem+json",
        headers={"Cache-Control": "no-store", **(headers or {})},
    )


async def _validation_problem(request: Request, error: Exception) -> JSONResponse:
    return problem_response(request, 400)


async def _http_problem(request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, StarletteHTTPException):
        return problem_response(request, 500)
    headers: dict[str, str] = {}
    if error.status_code == 405 and error.headers:
        allowed = error.headers.get("Allow", "")
        methods = {item.strip() for item in allowed.split(",")}
        if methods and methods <= {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            headers["Allow"] = ", ".join(sorted(methods))
    return problem_response(request, error.status_code, headers)


async def correlation_middleware(request: Request, call_next: CallNext) -> Response:
    current = safe_correlation_id(request.headers.get("X-Correlation-Id"))
    request.state.correlation_id = current
    context_token = correlation_id.set(current)
    error_type = None
    try:
        try:
            response = await call_next(request)
        except Exception as error:
            # Do not expose exception text, which can contain request values or credentials.
            error_type = type(error).__name__
            response = problem_response(request, 500)
        response.headers["X-Correlation-Id"] = current
        log_request(request, response.status_code, current, error_type)
        return response
    finally:
        correlation_id.reset(context_token)


def install_error_handling(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, _validation_problem)
    app.add_exception_handler(StarletteHTTPException, _http_problem)
    app.middleware("http")(correlation_middleware)
