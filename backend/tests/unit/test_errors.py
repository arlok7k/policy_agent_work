"""Host failures carry stable statuses without input-bearing detail."""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.core.errors import install_error_handling
from app.core.exceptions import (
    BadRequest,
    Conflict,
    Forbidden,
    HostError,
    NotFound,
    SemanticError,
    Throttled,
    Unauthenticated,
    Unavailable,
)


@pytest.mark.parametrize(
    "error_type,status",
    [
        (BadRequest, 400),
        (Unauthenticated, 401),
        (Forbidden, 403),
        (NotFound, 404),
        (Conflict, 409),
        (SemanticError, 422),
        (Throttled, 429),
        (Unavailable, 503),
    ],
)
def test_typed_host_error_status(error_type: type[HostError], status: int) -> None:
    error = error_type()
    assert error.status_code == status
    assert error.detail == "Request failed"


def test_unavailable_retry_hint_must_be_positive() -> None:
    assert Unavailable().headers is None
    assert Unavailable(retry_after=47).headers == {"Retry-After": "47"}
    with pytest.raises(ValueError, match="positive"):
        Unavailable(retry_after=0)


@pytest.mark.parametrize(
    "value,expected",
    [("30", "30"), ("bad", None), ("2\r\nX-Injected: yes", None), ("３", None)],
)
def test_503_problem_forwards_only_safe_numeric_retry_hints(
    value: str, expected: str | None
) -> None:
    app = FastAPI()
    install_error_handling(app)

    @app.get("/")
    def unavailable() -> None:
        raise HTTPException(503, headers={"Retry-After": value, "X-Unsafe": "not forwarded"})

    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 503
    assert response.headers.get("Retry-After") == expected
    assert "X-Unsafe" not in response.headers
