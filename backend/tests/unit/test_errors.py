"""Host failures carry stable statuses without input-bearing detail."""

import pytest

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
