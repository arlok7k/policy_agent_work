"""Keep throwaway test credentials out of object representations.

Unwrap values only at the API, database, or process boundary.  This wrapper
cannot protect a value that a caller explicitly reveals, serializes, or logs.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi.testclient import TestClient


class Redacted:
    """A test value whose normal string and container representations are safe."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Redacted test values must be strings")
        self._value = value

    @classmethod
    def random(cls, nbytes: int = 32) -> Redacted:
        return cls(secrets.token_urlsafe(nbytes))

    def reveal(self) -> str:
        """Return the underlying value solely for an actual integration boundary."""
        return self._value

    def __repr__(self) -> str:
        return "Redacted(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


def reveal(value: Any) -> Any:
    """Copy and unwrap sensitive values in simple test request/environment data."""
    if isinstance(value, Redacted):
        return value.reveal()
    if isinstance(value, dict):
        return {key: reveal(item) for key, item in value.items()}
    if isinstance(value, list):
        return [reveal(item) for item in value]
    if isinstance(value, tuple):
        return tuple(reveal(item) for item in value)
    return value


def assert_not_disclosed(label: str, output: str, *values: Redacted) -> None:
    """Assert absence without echoing an output that might contain a secret."""
    if any(value.reveal() in output for value in values):
        raise AssertionError(f"{label} disclosed a protected test value")


class SecretAwareTestClient(TestClient):
    """Unwrap request values at the HTTP boundary, without mutating test data."""

    def request(self, method: str, url: Any, **kwargs: Any) -> Any:
        for key in ("json", "headers", "cookies", "params", "data"):
            if key in kwargs:
                kwargs[key] = reveal(kwargs[key])
        return super().request(method, url, **kwargs)
