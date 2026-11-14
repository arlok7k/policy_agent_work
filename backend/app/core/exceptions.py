"""Typed host failures mapped centrally to generic problem responses."""

from fastapi import HTTPException


class HostError(HTTPException):
    http_status = 500

    def __init__(self) -> None:
        super().__init__(status_code=self.http_status, detail="Request failed")


class BadRequest(HostError):
    http_status = 400


class Unauthenticated(HostError):
    http_status = 401


class Forbidden(HostError):
    http_status = 403


class NotFound(HostError):
    http_status = 404


class Conflict(HostError):
    http_status = 409


class PayloadTooLarge(HostError):
    http_status = 413


class SemanticError(HostError):
    http_status = 422


class Throttled(HostError):
    http_status = 429


class Unavailable(HostError):
    http_status = 503
