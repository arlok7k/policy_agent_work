"""Structured HTTP events built exclusively from allow-listed metadata."""

import json
import logging
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import Request
from starlette.routing import BaseRoute

from app.core.config import Settings
from app.core.security import credential_digest

logger = logging.getLogger("smart_soc")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def mark_principal(request: Request, kind: Literal["user", "service"], principal_id: UUID) -> None:
    request.state.principal_kind = kind
    request.state.principal_id = principal_id


def log_request(request: Request, status: int, correlation: str, error_type: str | None) -> None:
    route = request.scope.get("route")
    path = route.path if isinstance(route, BaseRoute) and hasattr(route, "path") else "unmatched"
    method = request.method
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        method = "OTHER"
    kind = getattr(request.state, "principal_kind", "anonymous")
    principal_id = getattr(request.state, "principal_id", None)
    hashed = None
    if isinstance(principal_id, UUID):
        settings: Settings = request.app.state.settings
        hashed = credential_digest(
            settings.session_signing_secret, "log-principal", str(principal_id)
        ).hex()
    level = logging.ERROR if status >= 500 else logging.WARNING if status >= 400 else logging.INFO
    outcome = "error" if status >= 500 else "denied" if status >= 400 else "success"
    event = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "level": logging.getLevelName(level),
        "component": "http",
        "correlation_id": correlation,
        "principal_kind": kind,
        "principal_id": hashed,
        "op": f"{method} {path}",
        "outcome": outcome,
        "status": status,
    }
    if error_type is not None and error_type.isidentifier():
        event["error_type"] = error_type
    logger.log(level, json.dumps(event, separators=(",", ":")))
