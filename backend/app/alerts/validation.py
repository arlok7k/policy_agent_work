"""Bounded alert field and strict JSON validation shared by API and worker."""

import json
import math
from typing import Any, NoReturn

from pydantic import ValidationError

from app.alerts.schemas import WebhookAlert
from app.core.exceptions import BadRequest


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> NoReturn:
    raise ValueError("invalid JSON number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("invalid JSON number")
    return result


def _valid_json_text(value: Any) -> None:
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("invalid text")
        value.encode("utf-8")
    elif isinstance(value, dict):
        for key, item in value.items():
            _valid_json_text(key)
            _valid_json_text(item)
    elif isinstance(value, list):
        for item in value:
            _valid_json_text(item)


def validate_alert(body: bytes, *, max_field_chars: int) -> WebhookAlert:
    """Reject ambiguous JSON and strings PostgreSQL cannot safely store."""
    try:
        decoded = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )
        _valid_json_text(decoded)
        payload = WebhookAlert.model_validate(decoded)
        for value in (payload.source, payload.rule_id, payload.severity, payload.agent):
            if value is not None and (not value.strip() or len(value) > max_field_chars):
                raise ValueError("invalid alert text")
        return payload
    except ValueError, UnicodeError, ValidationError, RecursionError:
        raise BadRequest() from None
