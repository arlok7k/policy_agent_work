"""Load the versioned host authorization matrix as immutable data."""

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate operation")
        result[key] = value
    return result


def load_legacy_policy(path: Path | None = None) -> Mapping[str, tuple[str, ...]]:
    location = path if path is not None else Path(__file__).with_name("legacy_roles.json")
    try:
        parsed = json.loads(location.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(parsed, dict) or not {"users", "api_keys"}.issubset(parsed):
            raise ValueError("missing legacy operations")
        rules: dict[str, tuple[str, ...]] = {}
        for operation, values in parsed.items():
            if not isinstance(operation, str) or not operation:
                raise ValueError("invalid operation")
            if not isinstance(values, list) or not values:
                raise ValueError("missing roles")
            if any(
                not isinstance(role, str) or not role or role != role.strip() for role in values
            ):
                raise ValueError("invalid role")
            if len(set(values)) != len(values):
                raise ValueError("duplicate role")
            rules[operation] = tuple(values)
        return MappingProxyType(rules)
    except OSError, UnicodeError, ValueError, TypeError:
        raise RuntimeError("Legacy authorization policy is invalid") from None
