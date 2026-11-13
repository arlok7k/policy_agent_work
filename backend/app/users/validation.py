"""Shared normalization and configured password policy for host accounts."""

import re

from app.core.config import Settings

_USERNAME = re.compile(r"[a-z0-9][a-z0-9._@-]*\Z", flags=re.ASCII)


def normalize_username(value: str, settings: Settings) -> str | None:
    candidate = value.strip()
    if not candidate.isascii() or not 0 < len(candidate) <= settings.username_max_chars:
        return None
    normalized = candidate.lower()
    return normalized if _USERNAME.fullmatch(normalized) else None


def valid_password(value: str, settings: Settings) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return settings.password_min_chars <= len(value) <= settings.password_max_chars
