"""Request correlation context, with no user-provided free text."""

from contextvars import ContextVar
from uuid import UUID, uuid4

correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def safe_correlation_id(value: str | None) -> str:
    """Accept only canonical UUIDv4 values; otherwise generate a fresh identifier."""
    if value is not None:
        try:
            parsed = UUID(value)
        except ValueError, AttributeError:
            pass
        else:
            if parsed.version == 4 and str(parsed) == value:
                return str(parsed)
    return str(uuid4())
