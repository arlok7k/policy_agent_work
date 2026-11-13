"""The single host activity writer; callers commit it with their mutation."""

from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy.orm import Session

from app.core.context import correlation_id
from app.core.models import CaseActivity


def append_activity(
    db: Session,
    *,
    username: str,
    ip: IPv4Address | IPv6Address | None,
    action: str,
    target: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    safe_details = {} if details is None else dict(details)
    current = correlation_id.get()
    if current is not None:
        safe_details["correlation_id"] = current
    db.add(
        CaseActivity(
            username=username,
            ip=ip,
            action=action,
            target=target,
            details=safe_details,
        )
    )
