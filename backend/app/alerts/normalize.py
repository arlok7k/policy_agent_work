"""Canonical alert normalization and atomic PostgreSQL deduplication."""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.alerts.models import Alert
from app.alerts.validation import validate_alert
from app.core.exceptions import BadRequest


@dataclass(frozen=True)
class NormalizedAlert:
    source: str
    rule_id: str
    severity: str
    agent: str | None
    src_ip: str | None
    dst_ip: str | None
    raw: dict[str, Any]
    fingerprint: bytes = field(repr=False)


def normalize_alert(payload: dict[str, Any], *, max_field_chars: int) -> NormalizedAlert:
    """Revalidate task data and compute a stable digest of normalized fields."""
    try:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        validated = validate_alert(encoded.encode("utf-8"), max_field_chars=max_field_chars)
    except TypeError, ValueError, UnicodeError, RecursionError:
        raise BadRequest() from None
    values: dict[str, Any] = {
        "source": validated.source.strip(),
        "rule_id": validated.rule_id.strip(),
        "severity": validated.severity.strip().lower(),
        "agent": validated.agent.strip() if validated.agent is not None else None,
        "src_ip": str(validated.src_ip) if validated.src_ip is not None else None,
        "dst_ip": str(validated.dst_ip) if validated.dst_ip is not None else None,
        "raw": validated.raw,
    }
    canonical = json.dumps(
        values, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return NormalizedAlert(**values, fingerprint=hashlib.sha256(canonical).digest())


def store_alert(db: Session, alert: NormalizedAlert) -> tuple[UUID, bool]:
    """Insert once under concurrent deliveries; callers own the transaction."""
    statement = (
        insert(Alert)
        .values(
            source=alert.source,
            rule_id=alert.rule_id,
            severity=alert.severity,
            agent=alert.agent,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            raw=alert.raw,
            fingerprint=alert.fingerprint,
        )
        .on_conflict_do_nothing(index_elements=[Alert.fingerprint])
        .returning(Alert.id)
    )
    identifier = db.execute(statement).scalar_one_or_none()
    if identifier is not None:
        return identifier, True
    existing = db.execute(
        select(Alert.id).where(Alert.fingerprint == alert.fingerprint)
    ).scalar_one()
    return existing, False
