"""Build the minimal alert context allowed to reach the mock AI adapter."""

from collections.abc import Callable
from ipaddress import ip_address
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ai.providers import AlertContext
from app.alerts.models import Alert
from app.core.exceptions import NotFound, Unavailable


def invoke_provider[T](method: Callable[[AlertContext], T], alert: AlertContext) -> T:
    """Return no fabricated result when the mock adapter fails."""
    try:
        return method(alert)
    except Exception:
        raise Unavailable() from None


def load_alert_context(db: Session, alert_id: UUID) -> AlertContext:
    try:
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise NotFound()
        return AlertContext(
            id=alert.id,
            source=alert.source,
            rule_id=alert.rule_id,
            severity=alert.severity,
            status=alert.status,
            agent=alert.agent,
            src_ip=ip_address(alert.src_ip) if alert.src_ip is not None else None,
            dst_ip=ip_address(alert.dst_ip) if alert.dst_ip is not None else None,
        )
    except SQLAlchemyError:
        raise Unavailable() from None
