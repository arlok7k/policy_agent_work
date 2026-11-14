"""Legacy-role-protected alert list, detail, and summary endpoints."""

from dataclasses import dataclass
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import IPvAnyAddress
from sqlalchemy import func, select, tuple_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.alerts.models import Alert
from app.alerts.schemas import AlertPage, AlertSummary, AlertView
from app.auth.roles import require_operation
from app.auth.session import SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import BadRequest, NotFound, Unavailable
from app.core.http import page_size, private_json
from app.core.pagination import decode_cursor, encode_cursor
from app.core.pb2_config import PB2Settings

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
Database = Annotated[Session, Depends(get_db)]
AlertReader = Annotated[SessionIdentity, Depends(require_operation("alerts_read"))]


@dataclass(frozen=True)
class AlertFilters:
    source: str | None
    severity: str | None
    status: str | None
    agent: str | None
    src_ip: IPv4Address | IPv6Address | None
    dst_ip: IPv4Address | IPv6Address | None


def _text_filter(value: str | None, maximum: int, *, lowercase: bool = False) -> str | None:
    if value is None:
        return None
    result = value.strip()
    if not result or len(result) > maximum or "\x00" in result:
        raise BadRequest()
    return result.lower() if lowercase else result


@router.get("", response_model=AlertPage)
def list_alerts(
    request: Request,
    response: Response,
    identity: AlertReader,
    db: Database,
    source: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    agent: str | None = None,
    src_ip: IPvAnyAddress | None = None,
    dst_ip: IPvAnyAddress | None = None,
    limit: Annotated[int | None, Query(gt=0)] = None,
    cursor: str | None = None,
) -> AlertPage:
    settings: Settings = request.app.state.settings
    pb2: PB2Settings = request.app.state.pb2_settings
    size = page_size(settings, limit)
    filters = AlertFilters(
        source=_text_filter(source, pb2.webhook_max_field_chars),
        severity=_text_filter(severity, pb2.webhook_max_field_chars, lowercase=True),
        status=_text_filter(status, pb2.webhook_max_field_chars, lowercase=True),
        agent=_text_filter(agent, pb2.webhook_max_field_chars),
        src_ip=src_ip,
        dst_ip=dst_ip,
    )
    query = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())
    for column, value in (
        (Alert.source, filters.source),
        (Alert.severity, filters.severity),
        (Alert.status, filters.status),
        (Alert.agent, filters.agent),
        (Alert.src_ip, filters.src_ip),
        (Alert.dst_ip, filters.dst_ip),
    ):
        if value is not None:
            query = query.where(column == value)
    if cursor is not None:
        created_at, identifier = decode_cursor(cursor)
        query = query.where(tuple_(Alert.created_at, Alert.id) < tuple_(created_at, identifier))
    try:
        alerts = list(db.execute(query.limit(size + 1)).scalars())
        has_next = len(alerts) > size
        alerts = alerts[:size]
        next_cursor = encode_cursor(alerts[-1].created_at, alerts[-1].id) if has_next else None
        result = AlertPage(
            items=[AlertView.model_validate(alert) for alert in alerts], next_cursor=next_cursor
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.get("/stats/summary", response_model=AlertSummary)
def alert_summary(response: Response, identity: AlertReader, db: Database) -> AlertSummary:
    try:
        severities = db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
        statuses = db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all()
        recent = db.execute(
            select(func.count())
            .select_from(Alert)
            .where(Alert.created_at >= func.clock_timestamp() - timedelta(hours=24))
        ).scalar_one()
        result = AlertSummary(
            by_severity={severity: count for severity, count in severities},
            by_status={status: count for status, count in statuses},
            last_24h=recent,
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.get("/{alert_id}", response_model=AlertView)
def alert_detail(
    alert_id: UUID, response: Response, identity: AlertReader, db: Database
) -> AlertView:
    try:
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise NotFound()
        result = AlertView.model_validate(alert)
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result
