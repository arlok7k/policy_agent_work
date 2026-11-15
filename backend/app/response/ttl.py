"""Bounded, database-clock L2 rollback; all effects remain simulated."""

from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.connectors.base import ConnectorRefused
from app.connectors.registry import CONNECTORS
from app.core.activity import append_activity
from app.core.models import CaseActivity
from app.jobs.celery_app import TTL_INITIATOR
from app.response.catalog import CATALOG
from app.response.gate import transition
from app.response.models import ResponseAction
from app.response.rules import lock_safety_snapshot
from app.response.safeguards import SafeguardAction, check_safeguards

RollbackResult = Literal["rolled_back", "paused", "refused", "noop"]


def database_now(db: Session) -> datetime:
    """Use only the database clock; task messages never supply a deadline."""
    return cast(datetime, db.execute(select(func.clock_timestamp())).scalar_one())


def due_for_rollback(db: Session, batch_size: int) -> list[UUID]:
    """Find a bounded fair batch; every rollback rechecks under its own locks."""
    if batch_size < 1:
        raise ValueError("A positive batch size is required")
    safety = lock_safety_snapshot(db)
    if safety.kill_switch_engaged:
        return []
    now = database_now(db)
    return list(
        db.execute(
            select(ResponseAction.id)
            .where(
                ResponseAction.status == "executed",
                ResponseAction.level == 2,
                ResponseAction.ttl_expires_at <= now,
            )
            # Refused attempts update this timestamp and rotate to the back.
            .order_by(ResponseAction.updated_at, ResponseAction.id)
            .limit(batch_size)
        )
        .scalars()
        .all()
    )


def _refused_once(db: Session, action: ResponseAction, reason: str) -> RollbackResult:
    target = f"response_action:{action.id}"
    exists = db.execute(
        select(CaseActivity.id)
        .where(
            CaseActivity.action == "response.ttl_refused",
            CaseActivity.target == target,
            CaseActivity.details["reason"].astext == reason,
        )
        .limit(1)
    ).scalar_one_or_none()
    if exists is None:
        append_activity(
            db,
            username=TTL_INITIATOR,
            ip=None,
            action="response.ttl_refused",
            target=target,
            details={"reason": reason},
        )
    # The existing action trigger changes updated_at to the DB clock. This
    # rotates an unsafe row behind other due work without creating audit spam.
    action.updated_at = database_now(db)
    db.flush()
    return "refused"


def rollback_expired(db: Session, action_id: UUID) -> RollbackResult:
    """Rollback one still-due L2 action under a fresh, retained safety lock."""
    safety = lock_safety_snapshot(db)
    action = db.execute(
        select(ResponseAction).where(ResponseAction.id == action_id).with_for_update()
    ).scalar_one_or_none()
    if (
        action is None
        or action.status != "executed"
        or action.level != 2
        or action.ttl_expires_at is None
        or action.ttl_expires_at > database_now(db)
    ):
        return "noop"
    if safety.kill_switch_engaged:
        return "paused"
    original = CATALOG.get(action.action_type)
    if (
        original is None
        or original.level != 2
        or not original.requestable
        or not original.reversible
        or original.reverse_action is None
    ):
        return _refused_once(db, action, "invalid_action")
    reverse = CATALOG.get(original.reverse_action)
    if reverse is None or reverse.connector not in CONNECTORS:
        return _refused_once(db, action, "invalid_action")
    result = check_safeguards(
        SafeguardAction(reverse.name, action.target, action.params, safety.rules, "rollback")
    )
    if not result.ok:
        return _refused_once(db, action, "safeguard")
    try:
        CONNECTORS[reverse.connector].execute(
            db,
            action,
            phase="rollback",
            initiator=TTL_INITIATOR,
            automated=True,
            safety=safety,
        )
    except ConnectorRefused:
        return _refused_once(db, action, "connector_refused")
    transition(db, action, "rolled_back", username=TTL_INITIATOR, ip=None)
    return "rolled_back"
