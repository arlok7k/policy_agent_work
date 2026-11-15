"""Durable manual rollback intent, independently revalidated by a worker."""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import UUID

from sqlalchemy import BigInteger, Text, func, select
from sqlalchemy import cast as sql_cast
from sqlalchemy.orm import Session

from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.connectors.base import ConnectorRefused
from app.connectors.registry import CONNECTORS
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.exceptions import Conflict, Forbidden, NotFound, SemanticError
from app.core.http import PeerIP
from app.core.models import CaseActivity
from app.response.catalog import CATALOG, ActionDefinition
from app.response.gate import transition
from app.response.models import ResponseAction
from app.response.rules import SafetySnapshot, lock_safety_snapshot
from app.response.safeguards import SafeguardAction, check_safeguards
from app.users.models import Role, User

ManualResult = Literal["rolled_back", "refused", "noop"]
RollbackStatus = Literal["pending", "refused", "resolved"]
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_OPERATORS = frozenset({"senior_analyst", "admin"})


def _request_token(value: datetime) -> str:
    delta = value.astimezone(UTC) - _EPOCH
    return str((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds)


def _refusal_exists(db: Session, action_id: UUID, requested_at: datetime) -> bool:
    return (
        db.execute(
            select(CaseActivity.id)
            .where(
                CaseActivity.action == "response.manual_rollback_refused",
                CaseActivity.target == f"response_action:{action_id}",
                CaseActivity.details["request_token"].astext == _request_token(requested_at),
            )
            .limit(1)
        ).scalar_one_or_none()
        is not None
    )


def manual_request_status(db: Session, action: ResponseAction) -> RollbackStatus | None:
    if action.rollback_requested_by is None or action.rollback_requested_at is None:
        return None
    if action.status == "rolled_back":
        return "resolved"
    if _refusal_exists(db, action.id, action.rollback_requested_at):
        return "refused"
    return "pending"


def _safe_reverse(action: ResponseAction, safety: SafetySnapshot) -> ActionDefinition | None:
    original = CATALOG.get(action.action_type)
    if (
        original is None
        or original.level != action.level
        or not original.requestable
        or not original.reversible
        or original.reverse_action is None
    ):
        return None
    reverse = CATALOG.get(original.reverse_action)
    if reverse is None or reverse.connector not in CONNECTORS:
        return None
    result = check_safeguards(
        SafeguardAction(reverse.name, action.target, action.params, safety.rules, "rollback")
    )
    return reverse if result.ok else None


def request_manual_rollback(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    session_token: str,
    roles: Sequence[str],
    action_id: UUID,
    ip: PeerIP,
) -> ResponseAction:
    """Record a new authorized intent; never execute a connector in HTTP."""
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, session_token, identity, roles)
        if actor.role not in _OPERATORS:
            raise Forbidden()
        safety = lock_safety_snapshot(db)
        action = db.execute(
            select(ResponseAction).where(ResponseAction.id == action_id).with_for_update()
        ).scalar_one_or_none()
        if action is None:
            raise NotFound()
        original = CATALOG.get(action.action_type)
        if action.status != "executed" or original is None or not original.reversible:
            raise Conflict()
        if _safe_reverse(action, safety) is None:
            raise SemanticError()
        now = cast(datetime, db.execute(select(func.clock_timestamp())).scalar_one())
        if action.rollback_requested_at is not None:
            now = max(now, action.rollback_requested_at + timedelta(microseconds=1))
        action.rollback_requested_by = actor.user_id
        action.rollback_requested_at = now
        append_activity(
            db,
            username=actor.username,
            ip=ip,
            action="response.rollback_requested",
            target=f"response_action:{action.id}",
            details={"level": action.level},
        )
        db.flush()
        db.refresh(action)
    return action


def pending_manual_rollbacks(db: Session, batch_size: int) -> list[tuple[UUID, UUID, datetime]]:
    """Find intents not refused for their current request timestamp."""
    if batch_size < 1:
        raise ValueError("A positive batch size is required")
    token = sql_cast(
        sql_cast(
            func.extract("epoch", ResponseAction.rollback_requested_at) * 1_000_000, BigInteger
        ),
        Text,
    )
    refused = (
        select(CaseActivity.id)
        .where(
            CaseActivity.action == "response.manual_rollback_refused",
            CaseActivity.target
            == func.concat("response_action:", sql_cast(ResponseAction.id, Text)),
            CaseActivity.details["request_token"].astext == token,
        )
        .exists()
    )
    rows = db.execute(
        select(
            ResponseAction.id,
            ResponseAction.rollback_requested_by,
            ResponseAction.rollback_requested_at,
        )
        .where(
            ResponseAction.status == "executed",
            ResponseAction.rollback_requested_by.is_not(None),
            ResponseAction.rollback_requested_at.is_not(None),
            ~refused,
        )
        .order_by(ResponseAction.rollback_requested_at, ResponseAction.id)
        .limit(batch_size)
    ).all()
    return [
        (action, actor, at) for action, actor, at in rows if actor is not None and at is not None
    ]


def _refuse(db: Session, action: ResponseAction, actor_name: str, reason: str) -> ManualResult:
    if action.rollback_requested_at is None:
        return "noop"
    append_activity(
        db,
        username=actor_name,
        ip=None,
        action="response.manual_rollback_refused",
        target=f"response_action:{action.id}",
        details={"reason": reason, "request_token": _request_token(action.rollback_requested_at)},
    )
    db.flush()
    return "refused"


def perform_manual_rollback(
    db: Session,
    action_id: UUID,
    actor_id: UUID,
    requested_at: datetime,
    policy: Mapping[str, tuple[str, ...]],
) -> ManualResult:
    """Revalidate current intent, operator, action and safety before a simulated reverse."""
    configured = policy.get("response_rollback")
    if not configured:
        raise RuntimeError("Response authorization policy is unavailable")
    allowed = frozenset(configured) & _OPERATORS
    if requested_at.tzinfo is None:
        return "noop"
    preview = db.execute(
        select(
            ResponseAction.status,
            ResponseAction.rollback_requested_by,
            ResponseAction.rollback_requested_at,
        ).where(ResponseAction.id == action_id)
    ).one_or_none()
    if (
        preview is None
        or preview.status != "executed"
        or preview.rollback_requested_by != actor_id
        or preview.rollback_requested_at != requested_at
    ):
        return "noop"
    pair = db.execute(
        select(User, Role)
        .join(Role, User.role_id == Role.id)
        .where(User.id == actor_id)
        .with_for_update(of=User)
    ).one_or_none()
    safety = lock_safety_snapshot(db)
    action = db.execute(
        select(ResponseAction).where(ResponseAction.id == action_id).with_for_update()
    ).scalar_one_or_none()
    if (
        action is None
        or action.status != "executed"
        or action.rollback_requested_by != actor_id
        or action.rollback_requested_at != requested_at
        or _refusal_exists(db, action_id, requested_at)
    ):
        return "noop"
    actor_name = pair[0].username if pair is not None else "service:response-rollback"
    if pair is None or not pair[0].is_active or pair[1].name not in allowed:
        return _refuse(db, action, actor_name, "ineligible_operator")
    reverse = _safe_reverse(action, safety)
    if reverse is None:
        return _refuse(db, action, actor_name, "safeguard_or_invalid_action")
    try:
        CONNECTORS[reverse.connector].execute(
            db,
            action,
            phase="rollback",
            initiator=f"user:{actor_id}",
            automated=False,
            safety=safety,
        )
    except ConnectorRefused:
        return _refuse(db, action, actor_name, "connector_refused")
    transition(db, action, "rolled_back", username=actor_name, ip=None)
    return "rolled_back"
