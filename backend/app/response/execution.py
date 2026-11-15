"""Transactional Celery-only execution of previously approved response actions."""

from collections.abc import Mapping
from datetime import timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.connectors.base import ConnectorRefused
from app.connectors.registry import CONNECTORS
from app.core.activity import append_activity
from app.core.pb3_config import PB3Settings
from app.response.catalog import CATALOG
from app.response.gate import transition
from app.response.models import ResponseAction, ResponseApproval
from app.response.rules import lock_safety_snapshot
from app.response.safeguards import SafeguardAction, check_safeguards
from app.users.models import Role, User

ExecutionResult = Literal["executed", "paused", "failed", "noop"]
_ALLOWED_REQUESTERS = frozenset({"analyst", "senior_analyst", "admin"})
_ALLOWED_APPROVERS = frozenset({"senior_analyst", "admin"})


def _policy_roles(policy: Mapping[str, tuple[str, ...]], key: str) -> frozenset[str]:
    roles = policy.get(key)
    if not roles:
        # A broken configuration is not an eligibility decision: roll back and retry later.
        raise RuntimeError("Response authorization policy is unavailable")
    return frozenset(roles)


def _refuse(db: Session, action: ResponseAction, username: str, reason: str) -> ExecutionResult:
    append_activity(
        db,
        username=username,
        ip=None,
        action="response.execution_refused",
        target=f"response_action:{action.id}",
        details={"reason": reason},
    )
    transition(db, action, "failed", username=username, ip=None)
    return "failed"


def execute_approved(
    db: Session, action_id: UUID, policy: Mapping[str, tuple[str, ...]], response: PB3Settings
) -> ExecutionResult:
    """Execute once, within the caller's open transaction; never invoke from HTTP.

    Lock users in UUID order, then safety facts, then the action. The preview is
    not trusted; state and actor identifiers are checked again under row locks.
    """
    request_roles = _policy_roles(policy, "response_request") & _ALLOWED_REQUESTERS
    decision_roles = _policy_roles(policy, "response_decide") & _ALLOWED_APPROVERS
    preview = db.execute(
        select(
            ResponseAction.status,
            ResponseAction.requested_by,
            ResponseAction.decided_by,
            ResponseAction.approval_mode,
        ).where(ResponseAction.id == action_id)
    ).one_or_none()
    if preview is None or preview.status != "approved":
        return "noop"
    user_ids = {preview.requested_by}
    if preview.decided_by is not None:
        user_ids.add(preview.decided_by)
    locked = {
        user.id: (user, role)
        for user, role in db.execute(
            select(User, Role)
            .join(Role, User.role_id == Role.id)
            .where(User.id.in_(sorted(user_ids)))
            .order_by(User.id)
            .with_for_update(of=User)
        ).all()
    }
    safety = lock_safety_snapshot(db)
    action = db.execute(
        select(ResponseAction).where(ResponseAction.id == action_id).with_for_update()
    ).scalar_one_or_none()
    if action is None or action.status != "approved":
        return "noop"
    if (
        action.requested_by != preview.requested_by
        or action.decided_by != preview.decided_by
        or action.approval_mode != preview.approval_mode
    ):
        return "noop"
    automated = action.approval_mode == "automatic"
    actor_id = action.requested_by if automated else action.decided_by
    pair = locked.get(actor_id) if actor_id is not None else None
    username = pair[0].username if pair is not None else "service:response-execution"
    if automated:
        eligible = pair is not None and pair[0].is_active and pair[1].name in request_roles
    else:
        approval = db.execute(
            select(ResponseApproval.id).where(
                ResponseApproval.action_id == action.id,
                ResponseApproval.approver_id == action.decided_by,
                ResponseApproval.decision == "approved",
            )
        ).scalar_one_or_none()
        eligible = (
            action.approval_mode == "manual"
            and actor_id is not None
            and actor_id != action.requested_by
            and pair is not None
            and pair[0].is_active
            and pair[1].name in decision_roles
            and approval is not None
        )
    if not eligible:
        return _refuse(db, action, username, "ineligible_actor_or_approval")
    definition = CATALOG.get(action.action_type)
    if (
        definition is None
        or not definition.requestable
        or definition.level != action.level
        or action.approval_mode not in definition.modes
        or definition.connector not in CONNECTORS
        or (
            action.level == 2
            and (
                action.ttl_seconds is None
                or not 1 <= action.ttl_seconds <= response.l2_ttl_max_seconds
            )
        )
    ):
        return _refuse(db, action, username, "invalid_action")
    result = check_safeguards(
        SafeguardAction(action.action_type, action.target, action.params, safety.rules, "execute")
    )
    if not result.ok:
        return _refuse(db, action, username, "safeguard")
    if automated and safety.kill_switch_engaged:
        return "paused"
    transition(db, action, "executing", username=username, ip=None)
    connector = CONNECTORS[definition.connector]
    try:
        command = connector.execute(
            db,
            action,
            phase="execute",
            initiator=f"user:{actor_id}",
            automated=automated,
            safety=safety,
        )
    except ConnectorRefused:
        return _refuse(db, action, username, "connector_refused")
    # Some callers enable autoflush: sample and set the timestamp before the
    # append-only command can be inserted, never UPDATE the audit record.
    with db.no_autoflush:
        completed_at = db.execute(select(func.clock_timestamp())).scalar_one()
        command.executed_at = completed_at
    db.flush()
    if action.level == 2:
        ttl_seconds = action.ttl_seconds
        if ttl_seconds is None or ttl_seconds <= 0:
            raise RuntimeError("Invalid response TTL")
        action.ttl_expires_at = completed_at + timedelta(seconds=ttl_seconds)
    transition(db, action, "executed", username=username, ip=None)
    return "executed"


def approved_for_reconciliation(db: Session, batch_size: int) -> list[UUID]:
    """Bound the scan, while an engaged switch cannot starve manual approvals."""
    if batch_size < 1:
        raise ValueError("A positive batch size is required")
    safety = lock_safety_snapshot(db)
    query = select(ResponseAction.id).where(ResponseAction.status == "approved")
    if safety.kill_switch_engaged:
        query = query.where(ResponseAction.approval_mode == "manual")
    return list(
        db.execute(query.order_by(ResponseAction.created_at, ResponseAction.id).limit(batch_size))
        .scalars()
        .all()
    )
