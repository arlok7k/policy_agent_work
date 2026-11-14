"""The response lifecycle and transactional Four-Eyes approval gate."""

from collections.abc import Mapping, Sequence
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.exceptions import BadRequest, Conflict, Forbidden, NotFound
from app.response.models import ResponseAction, ResponseApproval

Decision = Literal["approved", "rejected"]
PeerIP = IPv4Address | IPv6Address

_TRANSITIONS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "requested": frozenset({"advised", "pending_approval", "approved"}),
        "pending_approval": frozenset({"approved", "rejected", "expired"}),
        "approved": frozenset({"executing", "failed", "expired"}),
        "executing": frozenset({"executed", "failed"}),
        "executed": frozenset({"rolled_back"}),
        "advised": frozenset(),
        "failed": frozenset(),
        "rejected": frozenset(),
        "rolled_back": frozenset(),
        "expired": frozenset(),
    }
)
_INITIAL = MappingProxyType(
    {"advisory": "advised", "automatic": "approved", "manual": "pending_approval"}
)


def transition_allowed(current: str, destination: str, mode: str, level: int) -> bool:
    """Check a lifecycle edge, including the mode-specific initial transition."""
    if mode not in _INITIAL or destination not in _TRANSITIONS.get(current, frozenset()):
        return False
    if level not in (0, 1, 2, 3):
        return False
    if (level == 0) != (mode == "advisory"):
        return False
    if level == 1 and mode != "automatic":
        return False
    if level == 3 and mode != "manual":
        return False
    if current == "requested" and destination != _INITIAL[mode]:
        return False
    if current == "pending_approval" and mode != "manual":
        return False
    if level == 0 and destination != "advised":
        return False
    return True


def transition(
    db: Session,
    action: ResponseAction,
    destination: str,
    *,
    username: str,
    ip: PeerIP | None,
) -> None:
    """Apply one checked edge and append its activity in the same transaction."""
    previous = action.status
    if not transition_allowed(previous, destination, action.approval_mode, action.level):
        raise Conflict()
    action.status = destination
    append_activity(
        db,
        username=username,
        ip=ip,
        action="response.transition",
        target=f"response_action:{action.id}",
        details={"from": previous, "to": destination, "level": action.level},
    )
    db.flush()


def _decision_reason(reason: str | None, maximum: int) -> str | None:
    if maximum <= 0:
        raise ValueError("A positive reason limit is required")
    if reason is None:
        return None
    value = reason.strip()
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise BadRequest() from None
    if not value or len(value) > maximum or "\x00" in value:
        raise BadRequest()
    return value


def decide_action(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    session_token: str,
    allowed_roles: Sequence[str],
    action_id: UUID,
    decision: Decision,
    reason: str | None,
    maximum_reason_chars: int,
    ip: PeerIP,
) -> ResponseAction:
    """Make exactly one serialized human decision; execution is never done here."""
    if decision not in {"approved", "rejected"}:
        raise BadRequest()
    safe_reason = _decision_reason(reason, maximum_reason_chars)
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, session_token, identity, allowed_roles)
        action = db.execute(
            select(ResponseAction).where(ResponseAction.id == action_id).with_for_update()
        ).scalar_one_or_none()
        if action is None:
            raise NotFound()
        if action.approval_mode != "manual" or action.status != "pending_approval":
            raise Conflict()
        if decision == "approved" and action.requested_by == actor.user_id:
            raise Forbidden()
        db.add(
            ResponseApproval(
                action_id=action.id,
                approver_id=actor.user_id,
                decision=decision,
                reason=safe_reason,
            )
        )
        # The database trigger requires the immutable decision to exist before
        # an action enters approved or rejected state.
        db.flush()
        action.decided_by = actor.user_id
        transition(db, action, decision, username=actor.username, ip=ip)
    return action
