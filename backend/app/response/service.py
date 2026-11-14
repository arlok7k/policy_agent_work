"""Authorized action requests, idempotency and shared-tenant action listing."""

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.exceptions import BadRequest, Conflict, Forbidden, NotFound, SemanticError
from app.core.http import PeerIP
from app.core.pagination import decode_cursor, encode_cursor
from app.core.pb2_config import PB2Settings
from app.core.pb3_config import PB3Settings
from app.incidents.models import Incident
from app.response.catalog import CATALOG
from app.response.gate import transition
from app.response.manual_rollback import manual_request_status
from app.response.models import ResponseAction
from app.response.rules import lock_safety_snapshot
from app.response.safeguards import SafeguardAction, check_safeguards
from app.response.schemas import ActionPage, ActionRequest, ActionView

_REQUESTERS = frozenset({"analyst", "senior_analyst", "admin"})
_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)


def idempotency_digests(key: str | None, body: ActionRequest) -> tuple[bytes | None, bytes | None]:
    if key is None:
        return None, None
    if _KEY_PATTERN.fullmatch(key) is None:
        raise BadRequest()
    try:
        canonical = json.dumps(
            body.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except TypeError, ValueError, UnicodeError:
        raise BadRequest() from None
    return hashlib.sha256(key.encode("ascii")).digest(), hashlib.sha256(canonical).digest()


def _bounded_input(target: dict[str, Any], params: dict[str, Any], maximum: int) -> None:
    """Bound all strings and structure before catalog validation or persistence."""
    stack: list[object] = [target, params]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > 256:
            raise SemanticError()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise BadRequest() from None
            if len(item) > maximum or "\x00" in item:
                raise SemanticError()
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def action_view(db: Session, action: ResponseAction) -> ActionView:
    view = ActionView.model_validate(action)
    return view.model_copy(update={"rollback_request_status": manual_request_status(db, action)})


def request_action(
    db: Session,
    settings: Settings,
    pb2: PB2Settings,
    pb3: PB3Settings,
    identity: SessionIdentity,
    session_token: str,
    roles: Sequence[str],
    body: ActionRequest,
    key: str | None,
    ip: PeerIP,
) -> tuple[ActionView, bool]:
    key_digest, request_digest = idempotency_digests(key, body)
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, session_token, identity, roles)
        if actor.role not in _REQUESTERS:
            raise Forbidden()
        if key_digest is not None:
            existing = db.execute(
                select(ResponseAction).where(
                    ResponseAction.requested_by == actor.user_id,
                    ResponseAction.idempotency_key_digest == key_digest,
                )
            ).scalar_one_or_none()
            if existing is not None:
                if existing.idempotency_request_digest != request_digest:
                    raise Conflict()
                return action_view(db, existing), False
        _bounded_input(body.target, body.params, pb2.incident_max_text_chars)
        definition = CATALOG.get(body.action_type)
        if definition is None or not definition.requestable:
            raise SemanticError()
        mode = body.mode
        if mode is None:
            if len(definition.modes) != 1:
                raise SemanticError()
            mode = definition.modes[0]
        if mode not in definition.modes:
            raise SemanticError()
        if definition.level == 2:
            ttl = pb3.l2_ttl_default_seconds if body.ttl_seconds is None else body.ttl_seconds
            if not 1 <= ttl <= pb3.l2_ttl_max_seconds:
                raise SemanticError()
        else:
            if body.ttl_seconds is not None:
                raise SemanticError()
            ttl = None
        if (
            db.execute(
                select(Incident.id).where(Incident.id == body.incident_id)
            ).scalar_one_or_none()
            is None
        ):
            raise NotFound()
        safety = lock_safety_snapshot(db)
        result = check_safeguards(
            SafeguardAction(body.action_type, body.target, body.params, safety.rules, "request")
        )
        if not result.ok:
            raise SemanticError()
        if mode == "automatic" and safety.kill_switch_engaged:
            raise Conflict()
        try:
            target, params = definition.validate_payload(body.target, body.params)
        except TypeError, ValueError:
            raise SemanticError() from None
        action = ResponseAction(
            incident_id=body.incident_id,
            action_type=definition.name,
            target=target,
            params=params,
            level=definition.level,
            approval_mode=mode,
            status="requested",
            requested_by=actor.user_id,
            ttl_seconds=ttl,
            idempotency_key_digest=key_digest,
            idempotency_request_digest=request_digest,
        )
        db.add(action)
        db.flush()
        append_activity(
            db,
            username=actor.username,
            ip=ip,
            action="response.requested",
            target=f"response_action:{action.id}",
            details={"level": action.level},
        )
        destination = {
            "advisory": "advised",
            "automatic": "approved",
            "manual": "pending_approval",
        }[mode]
        transition(db, action, destination, username=actor.username, ip=ip)
        db.refresh(action)
        return action_view(db, action), True


def list_actions(
    db: Session, *, size: int, cursor: str | None, incident_id: UUID | None
) -> ActionPage:
    query = select(ResponseAction)
    if incident_id is not None:
        query = query.where(ResponseAction.incident_id == incident_id)
    if cursor is not None:
        timestamp, identifier = decode_cursor(cursor)
        query = query.where(
            tuple_(ResponseAction.created_at, ResponseAction.id) < tuple_(timestamp, identifier)
        )
    actions = list(
        db.execute(
            query.order_by(ResponseAction.created_at.desc(), ResponseAction.id.desc()).limit(
                size + 1
            )
        )
        .scalars()
        .all()
    )
    page = actions[:size]
    next_cursor = encode_cursor(page[-1].created_at, page[-1].id) if len(actions) > size else None
    return ActionPage(items=[action_view(db, action) for action in page], next_cursor=next_cursor)
