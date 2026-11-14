"""Legacy-role-protected response catalog, actions, decisions and switch."""

from typing import Annotated
from uuid import UUID

from celery import Celery
from fastapi import APIRouter, Depends, Query, Request, Response, status
from kombu.exceptions import KombuError
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.roles import operation_roles, require_operation
from app.auth.session import SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import BadRequest, Unavailable
from app.core.http import page_size, private_json, request_peer_ip
from app.core.logging import logger
from app.core.pb2_config import PB2Settings
from app.core.pb3_config import PB3Settings
from app.jobs.celery_app import EXECUTE_RESPONSE_TASK, MANUAL_ROLLBACK_TASK
from app.response.catalog import CatalogPage, catalog_page
from app.response.gate import Decision, decide_action
from app.response.manual_rollback import request_manual_rollback
from app.response.schemas import (
    ActionPage,
    ActionRequest,
    ActionView,
    DecisionRequest,
    RollbackRequest,
)
from app.response.service import action_view, list_actions, request_action
from app.response.switch import KillSwitchChange, KillSwitchView, set_kill_switch

router = APIRouter(prefix="/api/response", tags=["response"])
ResponseReader = Annotated[SessionIdentity, Depends(require_operation("response_read"))]
ResponseRequester = Annotated[SessionIdentity, Depends(require_operation("response_request"))]
ResponseDecider = Annotated[SessionIdentity, Depends(require_operation("response_decide"))]
RollbackOperator = Annotated[SessionIdentity, Depends(require_operation("response_rollback"))]
SwitchOperator = Annotated[SessionIdentity, Depends(require_operation("response_kill_switch"))]
Database = Annotated[Session, Depends(get_db)]


def _dispatch(celery: Celery, name: str, args: list[str], actor: UUID) -> None:
    """Best-effort post-commit publication; Beat recovers durable DB intent."""
    try:
        celery.send_task(
            name,
            args=args,
            headers={"initiator": f"user:{actor}"},
            queue="default",
            retry=False,
            argsrepr="<redacted>",
            kwargsrepr="<redacted>",
        )
    except KombuError, RedisError, OSError:
        logger.warning('{"component":"response_dispatch","outcome":"deferred"}')


@router.get("/catalog", response_model=CatalogPage)
def catalog(response: Response, identity: ResponseReader) -> CatalogPage:
    private_json(response)
    return catalog_page()


@router.get("/actions", response_model=ActionPage)
def actions(
    request: Request,
    response: Response,
    identity: ResponseReader,
    db: Database,
    limit: Annotated[int | None, Query(gt=0)] = None,
    cursor: str | None = None,
    incident_id: UUID | None = None,
) -> ActionPage:
    settings: Settings = request.app.state.settings
    try:
        result = list_actions(
            db, size=page_size(settings, limit), cursor=cursor, incident_id=incident_id
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.post(
    "/actions",
    response_model=ActionView,
    status_code=status.HTTP_201_CREATED,
    responses={status.HTTP_200_OK: {"model": ActionView, "description": "Idempotent replay"}},
    openapi_extra={
        "parameters": [
            {
                "name": "Idempotency-Key",
                "in": "header",
                "required": False,
                "schema": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
                },
                "description": "Optional, scoped to the current requester; never returned.",
            }
        ]
    },
)
def create_action(
    body: ActionRequest,
    request: Request,
    response: Response,
    identity: ResponseRequester,
    db: Database,
) -> ActionView:
    keys = request.headers.getlist("Idempotency-Key")
    if len(keys) > 1:
        raise BadRequest()
    settings: Settings = request.app.state.settings
    pb2: PB2Settings = request.app.state.pb2_settings
    pb3: PB3Settings = request.app.state.pb3_settings
    try:
        result, created = request_action(
            db,
            settings,
            pb2,
            pb3,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "response_request"),
            body,
            keys[0] if keys else None,
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    actor = result.requested_by if result.approval_mode == "automatic" else result.decided_by
    if result.status == "approved" and actor is not None:
        _dispatch(request.app.state.celery, EXECUTE_RESPONSE_TASK, [str(result.id)], actor)
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    private_json(response)
    return result


def _decision(
    action_id: UUID,
    body: DecisionRequest | None,
    request: Request,
    response: Response,
    identity: SessionIdentity,
    db: Session,
    decision: Decision,
) -> ActionView:
    settings: Settings = request.app.state.settings
    pb2: PB2Settings = request.app.state.pb2_settings
    try:
        action = decide_action(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "response_decide"),
            action_id,
            decision,
            body.reason if body is not None else None,
            pb2.incident_max_text_chars,
            request_peer_ip(request),
        )
        result = action_view(db, action)
    except SQLAlchemyError:
        raise Unavailable() from None
    if decision == "approved" and action.decided_by is not None:
        _dispatch(
            request.app.state.celery, EXECUTE_RESPONSE_TASK, [str(action.id)], action.decided_by
        )
    private_json(response)
    return result


@router.post("/actions/{action_id}/approve", response_model=ActionView)
def approve(
    action_id: UUID,
    request: Request,
    response: Response,
    identity: ResponseDecider,
    db: Database,
    body: DecisionRequest | None = None,
) -> ActionView:
    return _decision(action_id, body, request, response, identity, db, "approved")


@router.post("/actions/{action_id}/reject", response_model=ActionView)
def reject(
    action_id: UUID,
    request: Request,
    response: Response,
    identity: ResponseDecider,
    db: Database,
    body: DecisionRequest | None = None,
) -> ActionView:
    return _decision(action_id, body, request, response, identity, db, "rejected")


@router.post(
    "/actions/{action_id}/rollback", response_model=ActionView, status_code=status.HTTP_202_ACCEPTED
)
def rollback(
    action_id: UUID,
    request: Request,
    response: Response,
    identity: RollbackOperator,
    db: Database,
    body: RollbackRequest | None = None,
) -> ActionView:
    settings: Settings = request.app.state.settings
    try:
        action = request_manual_rollback(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "response_rollback"),
            action_id,
            request_peer_ip(request),
        )
        result = action_view(db, action)
    except SQLAlchemyError:
        raise Unavailable() from None
    if action.rollback_requested_by is not None and action.rollback_requested_at is not None:
        _dispatch(
            request.app.state.celery,
            MANUAL_ROLLBACK_TASK,
            [
                str(action.id),
                str(action.rollback_requested_by),
                action.rollback_requested_at.isoformat(),
            ],
            action.rollback_requested_by,
        )
    private_json(response)
    return result


@router.post("/kill-switch", response_model=KillSwitchView)
def kill_switch(
    body: KillSwitchChange,
    request: Request,
    response: Response,
    identity: SwitchOperator,
    db: Database,
) -> KillSwitchView:
    settings: Settings = request.app.state.settings
    try:
        result = set_kill_switch(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "response_kill_switch"),
            body.engaged,
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result
