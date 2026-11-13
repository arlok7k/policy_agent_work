"""Cookie-authenticated, administrator-owned API-key management API."""

import sys
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.key_schemas import KeyCreate, KeyIssued, KeyPage
from app.auth.key_service import create_key, list_keys, revoke_key
from app.auth.roles import operation_roles, require_operation
from app.auth.session import SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.http import page_size, request_peer_ip

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])
Database = Annotated[Session, Depends(get_db)]
KeyAdmin = Annotated[SessionIdentity, Depends(require_operation("api_keys"))]


@router.get("", response_model=KeyPage)
def keys_list(
    request: Request,
    response: Response,
    identity: KeyAdmin,
    db: Database,
    limit: Annotated[int | None, Query(gt=0)] = None,
    offset: Annotated[int, Query(ge=0, le=sys.maxsize)] = 0,
) -> KeyPage:
    settings: Settings = request.app.state.settings
    try:
        result = list_keys(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "api_keys"),
            page_size(settings, limit),
            offset,
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("", response_model=KeyIssued, status_code=status.HTTP_201_CREATED)
def keys_create(
    body: KeyCreate, request: Request, response: Response, identity: KeyAdmin, db: Database
) -> KeyIssued:
    settings: Settings = request.app.state.settings
    try:
        result = create_key(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "api_keys"),
            body,
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    response.headers["Cache-Control"] = "no-store"
    return result


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def keys_delete(request: Request, identity: KeyAdmin, db: Database, id: UUID) -> Response:
    settings: Settings = request.app.state.settings
    try:
        revoke_key(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "api_keys"),
            id,
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
