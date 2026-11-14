"""Legacy-role-protected response catalog and action endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.roles import operation_roles, require_operation
from app.auth.session import SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import Unavailable
from app.core.http import private_json, request_peer_ip
from app.response.catalog import CatalogPage, catalog_page
from app.response.switch import KillSwitchChange, KillSwitchView, set_kill_switch

router = APIRouter(prefix="/api/response", tags=["response"])
ResponseReader = Annotated[SessionIdentity, Depends(require_operation("response_read"))]
SwitchOperator = Annotated[SessionIdentity, Depends(require_operation("response_kill_switch"))]
Database = Annotated[Session, Depends(get_db)]


@router.get("/catalog", response_model=CatalogPage)
def catalog(response: Response, identity: ResponseReader) -> CatalogPage:
    private_json(response)
    return catalog_page()


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
