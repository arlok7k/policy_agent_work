"""Administrator-only, audited host presentation settings."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.roles import operation_roles, require_operation
from app.auth.session import SESSION_COOKIE, SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import Forbidden, SemanticError, Unavailable
from app.core.http import private_json, request_peer_ip
from app.settings.schemas import PresentationView, SettingsPatch, SettingsView

router = APIRouter(prefix="/api/settings", tags=["settings"])
presentation_router = APIRouter(tags=["presentation"])
Database = Annotated[Session, Depends(get_db)]
SettingsAdmin = Annotated[SessionIdentity, Depends(require_operation("settings"))]
PresentationReader = Annotated[SessionIdentity, Depends(require_operation("presentation_read"))]


def _view(row: object) -> SettingsView:
    return SettingsView.model_validate(row, from_attributes=True)


@presentation_router.get("/api/presentation", response_model=PresentationView)
def read_presentation(
    response: Response, identity: PresentationReader, db: Database
) -> PresentationView:
    try:
        row = db.execute(
            text("SELECT display_name, default_direction FROM host_settings WHERE id=1")
        ).one_or_none()
        if row is None:
            raise Unavailable()
        result = PresentationView.model_validate(row, from_attributes=True)
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.get("", response_model=SettingsView)
def read_settings(response: Response, identity: SettingsAdmin, db: Database) -> SettingsView:
    if identity.role != "admin":
        raise Forbidden()
    try:
        row = db.execute(
            text("SELECT display_name, default_direction, updated_at FROM host_settings WHERE id=1")
        ).one_or_none()
        if row is None:
            raise Unavailable()
        result = _view(row)
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.patch("", response_model=SettingsView)
def change_settings(
    body: SettingsPatch,
    request: Request,
    response: Response,
    identity: SettingsAdmin,
    db: Database,
) -> SettingsView:
    settings: Settings = request.app.state.settings
    name = body.display_name
    if name is not None:
        name = name.strip()
        if not name or len(name) > settings.username_max_chars or not name.isprintable():
            raise SemanticError()
    try:
        with db.begin():
            actor, _ = lock_authorized_actor(
                db,
                settings,
                request.cookies.get(SESSION_COOKIE, ""),
                identity,
                operation_roles(request, "settings"),
            )
            if actor.role != "admin":
                raise Forbidden()
            before = db.execute(
                text(
                    "SELECT display_name, default_direction, updated_at "
                    "FROM host_settings WHERE id=1 FOR UPDATE"
                )
            ).one_or_none()
            if before is None:
                raise Unavailable()
            after = db.execute(
                text(
                    "UPDATE host_settings SET display_name=:name, default_direction=:direction, "
                    "updated_at=clock_timestamp() WHERE id=1 "
                    "RETURNING display_name, default_direction, updated_at"
                ),
                {
                    "name": name if name is not None else before.display_name,
                    "direction": body.default_direction or before.default_direction,
                },
            ).one()
            append_activity(
                db,
                username=actor.username,
                ip=request_peer_ip(request),
                action="settings.update",
                target="host_settings:1",
                details={
                    "fields": sorted(body.model_fields_set),
                    "before": {
                        "display_name": before.display_name,
                        "default_direction": before.default_direction,
                    },
                    "after": {
                        "display_name": after.display_name,
                        "default_direction": after.default_direction,
                    },
                },
            )
            db.flush()
            result = _view(after)
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result
