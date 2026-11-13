"""Administrative user API protected by the legacy role policy."""

import sys
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.roles import operation_roles, require_operation
from app.auth.session import SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import Conflict, Unavailable
from app.core.http import page_size, request_peer_ip
from app.core.security import PasswordService
from app.users.schemas import UserCreate, UserPage, UserPatch, UserView
from app.users.service import create_user, list_users, update_user

router = APIRouter(prefix="/api/users", tags=["users"])
Database = Annotated[Session, Depends(get_db)]
UserAdmin = Annotated[SessionIdentity, Depends(require_operation("users"))]


def _username_conflict(error: IntegrityError) -> bool:
    original = error.orig
    diag = getattr(original, "diag", None)
    return (
        getattr(original, "sqlstate", None) == "23505"
        and getattr(diag, "constraint_name", None) == "users_username_key"
    )


@router.get("", response_model=UserPage)
def users_list(
    request: Request,
    response: Response,
    identity: UserAdmin,
    db: Database,
    limit: Annotated[int | None, Query(gt=0)] = None,
    offset: Annotated[int, Query(ge=0, le=sys.maxsize)] = 0,
) -> UserPage:
    settings: Settings = request.app.state.settings
    try:
        result = list_users(
            db,
            settings,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "users"),
            page_size(settings, limit),
            offset,
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("", response_model=UserView, status_code=status.HTTP_201_CREATED)
def users_create(
    body: UserCreate, request: Request, response: Response, identity: UserAdmin, db: Database
) -> UserView:
    settings: Settings = request.app.state.settings
    passwords: PasswordService = request.app.state.passwords
    try:
        result = create_user(
            db,
            settings,
            passwords,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "users"),
            body,
            request_peer_ip(request),
        )
    except IntegrityError as error:
        if _username_conflict(error):
            raise Conflict() from None
        raise Unavailable() from None
    except SQLAlchemyError:
        raise Unavailable() from None
    response.headers["Cache-Control"] = "no-store"
    return result


@router.patch("", response_model=UserView)
def users_update(
    body: UserPatch, request: Request, response: Response, identity: UserAdmin, db: Database
) -> UserView:
    settings: Settings = request.app.state.settings
    passwords: PasswordService = request.app.state.passwords
    try:
        result = update_user(
            db,
            settings,
            passwords,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "users"),
            body,
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    response.headers["Cache-Control"] = "no-store"
    return result
