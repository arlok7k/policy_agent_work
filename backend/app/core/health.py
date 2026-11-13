"""Public database readiness without operational details or credentials."""

from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.exceptions import Unavailable

router = APIRouter(tags=["health"])


class HealthStatus(BaseModel):
    status: Literal["ok"]


@router.get("/api/health", response_model=HealthStatus)
def health(request: Request, response: Response) -> HealthStatus:
    factory: sessionmaker[Session] = request.app.state.session_factory
    try:
        with factory() as db:
            db.execute(text("SELECT 1")).scalar_one()
    except SQLAlchemyError:
        raise Unavailable() from None
    response.headers["Cache-Control"] = "no-store"
    return HealthStatus(status="ok")
