"""Password reauthentication adapter for the future governance boundary."""

from datetime import timedelta
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.models import AuthSession
from app.users.models import User


class StepUpProvider(Protocol):
    def verify(
        self, db: Session, user_id: UUID, session_id: UUID, level: str, max_age_s: int
    ) -> bool: ...


class PasswordStepUpProvider:
    def verify(
        self, db: Session, user_id: UUID, session_id: UUID, level: str, max_age_s: int
    ) -> bool:
        if level != "password" or max_age_s <= 0:
            return False
        query = (
            select(AuthSession.id)
            .join(User, User.id == AuthSession.user_id)
            .where(
                AuthSession.id == session_id,
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > func.clock_timestamp(),
                AuthSession.reauth_at.is_not(None),
                AuthSession.reauth_at <= func.clock_timestamp(),
                AuthSession.reauth_at >= func.clock_timestamp() - timedelta(seconds=max_age_s),
                User.is_active.is_(True),
            )
        )
        return db.execute(query).scalar_one_or_none() is not None
