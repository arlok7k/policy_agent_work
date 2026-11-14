"""Transactional, audited automation-only Kill Switch."""

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.exceptions import Forbidden, Unavailable
from app.core.http import PeerIP


class KillSwitchChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engaged: StrictBool


class KillSwitchView(BaseModel):
    engaged: bool
    changed_by: UUID
    changed_at: datetime


def set_kill_switch(
    db: Session,
    settings: Settings,
    identity: SessionIdentity,
    token: str,
    roles: Sequence[str],
    engaged: bool,
    ip: PeerIP,
) -> KillSwitchView:
    """Serialize and audit every authorized request, even an unchanged value."""
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, token, identity, roles)
        if actor.role not in {"senior_analyst", "admin"}:
            raise Forbidden()
        before = db.execute(
            text("SELECT engaged FROM kill_switch_state WHERE id=1 FOR UPDATE")
        ).scalar_one_or_none()
        if before is None:
            raise Unavailable()
        row = db.execute(
            text(
                "UPDATE kill_switch_state SET engaged=:engaged, changed_by=:actor, "
                "changed_at=clock_timestamp() WHERE id=1 RETURNING engaged, changed_by, changed_at"
            ),
            {"engaged": engaged, "actor": actor.user_id},
        ).one()
        append_activity(
            db,
            username=actor.username,
            ip=ip,
            action="response.kill_switch",
            target="response_kill_switch:1",
            details={"before": before, "after": engaged},
        )
        db.flush()
        return KillSwitchView(
            engaged=row.engaged, changed_by=row.changed_by, changed_at=row.changed_at
        )
