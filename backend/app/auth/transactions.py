"""Transactional revalidation for security-relevant user operations."""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.roles import require_roles
from app.auth.session import SessionIdentity, identity_from_rows, session_rows
from app.core.config import Settings
from app.core.exceptions import Unauthenticated
from app.users.models import User


def lock_authorized_actor(
    db: Session,
    settings: Settings,
    token: str,
    identity: SessionIdentity,
    allowed_roles: Sequence[str],
    *,
    other_user_ids: Sequence[UUID] = (),
) -> tuple[SessionIdentity, dict[UUID, User]]:
    """Lock users in UUID order, then recheck the session and actual DB role."""
    ids = sorted({identity.user_id, *other_user_ids})
    users = (
        db.execute(select(User).where(User.id.in_(ids)).order_by(User.id).with_for_update())
        .scalars()
        .all()
    )
    locked = {user.id: user for user in users}
    rows = session_rows(db, settings, token, lock=True)
    if rows is None or rows[0].id != identity.session_id or rows[1].id != identity.user_id:
        raise Unauthenticated()
    actual = identity_from_rows(rows)
    require_roles(*allowed_roles)(actual)
    return actual, locked
