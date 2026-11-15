"""Load a transactionally serialized safety snapshot for the pure evaluator."""

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.exceptions import Unavailable
from app.response.safeguards import SafeguardRule


@dataclass(frozen=True)
class SafetySnapshot:
    kill_switch_engaged: bool
    rules: tuple[SafeguardRule, ...]


def lock_safety_snapshot(db: Session) -> SafetySnapshot:
    """Hold the switch's share lock until commit, then read all safeguard facts.

    The switch update and all safeguard-rule writes take the conflicting lock.
    Callers must keep the transaction open through their simulated command and
    corresponding activity write so a committed toggle/rule cannot be missed.
    """
    row = db.execute(
        text("SELECT engaged FROM kill_switch_state WHERE id=1 FOR SHARE")
    ).one_or_none()
    if row is None:
        raise Unavailable()
    rows = db.execute(text("SELECT kind, value FROM response_safeguard_rule ORDER BY code")).all()
    return SafetySnapshot(
        bool(row.engaged), tuple(SafeguardRule(kind, value) for kind, value in rows)
    )
