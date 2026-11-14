"""Connector contract with structured, simulation-only command recording."""

from abc import ABC, abstractmethod
from typing import Literal

from sqlalchemy.orm import Session

from app.jobs.celery_app import require_initiator
from app.response.catalog import CATALOG, ActionDefinition, ConnectorName
from app.response.models import ExecutedCommand, ResponseAction
from app.response.rules import SafetySnapshot
from app.response.safeguards import SafeguardAction, check_safeguards

CommandPhase = Literal["execute", "rollback"]


class ConnectorRefused(Exception):
    """The invocation does not match the catalog, state, or human attribution."""


class SafeguardRefused(ConnectorRefused):
    """The current structured target fails the pure safeguard evaluator."""


class AutomationHalted(ConnectorRefused):
    """The fresh safety snapshot prevents automated work."""


class Connector(ABC):
    """Append one structured simulated command to the caller's transaction.

    The caller must obtain and retain the safety snapshot lock, lock and
    revalidate the action/actors, and flush/commit together with the transition
    and activity. This method opens no connections and never runs a shell.
    """

    @property
    @abstractmethod
    def name(self) -> ConnectorName:
        """The catalog connector identity."""

    @abstractmethod
    def _command_name(self, definition: ActionDefinition) -> str:
        """Return a fixed simulated command name, never a shell expression."""

    def execute(
        self,
        db: Session,
        action: ResponseAction,
        *,
        phase: CommandPhase,
        initiator: str,
        automated: bool,
        safety: SafetySnapshot,
    ) -> ExecutedCommand:
        require_initiator({"initiator": initiator})
        original = CATALOG.get(action.action_type)
        if (
            original is None
            or original.level != action.level
            or action.approval_mode not in original.modes
        ):
            raise ConnectorRefused()
        if phase == "execute":
            if action.status != "executing" or automated != (action.approval_mode == "automatic"):
                raise ConnectorRefused()
            actor = action.requested_by if automated else action.decided_by
            if actor is None or (not automated and actor == action.requested_by):
                raise ConnectorRefused()
            if initiator != f"user:{actor}":
                raise ConnectorRefused()
            selected = original
        elif phase == "rollback":
            if (
                action.status != "executed"
                or not original.reversible
                or original.reverse_action is None
            ):
                raise ConnectorRefused()
            if automated:
                if not initiator.startswith("service:"):
                    raise ConnectorRefused()
            elif (
                action.rollback_requested_by is None
                or initiator != f"user:{action.rollback_requested_by}"
            ):
                raise ConnectorRefused()
            reverse = CATALOG.get(original.reverse_action)
            if reverse is None:
                raise ConnectorRefused()
            selected = reverse
        else:
            raise ConnectorRefused()
        if safety.kill_switch_engaged and automated:
            raise AutomationHalted()
        if selected.connector != self.name:
            raise ConnectorRefused()
        evaluated = check_safeguards(
            SafeguardAction(
                selected.name,
                action.target,
                action.params,
                safety.rules,
                "execute" if phase == "execute" else "rollback",
            )
        )
        if not evaluated.ok:
            raise SafeguardRefused()
        target, params = selected.validate_payload(action.target, action.params)
        record = ExecutedCommand(
            action_id=action.id,
            phase=phase,
            connector=self.name,
            command=self._command_name(selected),
            target=target,
            params=params,
            initiator=initiator,
            simulated=True,
        )
        db.add(record)
        return record
