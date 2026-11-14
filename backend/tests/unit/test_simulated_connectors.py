"""Simulated connector calls cannot initiate a socket connection or shell command."""

import socket
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from app.connectors.base import AutomationHalted, ConnectorRefused, SafeguardRefused
from app.connectors.internal import InternalConnector
from app.connectors.simulated_wazuh import SimulatedWazuhConnector
from app.response.models import ExecutedCommand, ResponseAction
from app.response.rules import SafetySnapshot
from app.response.safeguards import SafeguardRule


class RecordingSession:
    def __init__(self) -> None:
        self.records: list[ExecutedCommand] = []

    def add(self, record: ExecutedCommand) -> None:
        self.records.append(record)


def _action(
    name: str,
    *,
    level: int,
    mode: str,
    requester: UUID,
    target: dict[str, Any],
    params: dict[str, Any],
    decided_by: UUID | None = None,
    status: str = "executing",
) -> ResponseAction:
    return ResponseAction(
        id=uuid4(),
        incident_id=uuid4(),
        action_type=name,
        target=target,
        params=params,
        level=level,
        approval_mode=mode,
        status=status,
        requested_by=requester,
        decided_by=decided_by,
        ttl_seconds=3600 if level == 2 else None,
    )


def test_both_connectors_make_no_socket_or_dns_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def blocked(*args: object, **kwargs: object) -> None:
        attempts.append("socket")
        raise AssertionError("Connector attempted network I/O")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    actor = uuid4()
    sink = RecordingSession()
    db = cast(Session, sink)
    safety = SafetySnapshot(False, ())
    internal = _action(
        "notify",
        level=1,
        mode="automatic",
        requester=actor,
        target={"value": "analysts"},
        params={"message": "Review alert"},
    )
    wazuh = _action(
        "firewall_drop",
        level=2,
        mode="automatic",
        requester=actor,
        target={"agent_id": "004", "ip": "8.8.8.8"},
        params={},
    )
    first = InternalConnector().execute(
        db, internal, phase="execute", initiator=f"user:{actor}", automated=True, safety=safety
    )
    second = SimulatedWazuhConnector().execute(
        db, wazuh, phase="execute", initiator=f"user:{actor}", automated=True, safety=safety
    )
    assert attempts == []
    assert sink.records == [first, second]
    assert first.command == "notify" and first.connector == "internal" and first.simulated
    assert (
        second.command == "firewall_drop"
        and second.connector == "simulated_wazuh"
        and second.simulated
    )


def test_unsafe_targets_injection_and_forged_attribution_are_refused() -> None:
    requester = uuid4()
    sink = RecordingSession()
    connector = SimulatedWazuhConnector()
    action = _action(
        "firewall_drop",
        level=2,
        mode="automatic",
        requester=requester,
        target={"agent_id": "000", "ip": "8.8.8.8"},
        params={},
    )
    db = cast(Session, sink)
    safety = SafetySnapshot(False, ())
    with pytest.raises(SafeguardRefused):
        connector.execute(
            db,
            action,
            phase="execute",
            initiator=f"user:{requester}",
            automated=True,
            safety=safety,
        )
    action.target = {"agent_id": "004", "ip": "10.0.0.5"}
    with pytest.raises(SafeguardRefused):
        connector.execute(
            db,
            action,
            phase="execute",
            initiator=f"user:{requester}",
            automated=True,
            safety=safety,
        )
    action.target = {"agent_id": "004", "ip": "8.8.8.8"}
    action.params = {"command": "; rm -rf"}
    with pytest.raises(SafeguardRefused):
        connector.execute(
            db,
            action,
            phase="execute",
            initiator=f"user:{requester}",
            automated=True,
            safety=safety,
        )
    action.params = {}
    with pytest.raises(ConnectorRefused):
        connector.execute(
            db, action, phase="execute", initiator=f"user:{uuid4()}", automated=True, safety=safety
        )
    extra = SafetySnapshot(False, (SafeguardRule("agent", "004"),))
    with pytest.raises(SafeguardRefused):
        connector.execute(
            db, action, phase="execute", initiator=f"user:{requester}", automated=True, safety=extra
        )
    assert sink.records == []


def test_kill_switch_blocks_automation_but_not_human_approved_or_manual_rollback() -> None:
    requester, approver = uuid4(), uuid4()
    sink = RecordingSession()
    db = cast(Session, sink)
    connector = SimulatedWazuhConnector()
    halted = SafetySnapshot(True, ())
    auto = _action(
        "firewall_drop",
        level=2,
        mode="automatic",
        requester=requester,
        target={"agent_id": "004", "ip": "8.8.8.8"},
        params={},
    )
    with pytest.raises(AutomationHalted):
        connector.execute(
            db, auto, phase="execute", initiator=f"user:{requester}", automated=True, safety=halted
        )
    manual = _action(
        "isolate_host",
        level=3,
        mode="manual",
        requester=requester,
        decided_by=approver,
        target={"agent_id": "004", "ip": "8.8.8.8"},
        params={},
    )
    command = connector.execute(
        db, manual, phase="execute", initiator=f"user:{approver}", automated=False, safety=halted
    )
    assert command.command == "isolate_host"
    auto.status = "executed"
    with pytest.raises(AutomationHalted):
        connector.execute(
            db, auto, phase="rollback", initiator="service:ttl-test", automated=True, safety=halted
        )
    auto.rollback_requested_by = approver
    command = connector.execute(
        db, auto, phase="rollback", initiator=f"user:{approver}", automated=False, safety=halted
    )
    assert command.command == "firewall_allow"
    assert len(sink.records) == 2


def test_permanent_block_has_only_fixed_simulated_drop_command() -> None:
    requester, approver = uuid4(), uuid4()
    sink = RecordingSession()
    action = _action(
        "permanent_block",
        level=3,
        mode="manual",
        requester=requester,
        decided_by=approver,
        target={"agent_id": "004", "ip": "8.8.8.8"},
        params={},
    )
    command = SimulatedWazuhConnector().execute(
        cast(Session, sink),
        action,
        phase="execute",
        initiator=f"user:{approver}",
        automated=False,
        safety=SafetySnapshot(False, ()),
    )
    assert command.command == "firewall_drop" and command.simulated is True
    action.status = "executed"
    action.rollback_requested_by = approver
    with pytest.raises(ConnectorRefused):
        SimulatedWazuhConnector().execute(
            cast(Session, sink),
            action,
            phase="rollback",
            initiator=f"user:{approver}",
            automated=False,
            safety=SafetySnapshot(False, ()),
        )
