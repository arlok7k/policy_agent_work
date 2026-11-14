"""The pure safeguard entry freezes required safety semantics and refusals."""

import socket
from copy import deepcopy
from ipaddress import IPv4Address

import pytest

from app.response.safeguards import Phase, SafeguardAction, SafeguardRule, check_safeguards


def _action(
    kind: str = "firewall_drop",
    *,
    agent: str = "004",
    ip: str = "8.8.8.8",
    rules: tuple[SafeguardRule, ...] = (),
    phase: Phase = "request",
) -> SafeguardAction:
    return SafeguardAction(kind, {"agent_id": agent, "ip": ip}, {}, rules, phase)


@pytest.mark.parametrize("agent", ["000", "0", "000000", "00"])
def test_every_zero_spelling_of_agent_000_is_refused(agent: str) -> None:
    for kind in ("firewall_drop", "firewall_allow", "isolate_host", "permanent_block"):
        result = check_safeguards(_action(kind, agent=agent))
        assert result.ok is False and result.reason == "protected_agent"
    result = check_safeguards(_action("release_host", agent=agent, phase="rollback"))
    assert result.ok is False and result.reason == "protected_agent"


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.2.1",
        "127.0.0.1",
        "169.254.1.9",
        str(IPv4Address(0)),
        "224.0.0.1",
        "::",
        "::1",
        "fe80::1",
        "fd00::1",
        "ff02::1",
        "::ffff:10.0.0.5",
        "::ffff:127.0.0.1",
        "::ffff:169.254.9.1",
    ],
)
def test_blocking_and_isolation_refuse_protected_addresses(address: str) -> None:
    for kind in ("firewall_drop", "isolate_host", "permanent_block"):
        result = check_safeguards(_action(kind, ip=address))
        assert result.ok is False and result.reason == "protected_ip"
    # A standalone allow would later auto-reverse to a forbidden drop.
    assert check_safeguards(_action("firewall_allow", ip=address)).reason == "protected_ip"
    # A rollback that only unblocks or releases is not itself a new block.
    assert check_safeguards(_action("firewall_allow", ip=address, phase="rollback")).ok
    assert check_safeguards(_action("release_host", ip=address, phase="rollback")).ok


@pytest.mark.parametrize("address", ["8.8.8.8", "172.15.1.1", "172.32.1.1", "2001:4860:4860::8888"])
def test_public_or_outside_rfc1918_ranges_are_allowed(address: str) -> None:
    assert check_safeguards(_action(ip=address)).ok


@pytest.mark.parametrize("value", ["; rm -rf", "a|b", "$(id)", "`id`", "x\ny", "x\\y", "x＞y"])
def test_metacharacters_are_rejected_in_target_params_and_keys(value: str) -> None:
    for target, params in (
        ({"value": value}, {"message": "notice"}),
        ({"value": "operator"}, {"message": value}),
        ({"value": "operator"}, {value: "notice"}),
    ):
        result = check_safeguards(SafeguardAction("notify", target, params))
        assert result.ok is False and result.reason == "shell"


def test_additive_rules_apply_without_mutating_the_action() -> None:
    target = {"agent_id": "005", "ip": "8.8.8.8"}
    params: dict[str, object] = {}
    before = deepcopy((target, params))
    allowed = SafeguardAction("firewall_drop", target, params)
    assert check_safeguards(allowed).ok
    protected_agent = SafeguardAction(
        "firewall_drop", target, params, (SafeguardRule("agent", "005"),)
    )
    assert check_safeguards(protected_agent).reason == "protected_agent"
    protected_network = SafeguardAction(
        "firewall_drop", target, params, (SafeguardRule("network", "8.8.8.0/24"),)
    )
    assert check_safeguards(protected_network).reason == "protected_ip"
    mapped_rule = (SafeguardRule("network", "::ffff:8.8.8.0/120"),)
    assert check_safeguards(_action(ip="8.8.8.8", rules=mapped_rule)).reason == "protected_ip"
    assert (
        check_safeguards(_action(ip="::ffff:8.8.8.8", rules=mapped_rule)).reason == "protected_ip"
    )
    assert (target, params) == before


@pytest.mark.parametrize(
    "rule",
    [
        SafeguardRule("agent", "bad"),
        SafeguardRule("network", "not-cidr"),
        SafeguardRule("shell", "disabled"),
        SafeguardRule("unknown", "x"),
    ],
)
def test_invalid_extra_rules_fail_closed(rule: SafeguardRule) -> None:
    assert check_safeguards(_action(rules=(rule,))).reason == "invalid_rule"


def test_unknown_actions_malformed_targets_and_nonrequestable_reverse_fail_closed() -> None:
    assert check_safeguards(_action("unknown")).reason == "unknown_action"
    assert check_safeguards(_action("release_host")).reason == "unknown_action"
    assert check_safeguards(_action(agent="not-numeric")).reason == "invalid_payload"
    assert check_safeguards(_action(ip="not-an-ip")).reason == "invalid_payload"
    assert (
        check_safeguards(SafeguardAction("firewall_drop", {"agent_id": "004"}, {})).reason
        == "invalid_payload"
    )
    assert (
        check_safeguards(
            SafeguardAction(
                "firewall_drop", {"agent_id": "004", "ip": "8.8.8.8"}, {"command": "unexpected"}
            )
        ).reason
        == "invalid_payload"
    )


def test_safeguard_evaluation_performs_no_file_or_socket_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Pure safeguards must not perform I/O")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    result = check_safeguards(_action())
    assert result.ok is True and result.reason is None
