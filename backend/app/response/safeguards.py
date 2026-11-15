"""Pure, fail-closed response safety facts and the single safeguard evaluator.

This module performs no database, network, clock, logging, or other I/O. Callers
supply an immutable snapshot of any additional rules for every evaluation.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from math import isfinite
from typing import Any, Literal
from unicodedata import category, normalize

from app.response.catalog import CATALOG

Reason = Literal[
    "unknown_action", "invalid_payload", "invalid_rule", "protected_agent", "protected_ip", "shell"
]
Phase = Literal["request", "execute", "rollback"]
Network = IPv4Network | IPv6Network

# These are mandatory minimums, not mutable policy: database rules may add to
# them but their absence cannot remove them. They are also seeded as facts.
_BASE_NETWORKS: tuple[Network, ...] = tuple(
    ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/32",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
        "ff00::/8",
    )
)
_SHELL_META = frozenset(";&|`$<>\\\"'(){}[]*?!~#")


@dataclass(frozen=True)
class SafeguardRule:
    kind: str
    value: str


@dataclass(frozen=True)
class SafeguardAction:
    action_type: str
    target: Mapping[str, Any]
    params: Mapping[str, Any]
    rules: tuple[SafeguardRule, ...] = ()
    phase: Phase = "request"


@dataclass(frozen=True)
class SafeguardResult:
    ok: bool
    reason: Reason | None = None


def _agent_key(value: object) -> str | None:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        return None
    return value.lstrip("0") or "0"


def _inspect_payload(*roots: object) -> Reason | None:
    """Inspect keys as well as values without trusting arbitrary nested objects."""
    stack = list(roots)
    seen: set[int] = set()
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            canonical = normalize("NFKC", value)
            if any(
                char in _SHELL_META
                or category(char).startswith("C")
                or category(char) in {"Zl", "Zp"}
                for char in canonical
            ):
                return "shell"
        elif isinstance(value, Mapping):
            if id(value) in seen or any(not isinstance(key, str) for key in value):
                return "invalid_payload"
            seen.add(id(value))
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, list | tuple):
            if id(value) in seen:
                return "invalid_payload"
            seen.add(id(value))
            stack.extend(value)
        elif isinstance(value, float):
            if not isfinite(value):
                return "invalid_payload"
        elif not isinstance(value, int | bool) and value is not None:
            return "invalid_payload"
    return None


def _rules(rules: tuple[object, ...]) -> tuple[set[str], tuple[Network, ...]] | None:
    agents = {"0"}
    networks = list(_BASE_NETWORKS)
    for rule in rules:
        if not isinstance(rule, SafeguardRule):
            return None
        kind: object = rule.kind
        value: object = rule.value
        if not isinstance(kind, str) or not isinstance(value, str):
            return None
        if kind == "agent":
            agent = _agent_key(value)
            if agent is None:
                return None
            agents.add(agent)
        elif kind == "network":
            try:
                networks.append(ip_network(value, strict=True))
            except ValueError:
                return None
        elif kind != "shell" or value != "baseline":
            return None
    return agents, tuple(networks)


def check_safeguards(action: SafeguardAction) -> SafeguardResult:
    """Return an allow/refusal fact without side effects or input-bearing reasons."""
    action_type: object = action.action_type
    if not isinstance(action_type, str):
        return SafeguardResult(False, "unknown_action")
    definition = CATALOG.get(action_type)
    if definition is None or action.phase not in {"request", "execute", "rollback"}:
        return SafeguardResult(False, "unknown_action")
    if action.phase != "rollback" and not definition.requestable:
        return SafeguardResult(False, "unknown_action")
    if action.phase == "execute" and definition.level == 0:
        return SafeguardResult(False, "unknown_action")
    issue = _inspect_payload(action.target, action.params)
    if issue is not None:
        return SafeguardResult(False, issue)
    parsed_rules = _rules(action.rules)
    if parsed_rules is None:
        return SafeguardResult(False, "invalid_rule")
    agents, networks = parsed_rules
    try:
        target, params = definition.validate_payload(dict(action.target), dict(action.params))
    except TypeError, ValueError:
        return SafeguardResult(False, "invalid_payload")
    if "agent_id" in target:
        agent = _agent_key(target["agent_id"])
        if agent is None:
            return SafeguardResult(False, "invalid_payload")
        if agent in agents:
            return SafeguardResult(False, "protected_agent")
    check_network = definition.requires_unprotected_ip
    # An independently requested L2 action must also be safe to reverse later.
    if definition.level == 2 and definition.requestable and action.phase != "rollback":
        reverse = CATALOG.get(definition.reverse_action or "")
        if reverse is None:
            return SafeguardResult(False, "invalid_payload")
        try:
            reverse.validate_payload(target, params)
        except TypeError, ValueError:
            return SafeguardResult(False, "invalid_payload")
        check_network = check_network or reverse.requires_unprotected_ip
    if check_network:
        try:
            address = ip_address(target["ip"])
        except KeyError, TypeError, ValueError:
            return SafeguardResult(False, "invalid_payload")
        addresses: tuple[IPv4Address | IPv6Address, ...] = (address,)
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            addresses += (address.ipv4_mapped,)
        elif isinstance(address, IPv4Address):
            addresses += (IPv6Address(f"::ffff:{address}"),)
        if any(
            candidate.version == network.version and candidate in network
            for candidate in addresses
            for network in networks
        ):
            return SafeguardResult(False, "protected_ip")
    return SafeguardResult(True)
