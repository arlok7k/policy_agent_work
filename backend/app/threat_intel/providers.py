"""Threat-intelligence interface with deterministic mock-only behavior."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Protocol

IPAddress = IPv4Address | IPv6Address
Verdict = Literal["benign", "suspicious", "unknown"]


class NotConfigured(Exception):
    """A real provider is intentionally not configured or reachable."""


@dataclass(frozen=True)
class ProviderVerdict:
    verdict: Verdict
    score: int | None
    sources: tuple[str, ...]
    mock: bool


class ThreatIntelProvider(Protocol):
    is_mock: bool

    async def check_ip(self, indicator: IPAddress) -> ProviderVerdict: ...


class MockProvider:
    """Synthetic, deterministic verdicts; never claim real reputation data."""

    is_mock = True

    async def check_ip(self, indicator: IPAddress) -> ProviderVerdict:
        if indicator.is_loopback:
            return ProviderVerdict("benign", 0, ("mock",), True)
        if indicator.is_private:
            return ProviderVerdict("suspicious", 50, ("mock",), True)
        return ProviderVerdict("unknown", None, ("mock",), True)


class _UnconfiguredProvider:
    is_mock = False

    async def check_ip(self, indicator: IPAddress) -> ProviderVerdict:
        raise NotConfigured("Real threat-intelligence providers are not configured")


class VirusTotalProvider(_UnconfiguredProvider):
    """Intentionally inert; no real provider calls are implemented."""


class AbuseIPDBProvider(_UnconfiguredProvider):
    """Intentionally inert; no real provider calls are implemented."""


class OTXProvider(_UnconfiguredProvider):
    """Intentionally inert; no real provider calls are implemented."""
