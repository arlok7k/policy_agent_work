"""Threat-intelligence providers remain deterministic and network-free."""

import asyncio
from ipaddress import ip_address

import pytest

from app.threat_intel.providers import (
    AbuseIPDBProvider,
    MockProvider,
    NotConfigured,
    OTXProvider,
    VirusTotalProvider,
)


@pytest.mark.parametrize(
    ("indicator", "verdict", "score"),
    [
        ("127.0.0.1", "benign", 0),
        ("::1", "benign", 0),
        ("10.0.0.5", "suspicious", 50),
        ("2001:db8::1", "suspicious", 50),
        ("8.8.8.8", "unknown", None),
    ],
)
def test_mock_is_deterministic_and_explicitly_labelled(
    indicator: str, verdict: str, score: int | None
) -> None:
    provider = MockProvider()
    first = asyncio.run(provider.check_ip(ip_address(indicator)))
    second = asyncio.run(provider.check_ip(ip_address(indicator)))
    assert first == second
    assert first.verdict == verdict and first.score == score
    assert first.mock is True and first.sources == ("mock",)


@pytest.mark.parametrize("provider_class", [VirusTotalProvider, AbuseIPDBProvider, OTXProvider])
def test_real_providers_only_raise_not_configured(provider_class: type) -> None:
    provider = provider_class()
    assert provider.is_mock is False
    with pytest.raises(NotConfigured):
        asyncio.run(provider.check_ip(ip_address("8.8.8.8")))
