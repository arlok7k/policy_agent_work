"""The mock LLM is deterministic and receives only a narrow alert context."""

from ipaddress import ip_address
from uuid import uuid4

from app.ai.providers import AlertContext, MockLLM


def test_mock_llm_returns_structured_deterministic_results() -> None:
    alert = AlertContext(
        id=uuid4(),
        source="sensor",
        rule_id="r1",
        severity="high",
        status="open",
        agent=None,
        src_ip=ip_address("2001:db8::1"),
        dst_ip=None,
    )
    provider = MockLLM()
    summary = provider.summarize(alert)
    recommendations = provider.recommendations(alert)
    comprehensive = provider.analyze_comprehensive(alert)
    assert summary == provider.summarize(alert) and summary.mock is True
    assert recommendations == provider.recommendations(alert) and recommendations.mock is True
    assert comprehensive == provider.analyze_comprehensive(alert) and comprehensive.mock is True
    assert comprehensive.summary == summary.summary
    assert comprehensive.recommendations == recommendations.recommendations
    assert comprehensive.analysis.severity == "high"
    assert comprehensive.analysis.agent_present is False
    assert comprehensive.analysis.indicator_present is True
    assert not hasattr(alert, "raw") and not hasattr(alert, "governance")
