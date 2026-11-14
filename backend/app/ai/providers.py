"""Minimal LLM interface; the only implementation is a deterministic mock."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol
from uuid import UUID

from app.ai.schemas import (
    AnalysisDetails,
    ComprehensiveResult,
    Recommendation,
    RecommendationResult,
    SummaryResult,
)


@dataclass(frozen=True)
class AlertContext:
    id: UUID
    source: str
    rule_id: str
    severity: str
    status: str
    agent: str | None
    src_ip: IPv4Address | IPv6Address | None
    dst_ip: IPv4Address | IPv6Address | None


class LLMProvider(Protocol):
    def summarize(self, alert: AlertContext) -> SummaryResult: ...

    def recommendations(self, alert: AlertContext) -> RecommendationResult: ...

    def analyze_comprehensive(self, alert: AlertContext) -> ComprehensiveResult: ...


class MockLLM:
    """Return synthetic, stable host-only output without a network client."""

    def summarize(self, alert: AlertContext) -> SummaryResult:
        return SummaryResult(
            alert_id=alert.id,
            summary=(
                f"Mock summary: {alert.source} reported rule {alert.rule_id} "
                f"with {alert.severity} severity and {alert.status} status."
            ),
        )

    def recommendations(self, alert: AlertContext) -> RecommendationResult:
        return RecommendationResult(
            alert_id=alert.id,
            recommendations=[
                Recommendation(
                    action="review_alert",
                    reason="Inspect the originating event and document the analyst's findings.",
                )
            ],
        )

    def analyze_comprehensive(self, alert: AlertContext) -> ComprehensiveResult:
        return ComprehensiveResult(
            alert_id=alert.id,
            summary=self.summarize(alert).summary,
            recommendations=self.recommendations(alert).recommendations,
            analysis=AnalysisDetails(
                severity=alert.severity,
                agent_present=alert.agent is not None,
                indicator_present=alert.src_ip is not None or alert.dst_ip is not None,
            ),
        )
