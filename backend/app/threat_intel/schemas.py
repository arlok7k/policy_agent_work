"""Public PB2 threat-intelligence request and response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from app.threat_intel.providers import Verdict


class CheckIPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: IPvAnyAddress


class BulkCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: list[IPvAnyAddress]


class IntelResult(BaseModel):
    indicator: IPvAnyAddress
    verdict: Verdict
    score: int | None = Field(ge=0, le=100)
    sources: list[str]
    mock: bool
    degraded: bool
    expires_at: datetime | None


class BulkCheckResult(BaseModel):
    items: list[IntelResult]


class CacheStats(BaseModel):
    fresh: int
    expired: int
    redis_available: bool
