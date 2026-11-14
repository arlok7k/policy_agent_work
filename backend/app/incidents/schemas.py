"""PB2 incident, evidence and investigation contracts."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.ai.schemas import ComprehensiveResult
from app.threat_intel.schemas import IntelResult


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    description: str | None = None
    alert_ids: list[UUID] = Field(default_factory=list)


class IncidentView(BaseModel):
    id: UUID
    title: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    alert_ids: list[UUID]


class IncidentPage(BaseModel):
    items: list[IncidentView]
    next_cursor: str | None


class EvidenceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    alert_id: UUID | None
    kind: str
    data: dict[str, Any]
    created_at: datetime


class EvidencePage(BaseModel):
    items: list[EvidenceView]
    next_cursor: str | None


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: UUID | None = None


class InvestigateResult(BaseModel):
    incident: IncidentView
    intelligence: IntelResult | None
    ai: ComprehensiveResult
