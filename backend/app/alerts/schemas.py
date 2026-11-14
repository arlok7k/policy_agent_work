"""Public webhook input and accepted response schemas."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class WebhookAlert(BaseModel):
    """The validated alert envelope; raw data remains data, never markup."""

    model_config = ConfigDict(extra="forbid")

    source: str
    rule_id: str
    severity: str
    agent: str | None = None
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class WebhookAccepted(BaseModel):
    accepted: bool = True


class AlertView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source: str
    rule_id: str
    severity: str
    agent: str | None
    src_ip: IPvAnyAddress | None
    dst_ip: IPvAnyAddress | None
    raw: dict[str, Any]
    status: str
    created_at: datetime


class AlertPage(BaseModel):
    items: list[AlertView]
    next_cursor: str | None


class AlertSummary(BaseModel):
    by_severity: dict[str, int]
    by_status: dict[str, int]
    last_24h: int
