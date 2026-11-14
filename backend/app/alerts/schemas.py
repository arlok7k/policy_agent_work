"""Public webhook input and accepted response schemas."""

from typing import Any

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
