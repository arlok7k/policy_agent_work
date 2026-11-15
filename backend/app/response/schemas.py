"""Explicit request and allow-listed response-domain HTTP models."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from app.response.catalog import Mode


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: UUID
    action_type: str
    target: dict[str, Any]
    params: dict[str, Any] = Field(default_factory=dict)
    mode: Mode | None = None
    ttl_seconds: StrictInt | None = None


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = None


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    action_type: str
    target: dict[str, Any]
    params: dict[str, Any]
    level: int
    approval_mode: str
    status: str
    requested_by: UUID
    decided_by: UUID | None
    ttl_seconds: int | None
    ttl_expires_at: datetime | None
    rollback_requested_by: UUID | None
    rollback_requested_at: datetime | None
    rollback_request_status: Literal["pending", "refused", "resolved"] | None = None
    created_at: datetime
    updated_at: datetime


class ActionPage(BaseModel):
    items: list[ActionView]
    next_cursor: str | None


class ExecutedCommandView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_id: UUID
    phase: Literal["execute", "rollback"]
    connector: str
    command: str
    target: dict[str, Any]
    params: dict[str, Any]
    initiator: str
    simulated: bool
    executed_at: datetime


class ExecutedCommandPage(BaseModel):
    items: list[ExecutedCommandView]
    next_before_id: int | None


class KillSwitchStateView(BaseModel):
    engaged: bool
    changed_by: UUID | None
    changed_at: datetime
