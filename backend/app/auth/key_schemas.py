"""Allow-listed API key requests and one-time issuance responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class KeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    ttl_seconds: StrictInt


class KeyView(BaseModel):
    id: UUID
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class KeyPage(BaseModel):
    items: list[KeyView]
    limit: int
    offset: int


class KeyIssued(BaseModel):
    key: KeyView
    secret: str = Field(repr=False)
