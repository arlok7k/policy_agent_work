"""Allow-listed administrative user request and response schemas."""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr, StrictBool, model_validator


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: SecretStr
    role: str


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    password: SecretStr | None = None
    role: str | None = None
    is_active: StrictBool | None = None

    @model_validator(mode="after")
    def has_nonnull_change(self) -> Self:
        changed = self.model_fields_set - {"id"}
        if not changed or any(getattr(self, field) is None for field in changed):
            raise ValueError("A non-null change is required")
        return self


class UserView(BaseModel):
    id: UUID
    username: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserPage(BaseModel):
    items: list[UserView]
    limit: int
    offset: int
