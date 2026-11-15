"""Explicit presentation-only administrative settings contracts."""

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator


class PresentationView(BaseModel):
    display_name: str
    default_direction: Literal["ltr", "rtl"]


class SettingsView(PresentationView):
    updated_at: datetime


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    default_direction: Literal["ltr", "rtl"] | None = None

    @model_validator(mode="after")
    def require_change(self) -> Self:
        if not self.model_fields_set or any(
            getattr(self, name) is None for name in self.model_fields_set
        ):
            raise ValueError("A non-null presentation setting is required")
        return self
