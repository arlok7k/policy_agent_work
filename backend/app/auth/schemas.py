"""Strict authentication request and explicitly allow-listed response shapes."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: SecretStr


class ReauthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: SecretStr


class PrincipalResponse(BaseModel):
    kind: Literal["user", "service"]
    id: UUID
    username: str | None
    roles: list[str]
    reauth_at: datetime | None


class AuthResponse(BaseModel):
    principal: PrincipalResponse
