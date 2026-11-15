"""Bounded response-worker scheduling settings, shared by API, Beat and workers."""

import os
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.core.config import ConfigurationError


class PB3Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    response_sweep_interval_seconds: int = Field(default=5, ge=1, le=3600)
    response_sweep_batch_size: int = Field(default=100, ge=1, le=1000)
    l2_ttl_default_seconds: int = Field(default=3600, ge=1, le=86400)
    l2_ttl_max_seconds: int = Field(default=86400, ge=1, le=86400)

    @model_validator(mode="after")
    def valid_ttl_policy(self) -> PB3Settings:
        if self.l2_ttl_default_seconds > self.l2_ttl_max_seconds:
            raise ValueError("Default TTL must not exceed the maximum")
        return self


def load_pb3_settings(environ: Mapping[str, str] | None = None) -> PB3Settings:
    source = os.environ if environ is None else environ
    try:
        return PB3Settings.model_validate(
            {
                "response_sweep_interval_seconds": source.get(
                    "RESPONSE_SWEEP_INTERVAL_SECONDS", "5"
                ),
                "response_sweep_batch_size": source.get("RESPONSE_SWEEP_BATCH_SIZE", "100"),
                "l2_ttl_default_seconds": source.get("RESPONSE_L2_TTL_DEFAULT_SECONDS", "3600"),
                "l2_ttl_max_seconds": source.get("RESPONSE_L2_TTL_MAX_SECONDS", "86400"),
            }
        )
    except ValidationError:
        raise ConfigurationError("Invalid response configuration") from None
