"""Typed settings with explicit, fail-closed secret loading."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    PositiveInt,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class ConfigurationError(Exception):
    """Configuration is missing or invalid; messages never include secret values."""


def _validate_database_url(value: SecretStr) -> SecretStr:
    try:
        url = make_url(value.get_secret_value())
    except ArgumentError:
        raise ValueError("invalid PostgreSQL database URL") from None
    if url.drivername != "postgresql+psycopg" or not url.database:
        raise ValueError("a PostgreSQL psycopg database URL is required")
    return value


class Settings(BaseModel):
    """Settings needed before serving any requests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Literal["development", "test", "production"]
    database_url: SecretStr
    session_signing_secret: SecretStr
    session_ttl_seconds: PositiveInt
    login_failure_limit: PositiveInt
    login_window_seconds: PositiveInt
    password_min_chars: PositiveInt
    password_max_chars: PositiveInt
    default_page_size: PositiveInt
    max_page_size: PositiveInt
    username_max_chars: PositiveInt
    api_key_name_max_chars: PositiveInt
    max_api_key_ttl_seconds: PositiveInt

    @model_validator(mode="after")
    def valid_policies(self) -> Settings:
        if self.password_min_chars > self.password_max_chars:
            raise ValueError("invalid password policy")
        if self.default_page_size > self.max_page_size:
            raise ValueError("invalid pagination policy")
        return self

    @field_validator("database_url")
    @classmethod
    def valid_database_url(cls, value: SecretStr) -> SecretStr:
        return _validate_database_url(value)

    @field_validator("session_signing_secret")
    @classmethod
    def sufficient_secret_length(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) < hashlib.sha256().digest_size:
            raise ValueError("session secret is too short")
        return value


def _read_secret(name: str, environ: Mapping[str, str]) -> str:
    inline = environ.get(name)
    file_path = environ.get(f"{name}_FILE")
    if (inline is None) == (file_path is None):
        raise ConfigurationError(f"Specify exactly one source for {name}")
    if file_path is not None:
        try:
            value = (
                Path(file_path).read_text(encoding="utf-8").removesuffix("\n").removesuffix("\r")
            )
        except OSError, UnicodeError, ValueError:
            raise ConfigurationError(f"Unable to read secret file for {name}") from None
    elif inline is not None:
        value = inline
    else:
        raise ConfigurationError(f"A source for {name} is required")
    if not value:
        raise ConfigurationError(f"{name} must not be empty")
    return value


def load_database_url(environ: Mapping[str, str] | None = None) -> SecretStr:
    """Load the DB secret without granting migrations access to other secrets."""
    source = os.environ if environ is None else environ
    try:
        return _validate_database_url(SecretStr(_read_secret("DATABASE_URL", source)))
    except ValueError:
        raise ConfigurationError("Invalid database configuration") from None


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Load settings once at startup; never include values in exceptions."""
    source = os.environ if environ is None else environ
    try:
        return Settings.model_validate(
            {
                "environment": source.get("ENV", ""),
                "database_url": SecretStr(_read_secret("DATABASE_URL", source)),
                "session_signing_secret": SecretStr(_read_secret("SESSION_SIGNING_SECRET", source)),
                "session_ttl_seconds": source.get("SESSION_TTL_SECONDS"),
                "login_failure_limit": source.get("LOGIN_FAILURE_LIMIT"),
                "login_window_seconds": source.get("LOGIN_WINDOW_SECONDS"),
                "password_min_chars": source.get("PASSWORD_MIN_CHARS"),
                "password_max_chars": source.get("PASSWORD_MAX_CHARS"),
                "default_page_size": source.get("DEFAULT_PAGE_SIZE"),
                "max_page_size": source.get("MAX_PAGE_SIZE"),
                "username_max_chars": source.get("USERNAME_MAX_CHARS"),
                "api_key_name_max_chars": source.get("API_KEY_NAME_MAX_CHARS"),
                "max_api_key_ttl_seconds": source.get("MAX_API_KEY_TTL_SECONDS"),
            }
        )
    except ValidationError:
        raise ConfigurationError("Invalid application configuration") from None
