"""Shared PB2 integration fixtures; all databases must be disposable."""

import os
from collections.abc import Iterator
from dataclasses import dataclass
from uuid import UUID

import pytest
from argon2 import PasswordHasher, Type
from redis import Redis
from sqlalchemy import create_engine, text

from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
from app.main import app
from tests.sensitive import Redacted, SecretAwareTestClient, reveal


@dataclass(frozen=True)
class PB2Account:
    id: UUID
    username: str
    password: Redacted
    digest: Redacted


@dataclass(frozen=True)
class PB2API:
    client: SecretAwareTestClient
    accounts: dict[str, PB2Account]
    broker: Redis
    cache: Redis
    database_url: str

    def login(self, role: str) -> dict[str, Redacted]:
        account = self.accounts[role]
        self.client.cookies.clear()
        response = self.client.post(
            "/api/auth/login", json={"username": account.username, "password": account.password}
        )
        assert response.status_code == 200
        return {
            "Cookie": Redacted(
                f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}; "
                f"{CSRF_COOKIE}={response.cookies[CSRF_COOKIE]}"
            ),
            CSRF_HEADER: Redacted(response.cookies[CSRF_COOKIE]),
        }


@pytest.fixture
def pb2_accounts(migrated_url: str) -> dict[str, PB2Account]:
    engine = create_engine(migrated_url, hide_parameters=True)
    hasher = PasswordHasher(type=Type.ID)
    accounts = {}
    try:
        with engine.begin() as db:
            for name, role, active in (
                ("admin", "admin", True),
                ("senior", "senior_analyst", True),
                ("analyst", "analyst", True),
                ("inactive", "analyst", False),
            ):
                password = Redacted.random()
                digest = Redacted(hasher.hash(password.reveal()))
                identifier = db.execute(
                    text(
                        "INSERT INTO users (username, password_hash, role_id, is_active) "
                        "VALUES (:name, :digest, "
                        "(SELECT id FROM roles WHERE name = :role), :active) "
                        "RETURNING id"
                    ),
                    {"name": name, "digest": digest.reveal(), "role": role, "active": active},
                ).scalar_one()
                accounts[name] = PB2Account(identifier, name, password, digest)
        return accounts
    finally:
        engine.dispose()


@pytest.fixture
def pb2_api(
    runtime_url: str,
    migrated_url: str,
    pb2_accounts: dict[str, PB2Account],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[PB2API]:
    if os.environ.get("TEST_REDIS_DISPOSABLE") != "1":
        pytest.fail("PB2 tests require two explicitly disposable Redis instances")
    broker_url = os.environ.get("TEST_REDIS_BROKER_URL")
    broker_client_url = os.environ.get("TEST_REDIS_BROKER_CLIENT_URL")
    cache_url = os.environ.get("TEST_REDIS_CACHE_URL")
    if not broker_url or not broker_client_url or not cache_url:
        pytest.fail("Configure disposable Redis broker, broker-client and cache URLs")
    broker = Redis.from_url(broker_client_url, socket_timeout=2)
    cache = Redis.from_url(cache_url, socket_timeout=2)
    if any(client.connection_pool.connection_kwargs.get("db") != 15 for client in (broker, cache)):
        pytest.fail("Redis tests require explicitly disposable database 15")
    # These are disposable instances, and the flag and dedicated DB are required.
    broker.flushdb()
    cache.flushdb()
    values: dict[str, str | Redacted] = {
        "ENV": "test",
        "DATABASE_URL": runtime_url,
        "SESSION_SIGNING_SECRET": Redacted.random(48),
        "SESSION_TTL_SECONDS": "3600",
        "LOGIN_FAILURE_LIMIT": "20",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "2",
        "MAX_PAGE_SIZE": "4",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "3600",
        "CELERY_BROKER_URL": broker_url,
        "REDIS_CACHE_URL": cache_url,
    }
    for key in ("DATABASE_URL_FILE", "SESSION_SIGNING_SECRET_FILE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, reveal(value))
    try:
        with SecretAwareTestClient(
            app, base_url="https://testserver", client=("127.0.0.1", 50123)
        ) as client:
            yield PB2API(client, pb2_accounts, broker, cache, migrated_url)
    finally:
        broker.flushdb()
        cache.flushdb()
        broker.close()
        cache.close()
