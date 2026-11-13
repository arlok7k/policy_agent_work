"""Public health is minimal and probes a real PostgreSQL connection."""

from collections.abc import Iterator
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.main import app
from tests.sensitive import Redacted, assert_not_disclosed, reveal


@pytest.fixture
def client(runtime_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    values = {
        "ENV": "test",
        "DATABASE_URL": runtime_url,
        "SESSION_SIGNING_SECRET": Redacted.random(48),
        "SESSION_TTL_SECONDS": "3600",
        "LOGIN_FAILURE_LIMIT": "5",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "50",
        "MAX_PAGE_SIZE": "100",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "3600",
    }
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, reveal(value))
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client


def test_health_is_public_minimal_and_uncached(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["Cache-Control"] == "no-store"
    assert UUID(response.headers["X-Correlation-Id"]).version == 4


def test_unreachable_database_returns_generic_503(
    client: TestClient, runtime_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = make_url(runtime_url).set(host="127.0.0.1", port=1)
    url = url.difference_update_query(["host", "port"]).update_query_dict({"connect_timeout": "1"})
    dead_engine = create_engine(url, pool_pre_ping=True, hide_parameters=True)
    try:
        monkeypatch.setattr(app.state, "session_factory", sessionmaker(dead_engine))
        response = client.get("/api/health")
        assert response.status_code == 503
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["code"] == "GOV-HTTP-503"
        assert set(response.json()) == {"type", "title", "status", "code", "correlation_id"}
        assert_not_disclosed("Readiness response", response.text, Redacted(runtime_url))
        assert "127.0.0.1" not in response.text
    finally:
        dead_engine.dispose()
