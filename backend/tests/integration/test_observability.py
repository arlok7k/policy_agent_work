"""Problem responses, correlated audit events and redacted JSON request logs."""

import json
from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.core.errors import install_error_handling
from app.core.logging import logger
from app.core.security import credential_digest
from app.main import app
from tests.sensitive import Redacted, SecretAwareTestClient, assert_not_disclosed, reveal


@pytest.fixture
def observed(
    runtime_url: str,
    migrated_url: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> Iterator[tuple[TestClient, Redacted, Redacted, UUID, pytest.LogCaptureFixture]]:
    password = Redacted.random()
    digest = Redacted(PasswordHasher().hash(password.reveal()))
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            user_id = db.execute(
                text(
                    "INSERT INTO users (username, password_hash, role_id) "
                    "VALUES ('alice', :digest, (SELECT id FROM roles WHERE name='admin')) "
                    "RETURNING id"
                ),
                {"digest": digest.reveal()},
            ).scalar_one()
    finally:
        engine.dispose()
    values = {
        "ENV": "test",
        "DATABASE_URL": runtime_url,
        "SESSION_SIGNING_SECRET": Redacted.random(48),
        "SESSION_TTL_SECONDS": "3600",
        "LOGIN_FAILURE_LIMIT": "10",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "2",
        "MAX_PAGE_SIZE": "4",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "3600",
    }
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, reveal(value))
    logger.addHandler(caplog.handler)
    try:
        with SecretAwareTestClient(
            app, base_url="https://testserver", client=("127.0.0.1", 50123)
        ) as client:
            yield client, password, digest, user_id, caplog
    finally:
        logger.removeHandler(caplog.handler)


def _events(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [
        json.loads(record.getMessage()) for record in caplog.records if record.name == "smart_soc"
    ]


def _assert_problem(response: object, status: int) -> None:
    from httpx2 import Response

    assert isinstance(response, Response)
    assert response.status_code == status
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert set(body) == {"type", "title", "status", "code", "correlation_id"}
    assert body["type"] == "about:blank" and body["status"] == status
    assert body["code"] == f"GOV-HTTP-{status:03d}"
    assert body["correlation_id"] == response.headers["X-Correlation-Id"]
    assert UUID(body["correlation_id"]).version == 4


def test_login_logs_and_audit_share_correlation_without_secrets(
    observed: tuple[TestClient, Redacted, Redacted, UUID, pytest.LogCaptureFixture],
    migrated_url: str,
) -> None:
    client, password, digest, user_id, caplog = observed
    correlation = str(uuid4())
    response = client.post(
        "/api/auth/login",
        headers={"X-Correlation-Id": correlation},
        json={"username": "alice", "password": password},
    )
    assert response.status_code == 200
    assert response.headers["X-Correlation-Id"] == correlation
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            audit_id = db.execute(
                text(
                    "SELECT details->>'correlation_id' FROM case_activities "
                    "WHERE action='auth.login'"
                )
            ).scalar_one()
        assert audit_id == correlation
    finally:
        engine.dispose()
    events = _events(caplog)
    assert events
    event = events[-1]
    assert set(event) >= {
        "ts",
        "level",
        "component",
        "correlation_id",
        "principal_kind",
        "principal_id",
        "op",
        "outcome",
    }
    assert event["correlation_id"] == correlation
    assert event["principal_kind"] == "user" and event["op"] == "POST /api/auth/login"
    expected_hash = credential_digest(
        app.state.settings.session_signing_secret, "log-principal", str(user_id)
    ).hex()
    assert event["principal_id"] == expected_hash and event["principal_id"] != str(user_id)
    combined = caplog.text + response.text
    assert_not_disclosed("Login log or response", combined, password, digest)


def test_problem_responses_replace_untrusted_correlation_and_hide_inputs(
    observed: tuple[TestClient, Redacted, Redacted, UUID, pytest.LogCaptureFixture],
) -> None:
    client, password, digest, _, caplog = observed
    marker = Redacted.random()
    correlation = str(uuid4())
    invalid = client.post(
        "/api/auth/login",
        headers={"X-Correlation-Id": correlation},
        json={"username": "alice", "password": password, "unexpected": marker},
    )
    _assert_problem(invalid, 400)
    assert invalid.headers["X-Correlation-Id"] == correlation
    not_found = client.get(
        f"/not-real/{marker.reveal()}?token={marker.reveal()}",
        headers={"X-Correlation-Id": marker},
    )
    _assert_problem(not_found, 404)
    correlation_replaced = not_found.headers["X-Correlation-Id"] != marker.reveal()
    assert correlation_replaced
    unauthorized = client.get("/api/users")
    _assert_problem(unauthorized, 401)
    method = client.put("/api/auth/me")
    _assert_problem(method, 405)
    assert "GET" in method.headers["Allow"]
    combined = caplog.text + invalid.text + not_found.text + unauthorized.text + method.text
    assert_not_disclosed("Problem response or log", combined, marker, password, digest)
    assert all("token=" not in str(event["op"]) for event in _events(caplog))


def test_csrf_denial_is_a_correlated_problem(
    observed: tuple[TestClient, Redacted, Redacted, UUID, pytest.LogCaptureFixture],
) -> None:
    client, password, _, _, caplog = observed
    login = client.post("/api/auth/login", json={"username": "alice", "password": password})
    assert login.status_code == 200
    correlation = str(uuid4())
    denied = client.post("/api/auth/logout", headers={"X-Correlation-Id": correlation})
    _assert_problem(denied, 403)
    assert denied.headers["X-Correlation-Id"] == correlation
    assert _events(caplog)[-1]["outcome"] == "denied"


def test_unhandled_exception_is_generic_and_only_its_class_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    example = FastAPI()
    install_error_handling(example)
    marker = Redacted.random()

    @example.get("/probe")
    def probe() -> None:
        raise RuntimeError(marker.reveal())

    logger.addHandler(caplog.handler)
    try:
        with TestClient(example) as client:
            response = client.get("/probe")
        _assert_problem(response, 500)
        assert_not_disclosed("Exception response or log", response.text + caplog.text, marker)
        event = _events(caplog)[-1]
        assert event["level"] == "ERROR" and event["error_type"] == "RuntimeError"
    finally:
        logger.removeHandler(caplog.handler)


def test_service_key_request_logs_hashed_identity_not_credentials(
    observed: tuple[TestClient, Redacted, Redacted, UUID, pytest.LogCaptureFixture],
) -> None:
    from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE

    client, password, digest, _, caplog = observed
    login = client.post("/api/auth/login", json={"username": "alice", "password": password})
    assert login.status_code == 200
    session = Redacted(login.cookies[SESSION_COOKIE])
    csrf = Redacted(login.cookies[CSRF_COOKIE])
    created = client.post(
        "/api/api-keys",
        headers={CSRF_HEADER: csrf},
        json={"name": "automation", "ttl_seconds": 600},
    )
    assert created.status_code == 201
    body = created.json()
    secret = Redacted(body["secret"])
    key_id = body["key"]["id"]
    client.cookies.clear()
    caplog.clear()
    response = client.get(
        "/api/auth/me", headers={"Authorization": Redacted(f"Bearer {secret.reveal()}")}
    )
    assert response.status_code == 200
    event = _events(caplog)[-1]
    assert event["principal_kind"] == "service"
    assert (
        event["principal_id"]
        == credential_digest(
            app.state.settings.session_signing_secret, "log-principal", key_id
        ).hex()
    )
    combined = caplog.text + response.text
    assert_not_disclosed(
        "Service request log or response", combined, password, digest, secret, session, csrf
    )


def test_database_failure_returns_generic_correlated_503(
    observed: tuple[TestClient, Redacted, Redacted, UUID, pytest.LogCaptureFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.exc import OperationalError

    client, password, digest, _, caplog = observed
    assert (
        client.post("/api/auth/login", json={"username": "alice", "password": password}).status_code
        == 200
    )
    marker = Redacted.random()

    def broken_factory() -> object:
        raise OperationalError(marker.reveal(), {}, RuntimeError(marker.reveal()))

    monkeypatch.setattr(app.state, "session_factory", broken_factory)
    response = client.get("/api/auth/me")
    _assert_problem(response, 503)
    event = _events(caplog)[-1]
    assert event["level"] == "ERROR" and event["outcome"] == "error"
    combined = caplog.text + response.text
    assert_not_disclosed("Database failure output", combined, password, digest, marker)
