"""End-to-end session authentication against disposable PostgreSQL."""

import hmac
import json
import secrets
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from uuid import UUID

import pytest
from argon2 import PasswordHasher, Type
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.auth.models import AuthSession
from app.auth.service import AuthFailure, LoginSuccess, login
from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
from app.auth.step_up import PasswordStepUpProvider
from app.main import app


@pytest.fixture
def account(migrated_url: str) -> dict[str, str | UUID]:
    password = secrets.token_urlsafe(32)
    digest = PasswordHasher(type=Type.ID).hash(password)
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            user_id = db.execute(
                text(
                    "INSERT INTO users (username, password_hash, role_id) "
                    "VALUES (:username, :digest, (SELECT id FROM roles WHERE name='analyst')) "
                    "RETURNING id"
                ),
                {"username": "alice", "digest": digest},
            ).scalar_one()
        return {"username": "alice", "password": password, "digest": digest, "id": user_id}
    finally:
        engine.dispose()


@pytest.fixture
def client(
    runtime_url: str, account: dict[str, str | UUID], monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    values = {
        "ENV": "test",
        "DATABASE_URL": runtime_url,
        "SESSION_SIGNING_SECRET": secrets.token_urlsafe(48),
        "SESSION_TTL_SECONDS": "3600",
        "LOGIN_FAILURE_LIMIT": "2",
        "LOGIN_WINDOW_SECONDS": "60",
        "PASSWORD_MIN_CHARS": "14",
        "PASSWORD_MAX_CHARS": "1024",
        "DEFAULT_PAGE_SIZE": "50",
        "MAX_PAGE_SIZE": "100",
        "USERNAME_MAX_CHARS": "128",
        "API_KEY_NAME_MAX_CHARS": "128",
        "MAX_API_KEY_TTL_SECONDS": "2592000",
    }
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    with TestClient(app, base_url="https://testserver", client=("127.0.0.1", 50123)) as test_client:
        yield test_client


def login_as(client: TestClient, account: dict[str, str | UUID]) -> tuple[str, str]:
    response = client.post(
        "/api/auth/login", json={"username": account["username"], "password": account["password"]}
    )
    assert response.status_code == 200
    return response.cookies[SESSION_COOKIE], response.cookies[CSRF_COOKIE]


def test_login_reauth_logout_and_cookie_flags(
    client: TestClient, account: dict[str, str | UUID], migrated_url: str
) -> None:
    response = client.post(
        "/api/auth/login", json={"username": " ALICE ", "password": account["password"]}
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    headers = response.headers.get_list("set-cookie")
    session_cookie = next(value for value in headers if value.startswith(f"{SESSION_COOKIE}="))
    csrf_cookie = next(value for value in headers if value.startswith(f"{CSRF_COOKIE}="))
    assert all(
        flag in session_cookie.lower()
        for flag in ("secure", "httponly", "samesite=strict", "path=/")
    )
    assert all(flag in csrf_cookie.lower() for flag in ("secure", "samesite=strict", "path=/"))
    csrf_is_httponly = "httponly" in csrf_cookie.lower()
    has_domain = "domain=" in session_cookie.lower() + csrf_cookie.lower()
    assert not csrf_is_httponly
    assert not has_domain
    assert response.json()["principal"]["roles"] == ["analyst"]
    assert all(str(account[key]) not in response.text for key in ("password", "digest"))
    assert client.get("/api/auth/me").status_code == 200
    csrf = response.cookies[CSRF_COOKIE]
    assert (
        client.post("/api/auth/reauth", json={"password": account["password"]}).status_code == 403
    )
    reauth = client.post(
        "/api/auth/reauth", json={"password": account["password"]}, headers={CSRF_HEADER: csrf}
    )
    assert reauth.status_code == 204
    assert client.get("/api/auth/me").json()["principal"]["reauth_at"] is not None
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with Session(engine) as db:
            auth_session = db.execute(select(AuthSession)).scalar_one()
            provider = PasswordStepUpProvider()
            assert provider.verify(db, auth_session.user_id, auth_session.id, "password", 60)
            assert not provider.verify(db, auth_session.user_id, auth_session.id, "mfa", 60)
            assert not provider.verify(db, auth_session.user_id, auth_session.id, "password", 0)
        with engine.begin() as db:
            db.execute(
                text("UPDATE auth_sessions SET reauth_at=clock_timestamp()-interval '1 hour'")
            )
        with Session(engine) as db:
            auth_session = db.execute(select(AuthSession)).scalar_one()
            assert not provider.verify(db, auth_session.user_id, auth_session.id, "password", 60)
        logout_response = client.post("/api/auth/logout", headers={CSRF_HEADER: csrf})
        assert logout_response.status_code == 204
        assert client.get("/api/auth/me").status_code == 401
        with engine.connect() as db:
            audit = json.dumps(
                [
                    list(row)
                    for row in db.execute(text("SELECT action, details FROM case_activities"))
                ]
            )
            assert all(str(account[key]) not in audit for key in ("password", "digest"))
    finally:
        engine.dispose()


@pytest.mark.parametrize("path", ["/api/auth/logout", "/api/auth/reauth", "/api/auth/login"])
def test_every_cookie_mutation_requires_csrf(
    client: TestClient, account: dict[str, str | UUID], path: str
) -> None:
    login_as(client, account)
    response = client.post(
        path, json={"username": account["username"], "password": account["password"]}
    )
    assert response.status_code == 403
    assert client.get("/api/auth/me").status_code == 200


def test_forged_double_submit_is_bound_to_session(
    client: TestClient, account: dict[str, str | UUID]
) -> None:
    session, _ = login_as(client, account)
    forged = secrets.token_urlsafe(32)
    response = client.post(
        "/api/auth/logout",
        headers={
            "Cookie": f"{SESSION_COOKIE}={session}; {CSRF_COOKIE}={forged}",
            CSRF_HEADER: forged,
        },
    )
    assert response.status_code == 403
    assert client.get("/api/auth/me").status_code == 200


def test_session_fixation_and_rotation(client: TestClient, account: dict[str, str | UUID]) -> None:
    attacker_token = secrets.token_urlsafe(32)
    first = client.post(
        "/api/auth/login",
        json={"username": account["username"], "password": account["password"]},
        headers={"Cookie": f"{SESSION_COOKIE}={attacker_token}"},
    )
    assert first.status_code == 200
    old_session, csrf = first.cookies[SESSION_COOKIE], first.cookies[CSRF_COOKIE]
    session_reused = hmac.compare_digest(old_session, attacker_token)
    assert not session_reused
    second = client.post(
        "/api/auth/login",
        json={"username": account["username"], "password": account["password"]},
        headers={CSRF_HEADER: csrf},
    )
    assert second.status_code == 200
    session_reused = hmac.compare_digest(old_session, second.cookies[SESSION_COOKIE])
    assert not session_reused
    assert (
        client.get(
            "/api/auth/me", headers={"Cookie": f"{SESSION_COOKIE}={old_session}"}
        ).status_code
        == 401
    )
    assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize("mutation", ["revoke", "expire", "disable"])
def test_sessions_reject_revoked_expired_or_disabled_users_immediately(
    client: TestClient, account: dict[str, str | UUID], migrated_url: str, mutation: str
) -> None:
    login_as(client, account)
    sql = {
        "revoke": "UPDATE auth_sessions SET revoked_at=clock_timestamp()",
        "expire": "UPDATE auth_sessions SET created_at=clock_timestamp()-interval '2 hours', "
        "expires_at=clock_timestamp()-interval '1 hour'",
        "disable": "UPDATE users SET is_active=false",
    }[mutation]
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text(sql))
        assert client.get("/api/auth/me").status_code == 401
    finally:
        engine.dispose()


def test_wrong_and_unknown_credentials_are_generic_and_rate_limited(
    client: TestClient, account: dict[str, str | UUID]
) -> None:
    wrong = secrets.token_urlsafe(32)
    first = client.post(
        "/api/auth/login", json={"username": account["username"], "password": wrong}
    )
    second = client.post("/api/auth/login", json={"username": "unknown", "password": wrong})
    assert first.status_code == second.status_code == 401
    assert first.json() == second.json()
    assert (
        client.post("/api/auth/login", json={"username": "another", "password": wrong}).status_code
        == 429
    )
    assert all(wrong not in response.text for response in (first, second))


def test_concurrent_failures_share_atomic_database_limit(
    client: TestClient, account: dict[str, str | UUID]
) -> None:
    settings = app.state.settings.model_copy(update={"login_failure_limit": 1})
    factory = app.state.session_factory
    passwords = app.state.passwords
    wrong = secrets.token_urlsafe(32)

    def attempt() -> AuthFailure:
        with factory() as db:
            result = login(
                db,
                settings,
                passwords,
                str(account["username"]),
                wrong,
                ip_address("127.0.0.1"),
                None,
            )
            assert isinstance(result, AuthFailure)
            return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == sorted([AuthFailure.INVALID, AuthFailure.THROTTLED])


def test_validation_and_mixed_credentials_do_not_leak(
    client: TestClient, account: dict[str, str | UUID], caplog: pytest.LogCaptureFixture
) -> None:
    extra = secrets.token_urlsafe(40)
    bad = client.post(
        "/api/auth/login",
        json={
            "username": account["username"],
            "password": account["password"],
            "unexpected": extra,
        },
    )
    assert bad.status_code == 400
    assert all(secret not in bad.text + caplog.text for secret in (extra, str(account["password"])))
    login_as(client, account)
    assert (
        client.get("/api/auth/me", headers={"Authorization": "Bearer invalid"}).status_code == 401
    )


def test_only_digests_are_persisted_for_session_cookies(
    client: TestClient, account: dict[str, str | UUID], migrated_url: str
) -> None:
    session_token, csrf_token = login_as(client, account)
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            row = db.execute(text("SELECT token_digest, csrf_digest FROM auth_sessions")).one()
        no_plaintext = (
            row.token_digest != session_token.encode() and row.csrf_digest != csrf_token.encode()
        )
        assert no_plaintext
    finally:
        engine.dispose()


def test_reauthentication_failures_share_the_login_rate_limit(
    client: TestClient, account: dict[str, str | UUID]
) -> None:
    _, csrf = login_as(client, account)
    wrong = secrets.token_urlsafe(32)
    for _ in range(2):
        result = client.post(
            "/api/auth/reauth", json={"password": wrong}, headers={CSRF_HEADER: csrf}
        )
        assert result.status_code == 401
    limited = client.post("/api/auth/reauth", json={"password": wrong}, headers={CSRF_HEADER: csrf})
    assert limited.status_code == 429
    assert client.get("/api/auth/me").json()["principal"]["reauth_at"] is None


def test_concurrent_successful_logins_create_independent_sessions(
    client: TestClient, account: dict[str, str | UUID]
) -> None:
    settings = app.state.settings
    factory = app.state.session_factory
    passwords = app.state.passwords

    def attempt() -> LoginSuccess:
        with factory() as db:
            result = login(
                db,
                settings,
                passwords,
                str(account["username"]),
                str(account["password"]),
                ip_address("127.0.0.1"),
                None,
            )
            assert isinstance(result, LoginSuccess)
            return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))
    session_reused = hmac.compare_digest(results[0].session_token, results[1].session_token)
    assert not session_reused


def test_untrusted_username_and_password_are_not_written_to_activity(
    client: TestClient, migrated_url: str
) -> None:
    username = secrets.token_urlsafe(32)
    password = secrets.token_urlsafe(32)
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            activities = str(
                db.execute(
                    text("SELECT username, ip, action, target, details FROM case_activities")
                ).all()
            )
        assert username not in activities
        assert password not in activities
    finally:
        engine.dispose()


def test_audit_failure_rolls_back_successful_login(
    client: TestClient, account: dict[str, str | UUID], migrated_url: str
) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        response = client.post(
            "/api/auth/login",
            json={"username": account["username"], "password": account["password"]},
        )
        assert response.status_code == 503
        assert str(account["password"]) not in response.text
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM auth_sessions")).scalar_one() == 0
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()


def test_login_throttle_window_expires_using_database_time(
    client: TestClient, account: dict[str, str | UUID], migrated_url: str
) -> None:
    wrong = secrets.token_urlsafe(32)
    credentials = {"username": account["username"], "password": wrong}
    assert client.post("/api/auth/login", json=credentials).status_code == 401
    assert client.post("/api/auth/login", json=credentials).status_code == 401
    assert client.post("/api/auth/login", json=credentials).status_code == 429
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "UPDATE auth_login_throttle SET window_started_at = "
                    "clock_timestamp() - interval '2 minutes'"
                )
            )
        assert (
            client.post(
                "/api/auth/login",
                json={"username": account["username"], "password": account["password"]},
            ).status_code
            == 200
        )
    finally:
        engine.dispose()


def test_current_user_reads_current_role_from_database_each_request(
    client: TestClient, account: dict[str, str | UUID], migrated_url: str
) -> None:
    login_as(client, account)
    assert client.get("/api/auth/me").json()["principal"]["roles"] == ["analyst"]
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='admin') "
                    "WHERE id=:id"
                ),
                {"id": account["id"]},
            )
        assert client.get("/api/auth/me").json()["principal"]["roles"] == ["admin"]
    finally:
        engine.dispose()


def test_invalid_unicode_credentials_are_generic_and_do_not_crash(
    client: TestClient, account: dict[str, str | UUID]
) -> None:
    headers = {"Content-Type": "application/json"}
    response = client.post(
        "/api/auth/login",
        content=json.dumps({"username": account["username"], "password": "\ud800"}),
        headers=headers,
    )
    assert response.status_code == 401
    response = client.post(
        "/api/auth/login",
        content=json.dumps({"username": "\ud800", "password": account["password"]}),
        headers=headers,
    )
    assert response.status_code == 401
