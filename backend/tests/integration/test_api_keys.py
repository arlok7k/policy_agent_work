"""API-key ownership, service identity and revocation on disposable PostgreSQL."""

import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from argon2 import PasswordHasher, Type
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.auth.key_schemas import KeyIssued
from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
from app.main import app
from tests.sensitive import Redacted, SecretAwareTestClient, assert_not_disclosed, reveal


@pytest.fixture
def accounts(migrated_url: str) -> dict[str, dict[str, object]]:
    hasher = PasswordHasher(type=Type.ID)
    engine = create_engine(migrated_url, hide_parameters=True)
    result = {}
    try:
        with engine.begin() as db:
            for name, role in (
                ("alice", "admin"),
                ("bob", "admin"),
                ("amy", "analyst"),
                ("sam", "senior_analyst"),
            ):
                password = Redacted.random()
                digest = Redacted(hasher.hash(password.reveal()))
                identifier = db.execute(
                    text(
                        "INSERT INTO users (username, password_hash, role_id) "
                        "VALUES (:name, :digest, (SELECT id FROM roles WHERE name=:role)) "
                        "RETURNING id"
                    ),
                    {"name": name, "digest": digest.reveal(), "role": role},
                ).scalar_one()
                result[name] = {"id": identifier, "username": name, "password": password}
        return result
    finally:
        engine.dispose()


@pytest.fixture
def client(
    runtime_url: str, accounts: dict[str, dict[str, object]], monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    values = {
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
    }
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, reveal(value))
    with SecretAwareTestClient(
        app, base_url="https://testserver", client=("127.0.0.1", 50123)
    ) as test_client:
        yield test_client


def login_as(client: TestClient, account: dict[str, object]) -> dict[str, Redacted]:
    client.cookies.clear()
    response = client.post(
        "/api/auth/login", json={"username": account["username"], "password": account["password"]}
    )
    assert response.status_code == 200
    headers = {
        "Cookie": Redacted(
            f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}; "
            f"{CSRF_COOKIE}={response.cookies[CSRF_COOKIE]}"
        ),
        CSRF_HEADER: Redacted(response.cookies[CSRF_COOKIE]),
    }
    client.cookies.clear()
    return headers


def issue(
    client: TestClient, admin: dict[str, Redacted], name: str = "automation"
) -> dict[str, object]:
    response = client.post("/api/api-keys", headers=admin, json={"name": name, "ttl_seconds": 600})
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    result["secret"] = Redacted(result["secret"])
    return result


def bearer(secret: Redacted) -> dict[str, Redacted]:
    return {"Authorization": Redacted(f"Bearer {secret.reveal()}")}


def test_key_lifecycle_uses_distinct_service_principal_and_once_only_secret(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    admin = login_as(client, accounts["alice"])
    issued = issue(client, admin)
    key = issued["key"]
    assert isinstance(key, dict)
    secret = issued["secret"]
    assert isinstance(secret, Redacted)
    assert set(key) == {"id", "name", "prefix", "created_at", "expires_at", "revoked_at"}
    has_prefix = secret.reveal().startswith(f"soc_{key['prefix']}.")
    assert has_prefix
    issued_repr = repr(KeyIssued.model_validate(reveal(issued)))
    assert_not_disclosed("Issued key representation", issued_repr, secret)
    listing = client.get("/api/api-keys", headers=admin)
    assert listing.status_code == 200 and len(listing.json()["items"]) == 1
    assert_not_disclosed("Key listing", listing.text, secret)
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            stored = db.execute(
                text("SELECT key_digest FROM api_keys WHERE id=:id"), {"id": key["id"]}
            ).scalar_one()
            audit = str(
                db.execute(
                    text("SELECT username, action, target, details FROM case_activities")
                ).all()
            )
        not_plaintext = stored != secret.reveal().encode()
        assert not_plaintext
        assert_not_disclosed("Key audit", audit, secret, Redacted(stored.hex()))
        me = client.get("/api/auth/me", headers=bearer(secret))
        assert me.status_code == 200
        assert me.json()["principal"] == {
            "kind": "service",
            "id": key["id"],
            "username": None,
            "roles": [],
            "reauth_at": None,
        }
        assert client.get("/api/users", headers=bearer(secret)).status_code == 403
        assert client.get("/api/api-keys", headers=bearer(secret)).status_code == 403
        assert client.post("/api/auth/logout", headers=bearer(secret)).status_code == 403
        assert (
            client.post(
                "/api/api-keys", headers=bearer(secret), json={"name": "forged", "ttl_seconds": 1}
            ).status_code
            == 403
        )
        assert client.delete(f"/api/api-keys?id={key['id']}", headers=admin).status_code == 204
        assert client.get("/api/auth/me", headers=bearer(secret)).status_code == 401
        assert client.delete(f"/api/api-keys?id={key['id']}", headers=admin).status_code == 204
        with engine.connect() as db:
            assert (
                db.execute(
                    text("SELECT count(*) FROM case_activities WHERE action='api_key.revoke'")
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_key_idor_and_owner_scoped_listing(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    alice = login_as(client, accounts["alice"])
    issued = issue(client, alice)
    key = issued["key"]
    assert isinstance(key, dict)
    bob = login_as(client, accounts["bob"])
    listing = client.get("/api/api-keys", headers=bob)
    assert listing.status_code == 200 and listing.json()["items"] == []
    assert client.delete(f"/api/api-keys?id={key['id']}", headers=bob).status_code == 404
    assert client.delete(f"/api/api-keys?id={uuid4()}", headers=bob).status_code == 404
    assert client.get("/api/auth/me", headers=bearer(issued["secret"])).status_code == 200


@pytest.mark.parametrize("name", ["amy", "sam"])
def test_non_admin_cannot_manage_keys(
    client: TestClient, accounts: dict[str, dict[str, object]], name: str
) -> None:
    headers = login_as(client, accounts[name])
    headers["X-Role"] = "admin"
    assert client.get("/api/api-keys", headers=headers).status_code == 403
    assert (
        client.post(
            "/api/api-keys", headers=headers, json={"name": "forged", "ttl_seconds": 600}
        ).status_code
        == 403
    )
    assert client.delete(f"/api/api-keys?id={uuid4()}", headers=headers).status_code == 403


def test_api_key_mutations_require_csrf_and_never_fall_back(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    admin = login_as(client, accounts["alice"])
    issued = issue(client, admin)
    key = issued["key"]
    assert isinstance(key, dict)
    missing = {"Cookie": admin["Cookie"]}
    forged = {**admin, CSRF_HEADER: Redacted.random()}
    payload = {"name": "new", "ttl_seconds": 600}
    assert client.post("/api/api-keys", headers=missing, json=payload).status_code == 403
    assert client.post("/api/api-keys", headers=forged, json=payload).status_code == 403
    assert client.delete(f"/api/api-keys?id={key['id']}", headers=missing).status_code == 403
    mixed = {**admin, **bearer(issued["secret"])}
    assert client.get("/api/auth/me", headers=mixed).status_code == 401
    mixed["Authorization"] = "Bearer invalid"
    assert client.get("/api/auth/me", headers=mixed).status_code == 401
    assert client.delete(f"/api/api-keys?id={key['id']}", headers=mixed).status_code == 401


def test_tampered_invalid_and_expired_keys_are_rejected(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    admin = login_as(client, accounts["alice"])
    issued = issue(client, admin)
    key = issued["key"]
    assert isinstance(key, dict)
    secret = issued["secret"]
    assert isinstance(secret, Redacted)
    replacement = "A" if secret.reveal()[-1] != "A" else "B"
    tampered = Redacted(secret.reveal()[:-1] + replacement)
    assert client.get("/api/auth/me", headers=bearer(tampered)).status_code == 401
    basic = {"Authorization": Redacted(f"Basic {secret.reveal()}")}
    assert client.get("/api/auth/me", headers=basic).status_code == 401
    assert (
        client.get("/api/auth/me", headers={"Authorization": "Bearer invalid"}).status_code == 401
    )
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "UPDATE api_keys SET created_at=clock_timestamp()-interval '2 hours', "
                    "expires_at=clock_timestamp()-interval '1 hour' WHERE id=:id"
                ),
                {"id": key["id"]},
            )
        assert client.get("/api/auth/me", headers=bearer(secret)).status_code == 401
    finally:
        engine.dispose()


def test_owner_disable_revokes_keys_even_after_reactivation(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    bob = login_as(client, accounts["bob"])
    issued = issue(client, bob)
    alice = login_as(client, accounts["alice"])
    bob_id = str(accounts["bob"]["id"])
    assert (
        client.patch(
            "/api/users", headers=alice, json={"id": bob_id, "is_active": False}
        ).status_code
        == 200
    )
    assert client.get("/api/auth/me", headers=bearer(issued["secret"])).status_code == 401
    assert (
        client.patch(
            "/api/users", headers=alice, json={"id": bob_id, "is_active": True}
        ).status_code
        == 200
    )
    assert client.get("/api/auth/me", headers=bearer(issued["secret"])).status_code == 401
    assert client.get("/api/users", headers=bob).status_code == 401


def test_key_name_ttl_and_request_validation(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    admin = login_as(client, accounts["alice"])
    for payload in (
        {"name": "", "ttl_seconds": 600},
        {"name": "a" * 129, "ttl_seconds": 600},
        {"name": "valid", "ttl_seconds": 0},
        {"name": "valid", "ttl_seconds": 3601},
    ):
        assert client.post("/api/api-keys", headers=admin, json=payload).status_code == 422
    assert (
        client.post(
            "/api/api-keys",
            headers=admin,
            json={"name": "valid", "ttl_seconds": 600, "owner_user_id": str(accounts["bob"]["id"])},
        ).status_code
        == 400
    )
    assert client.get("/api/api-keys?limit=5", headers=admin).status_code == 422
    assert client.get("/api/api-keys", headers=admin).json()["items"] == []


def test_audit_failure_rolls_back_key_creation_and_revocation(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    admin = login_as(client, accounts["alice"])
    issued = issue(client, admin)
    key = issued["key"]
    assert isinstance(key, dict)
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        assert (
            client.post(
                "/api/api-keys", headers=admin, json={"name": "notpersisted", "ttl_seconds": 600}
            ).status_code
            == 503
        )
        assert client.delete(f"/api/api-keys?id={key['id']}", headers=admin).status_code == 503
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM api_keys")).scalar_one() == 1
            assert db.execute(text("SELECT revoked_at FROM api_keys")).scalar_one() is None
        assert client.get("/api/auth/me", headers=bearer(issued["secret"])).status_code == 200
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()


def test_key_creation_rechecks_demoted_admin_after_initial_guard(
    client: TestClient,
    accounts: dict[str, dict[str, object]],
    migrated_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.auth.key_service as service

    admin = login_as(client, accounts["alice"])
    reached = threading.Event()
    resume = threading.Event()
    original = service.lock_authorized_actor

    def pause_before_recheck(*args: object, **kwargs: object) -> object:
        reached.set()
        assert resume.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "lock_authorized_actor", pause_before_recheck)
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                client.post,
                "/api/api-keys",
                headers=admin,
                json={"name": "notpersisted", "ttl_seconds": 600},
            )
            try:
                assert reached.wait(10)
                with engine.begin() as db:
                    db.execute(
                        text(
                            "UPDATE users SET role_id=(SELECT id FROM roles WHERE name='analyst') "
                            "WHERE username='alice'"
                        )
                    )
            finally:
                resume.set()
            assert future.result(timeout=10).status_code == 403
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM api_keys")).scalar_one() == 0
    finally:
        engine.dispose()


def test_key_list_is_paginated_and_never_returns_issued_secrets(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    admin = login_as(client, accounts["alice"])
    issued = [issue(client, admin, name=f"automation-{index}") for index in range(3)]
    first = client.get("/api/api-keys?limit=2", headers=admin)
    second = client.get("/api/api-keys?limit=2&offset=2", headers=admin)
    assert first.status_code == second.status_code == 200
    assert len(first.json()["items"]) == 2 and len(second.json()["items"]) == 1
    for key in issued:
        secret = key["secret"]
        assert isinstance(secret, Redacted)
        assert_not_disclosed("First key-list page", first.text, secret)
        assert_not_disclosed("Second key-list page", second.text, secret)


def test_key_auth_checks_owner_activity_even_without_prior_revocation(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    admin = login_as(client, accounts["alice"])
    issued = issue(client, admin)
    assert client.get("/api/auth/me", headers=bearer(issued["secret"])).status_code == 200
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE users SET is_active=false WHERE username='alice'"))
        with engine.connect() as db:
            assert db.execute(text("SELECT revoked_at FROM api_keys")).scalar_one() is None
        assert client.get("/api/auth/me", headers=bearer(issued["secret"])).status_code == 401
    finally:
        engine.dispose()
