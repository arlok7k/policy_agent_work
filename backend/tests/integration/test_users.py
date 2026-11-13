"""Administrative user security and revocation against real PostgreSQL."""

import secrets
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from uuid import uuid4

import pytest
from argon2 import PasswordHasher, Type
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.auth.session import (
    CSRF_COOKIE,
    CSRF_HEADER,
    SESSION_COOKIE,
    identity_from_rows,
    session_rows,
)
from app.main import app
from app.users.schemas import UserPatch
from app.users.service import update_user
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
                ("sam", "senior_analyst"),
                ("amy", "analyst"),
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
                result[name] = {
                    "id": identifier,
                    "username": name,
                    "password": password,
                    "digest": digest,
                }
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
        "MAX_API_KEY_TTL_SECONDS": "2592000",
    }
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, reveal(value))
    with SecretAwareTestClient(
        app, base_url="https://testserver", client=("127.0.0.1", 50123)
    ) as test_client:
        yield test_client


def login_as(client: TestClient, account: dict[str, object]) -> dict[str, str | Redacted]:
    client.cookies.clear()
    response = client.post(
        "/api/auth/login", json={"username": account["username"], "password": account["password"]}
    )
    assert response.status_code == 200
    return {
        "Cookie": Redacted(
            f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}; "
            f"{CSRF_COOKIE}={response.cookies[CSRF_COOKIE]}"
        ),
        CSRF_HEADER: Redacted(response.cookies[CSRF_COOKIE]),
    }


def test_admin_create_list_update_and_safe_metadata(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    auth = login_as(client, accounts["alice"])
    password = Redacted.random()
    response = client.post(
        "/api/users",
        headers=auth,
        json={"username": "  New.User  ", "password": password, "role": "analyst"},
    )
    assert response.status_code == 201
    user = response.json()
    assert set(user) == {"id", "username", "role", "is_active", "created_at", "updated_at"}
    assert user["username"] == "new.user" and user["is_active"] is True
    assert_not_disclosed("User response", response.text, password)
    first = client.get("/api/users", headers=auth).json()
    second = client.get("/api/users?limit=2&offset=2", headers=auth).json()
    assert first["limit"] == 2 and first["offset"] == 0 and len(first["items"]) == 2
    assert len(second["items"]) == 2
    assert {item["id"] for item in first["items"]}.isdisjoint(
        item["id"] for item in second["items"]
    )
    assert client.get("/api/users?limit=5", headers=auth).status_code == 422
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            digest = Redacted(
                db.execute(
                    text("SELECT password_hash FROM users WHERE username='new.user'")
                ).scalar_one()
            )
            is_argon2id = digest.reveal().startswith("$argon2id$")
            assert is_argon2id
            verified = PasswordHasher().verify(digest.reveal(), password.reveal())
            assert verified
            audit = str(
                db.execute(
                    text("SELECT username, action, target, details FROM case_activities")
                ).all()
            )
            assert_not_disclosed("User activity", audit, password, digest)
    finally:
        engine.dispose()


@pytest.mark.parametrize("name", ["sam", "amy"])
def test_non_admin_cannot_bypass_users_roles(
    client: TestClient, accounts: dict[str, dict[str, object]], name: str
) -> None:
    auth = login_as(client, accounts[name])
    auth["X-Role"] = "admin"
    password = Redacted.random()
    assert client.get("/api/users", headers=auth).status_code == 403
    assert (
        client.post(
            "/api/users",
            headers=auth,
            json={"username": "forged", "password": password, "role": "admin"},
        ).status_code
        == 403
    )
    assert (
        client.patch(
            "/api/users", headers=auth, json={"id": str(accounts[name]["id"]), "role": "admin"}
        ).status_code
        == 403
    )


def test_admin_mutations_require_session_bound_csrf(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    auth = login_as(client, accounts["alice"])
    no_csrf = {"Cookie": auth["Cookie"]}
    forged = {**auth, CSRF_HEADER: Redacted.random()}
    payload = {"username": "new", "password": Redacted.random(), "role": "analyst"}
    assert client.post("/api/users", headers=no_csrf, json=payload).status_code == 403
    assert client.post("/api/users", headers=forged, json=payload).status_code == 403
    assert (
        client.patch(
            "/api/users",
            headers=no_csrf,
            json={"id": str(accounts["amy"]["id"]), "is_active": False},
        ).status_code
        == 403
    )


def test_validation_conflict_and_self_lockout_protection(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    auth = login_as(client, accounts["alice"])
    password = Redacted.random()
    for bad_name in ("bad/name", "Kelvin", "a" * 129, ""):
        response = client.post(
            "/api/users",
            headers=auth,
            json={"username": bad_name, "password": password, "role": "analyst"},
        )
        assert response.status_code == 422
        assert_not_disclosed("User validation response", response.text, password)
    short_password = Redacted(password.reveal()[:3])
    assert (
        client.post(
            "/api/users",
            headers=auth,
            json={"username": "new", "password": short_password, "role": "analyst"},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/users",
            headers=auth,
            json={"username": "new", "password": password, "role": "unknown"},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/users",
            headers=auth,
            json={"username": " ALICE ", "password": password, "role": "admin"},
        ).status_code
        == 409
    )
    alice_id = str(accounts["alice"]["id"])
    assert (
        client.patch(
            "/api/users", headers=auth, json={"id": alice_id, "is_active": False}
        ).status_code
        == 409
    )
    assert (
        client.patch(
            "/api/users", headers=auth, json={"id": alice_id, "role": "analyst"}
        ).status_code
        == 409
    )
    assert client.patch("/api/users", headers=auth, json={"id": alice_id}).status_code == 400
    assert (
        client.patch(
            "/api/users", headers=auth, json={"id": alice_id, "is_active": None}
        ).status_code
        == 400
    )
    assert (
        client.patch(
            "/api/users", headers=auth, json={"id": str(uuid4()), "is_active": False}
        ).status_code
        == 404
    )


def test_password_change_revokes_all_old_sessions(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    first = login_as(client, accounts["amy"])
    second = login_as(client, accounts["amy"])
    admin = login_as(client, accounts["alice"])
    new_password = Redacted.random()
    changed = client.patch(
        "/api/users",
        headers=admin,
        json={"id": str(accounts["amy"]["id"]), "password": new_password},
    )
    assert changed.status_code == 200
    assert_not_disclosed("Password change response", changed.text, new_password)
    assert client.get("/api/auth/me", headers=first).status_code == 401
    assert client.get("/api/auth/me", headers=second).status_code == 401
    client.cookies.clear()
    assert (
        client.post(
            "/api/auth/login", json={"username": "amy", "password": accounts["amy"]["password"]}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/auth/login", json={"username": "amy", "password": new_password}
        ).status_code
        == 200
    )


def test_disabling_revokes_sessions_and_keys_without_resurrection(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    old = login_as(client, accounts["amy"])
    admin = login_as(client, accounts["alice"])
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "INSERT INTO api_keys (owner_user_id, name, prefix, key_digest, expires_at) "
                    "VALUES (:owner, 'test', :prefix, :digest, "
                    "clock_timestamp() + interval '1 day')"
                ),
                {
                    "owner": accounts["amy"]["id"],
                    "prefix": secrets.token_urlsafe(12),
                    "digest": secrets.token_bytes(32),
                },
            )
        user_id = str(accounts["amy"]["id"])
        disabled = client.patch(
            "/api/users", headers=admin, json={"id": user_id, "is_active": False}
        )
        assert disabled.status_code == 200 and disabled.json()["is_active"] is False
        assert client.get("/api/auth/me", headers=old).status_code == 401
        with engine.connect() as db:
            assert db.execute(text("SELECT revoked_at FROM api_keys")).scalar_one() is not None
        enabled = client.patch("/api/users", headers=admin, json={"id": user_id, "is_active": True})
        assert enabled.status_code == 200 and enabled.json()["is_active"] is True
        assert client.get("/api/auth/me", headers=old).status_code == 401
        with engine.connect() as db:
            assert db.execute(text("SELECT revoked_at FROM api_keys")).scalar_one() is not None
    finally:
        engine.dispose()


def test_user_write_rolls_back_when_audit_fails(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    admin = login_as(client, accounts["alice"])
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        response = client.post(
            "/api/users",
            headers=admin,
            json={
                "username": "notpersisted",
                "password": Redacted.random(),
                "role": "analyst",
            },
        )
        assert response.status_code == 503
        with engine.connect() as db:
            assert (
                db.execute(
                    text("SELECT count(*) FROM users WHERE username='notpersisted'")
                ).scalar_one()
                == 0
            )
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()


@pytest.mark.parametrize("change,expected", [("disable", 401), ("demote", 403)])
def test_admin_identity_is_rechecked_after_dependency_before_mutation(
    client: TestClient,
    accounts: dict[str, dict[str, object]],
    migrated_url: str,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    expected: int,
) -> None:
    import app.users.service as service

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
                "/api/users",
                headers=admin,
                json={
                    "username": "afterchange",
                    "password": Redacted.random(),
                    "role": "analyst",
                },
            )
            try:
                assert reached.wait(10)
                with engine.begin() as db:
                    if change == "disable":
                        db.execute(text("UPDATE users SET is_active=false WHERE username='alice'"))
                    else:
                        db.execute(
                            text(
                                "UPDATE users SET role_id=(SELECT id FROM roles "
                                "WHERE name='analyst') WHERE username='alice'"
                            )
                        )
            finally:
                resume.set()
            assert future.result(timeout=10).status_code == expected
        with engine.connect() as db:
            assert (
                db.execute(
                    text("SELECT count(*) FROM users WHERE username='afterchange'")
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()


def test_concurrent_admin_disables_cannot_remove_last_admin(
    client: TestClient, accounts: dict[str, dict[str, object]], migrated_url: str
) -> None:
    first = login_as(client, accounts["alice"])
    second = login_as(client, accounts["bob"])
    settings = app.state.settings
    passwords = app.state.passwords
    factory = app.state.session_factory
    tokens = [
        Redacted(first["Cookie"].reveal().split(";")[0].split("=", 1)[1]),
        Redacted(second["Cookie"].reveal().split(";")[0].split("=", 1)[1]),
    ]
    identities = []
    for token in tokens:
        with factory() as db:
            rows = session_rows(db, settings, token.reveal())
            assert rows is not None
            identities.append(identity_from_rows(rows))
    barrier = threading.Barrier(2)

    def attempt(index: int) -> int:
        with factory() as db:
            barrier.wait(timeout=10)
            try:
                update_user(
                    db,
                    settings,
                    passwords,
                    identities[index],
                    tokens[index].reveal(),
                    ("admin",),
                    UserPatch(id=identities[1 - index].user_id, is_active=False),
                    ip_address("127.0.0.1"),
                )
                return 200
            except HTTPException as error:
                return error.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        result = list(executor.map(attempt, range(2)))
    assert sorted(result) == [200, 401]
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert (
                db.execute(
                    text(
                        "SELECT count(*) FROM users u JOIN roles r ON r.id=u.role_id "
                        "WHERE r.name='admin' AND u.is_active"
                    )
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_role_change_takes_effect_for_existing_session(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    target = login_as(client, accounts["amy"])
    admin = login_as(client, accounts["alice"])
    changed = client.patch(
        "/api/users",
        headers=admin,
        json={"id": str(accounts["amy"]["id"]), "role": "senior_analyst"},
    )
    assert changed.status_code == 200
    assert changed.json()["role"] == "senior_analyst"
    assert client.get("/api/auth/me", headers=target).json()["principal"]["roles"] == [
        "senior_analyst"
    ]
    assert client.get("/api/users", headers=target).status_code == 403


def test_admin_can_change_own_password_but_session_is_revoked(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    admin = login_as(client, accounts["alice"])
    password = Redacted.random()
    response = client.patch(
        "/api/users", headers=admin, json={"id": str(accounts["alice"]["id"]), "password": password}
    )
    assert response.status_code == 200
    assert client.get("/api/auth/me", headers=admin).status_code == 401
    client.cookies.clear()
    assert (
        client.post("/api/auth/login", json={"username": "alice", "password": password}).status_code
        == 200
    )


def test_unauthenticated_user_routes_and_extra_fields_fail_closed(
    client: TestClient, accounts: dict[str, dict[str, object]]
) -> None:
    assert client.get("/api/users", headers={"X-Role": "admin"}).status_code == 401
    admin = login_as(client, accounts["alice"])
    response = client.post(
        "/api/users",
        headers=admin,
        json={
            "username": "new",
            "password": Redacted.random(),
            "role": "analyst",
            "is_active": True,
        },
    )
    assert response.status_code == 400
