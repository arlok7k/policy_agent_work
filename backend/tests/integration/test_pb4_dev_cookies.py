"""Development-only HTTP cookies never replace secure production sessions."""

import pytest

from app.auth.session import CSRF_HEADER, DEV_CSRF_COOKIE, DEV_SESSION_COOKIE, SESSION_COOKIE
from app.core.config import load_settings
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted, assert_not_disclosed


def test_development_http_cookie_flow_csrf_and_session_mode_isolation(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("DEV_INSECURE_COOKIES", "true")
    dev_settings = load_settings()
    monkeypatch.setitem(app.state._state, "settings", dev_settings)
    client.base_url = "http://testserver"
    admin = pb2_api.accounts["admin"]
    login = client.post(
        "/api/auth/login", json={"username": admin.username, "password": admin.password}
    )
    assert login.status_code == 200
    assert_not_disclosed("Development login response", login.text, admin.password, admin.digest)
    cookie_attributes = {
        line.split("=", 1)[0]: {part.strip().lower() for part in line.split(";")[1:]}
        for line in login.headers.get_list("set-cookie")
    }
    assert set(cookie_attributes) == {DEV_SESSION_COOKIE, DEV_CSRF_COOKIE}
    for attributes in cookie_attributes.values():
        assert "secure" not in attributes
        assert {"path=/", "samesite=strict"} <= attributes
        assert not any(attribute.startswith("domain=") for attribute in attributes)
    assert "httponly" in cookie_attributes[DEV_SESSION_COOKIE]
    assert "httponly" not in cookie_attributes[DEV_CSRF_COOKIE]
    session = Redacted(login.cookies[DEV_SESSION_COOKIE])
    csrf = Redacted(login.cookies[DEV_CSRF_COOKIE])
    headers = {CSRF_HEADER: csrf}
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/reauth", json={"password": admin.password}).status_code == 403
    assert (
        client.post(
            "/api/auth/reauth", headers=headers, json={"password": admin.password}
        ).status_code
        == 204
    )
    assert client.get("/api/users").status_code == 200
    assert client.get("/api/api-keys").status_code == 200
    assert client.patch("/api/settings", json={"display_name": "Dev SOC"}).status_code == 403
    changed = client.patch("/api/settings", headers=headers, json={"display_name": "Dev SOC"})
    assert changed.status_code == 200
    case = client.post(
        "/api/incidents", headers=headers, json={"title": "Dev case", "alert_ids": []}
    )
    assert case.status_code == 201
    request = client.post(
        "/api/response/actions",
        headers=headers,
        json={
            "incident_id": case.json()["id"],
            "action_type": "isolate_host",
            "target": {"agent_id": "004", "ip": "8.8.8.8"},
            "params": {},
        },
    )
    assert request.status_code == 201
    assert request.json()["status"] == "pending_approval"

    # Neither changing cookie names nor sharing a DB/secret permits replay in
    # the production cookie domain, even before the dev session is revoked.
    production = dev_settings.model_copy(
        update={"environment": "production", "dev_insecure_cookies": False}
    )
    monkeypatch.setitem(app.state._state, "settings", production)
    client.cookies.clear()
    for cookie_name in (DEV_SESSION_COOKIE, SESSION_COOKIE):
        forged = {"Cookie": Redacted(f"{cookie_name}={session.reveal()}")}
        assert client.get("/api/auth/me", headers=forged).status_code == 401
    monkeypatch.setitem(app.state._state, "settings", dev_settings)
    # Restore the live dev session to test a different user's approval and logout.
    client.cookies.set(DEV_SESSION_COOKIE, session.reveal(), domain="testserver.local", path="/")
    client.cookies.set(DEV_CSRF_COOKIE, csrf.reveal(), domain="testserver.local", path="/")
    senior = pb2_api.accounts["senior"]
    second = client.post(
        "/api/auth/login",
        headers=headers,
        json={"username": senior.username, "password": senior.password},
    )
    assert second.status_code == 200
    senior_csrf = Redacted(second.cookies[DEV_CSRF_COOKIE])
    senior_headers = {CSRF_HEADER: senior_csrf}
    decision = client.post(
        f"/api/response/actions/{request.json()['id']}/approve",
        headers=senior_headers,
        json={"reason": "Review"},
    )
    assert decision.status_code == 200
    switch = client.post(
        "/api/response/kill-switch", headers=senior_headers, json={"engaged": True}
    )
    assert switch.status_code == 200
    logout = client.post("/api/auth/logout", headers=senior_headers)
    assert logout.status_code == 204
    assert client.get("/api/auth/me").status_code == 401
