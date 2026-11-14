"""NFR-10 host authorization baseline, including every PB2 route."""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import create_engine, text

from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


@dataclass(frozen=True)
class RouteCase:
    method: str
    path: str
    access: str
    success: int
    body: str | None = None


# This table is independent of the application's policy data and router guards.
ROLE_ROUTES = (
    RouteCase("GET", "/api/alerts", "all", 200),
    RouteCase("GET", "/api/alerts/stats/summary", "all", 200),
    RouteCase("GET", "/api/alerts/{alert_id}", "all", 200),
    RouteCase("POST", "/api/alerts/{alert_id}/investigate", "all", 200, "investigate"),
    RouteCase("GET", "/api/incidents", "all", 200),
    RouteCase("POST", "/api/incidents", "all", 201, "incident"),
    RouteCase("GET", "/api/incidents/{incident_id}", "all", 200),
    RouteCase("GET", "/api/incidents/{incident_id}/evidence", "all", 200),
    RouteCase("POST", "/api/threat-intel/check-ip", "all", 200, "ip"),
    RouteCase("POST", "/api/threat-intel/bulk-check", "all", 200, "ips"),
    RouteCase("GET", "/api/threat-intel/cache/stats", "all", 200),
    RouteCase("POST", "/api/ai/summarize", "all", 200, "ai"),
    RouteCase("POST", "/api/ai/recommendations", "all", 200, "ai"),
    RouteCase("POST", "/api/ai/analyze-comprehensive", "all", 200, "ai"),
    RouteCase("GET", "/api/users", "admin", 200),
    RouteCase("POST", "/api/users", "admin", 201, "user_create"),
    RouteCase("PATCH", "/api/users", "admin", 200, "user_patch"),
    RouteCase("GET", "/api/api-keys", "admin", 200),
    RouteCase("POST", "/api/api-keys", "admin", 201, "key_create"),
    RouteCase("DELETE", "/api/api-keys", "admin", 204, "key_delete"),
)
PRINCIPAL_ROUTES = {
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/reauth"),
}
PUBLIC_ROUTES = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/alerts/webhook"),
}


def test_characterization_inventory_covers_every_host_operation() -> None:
    expected = {(case.method, case.path) for case in ROLE_ROUTES} | PRINCIPAL_ROUTES | PUBLIC_ROUTES
    observed = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method in {"get", "post", "patch", "put", "delete"}
    }
    assert observed == expected


def _cookie_headers(response: object) -> dict[str, Redacted]:
    # The response object is unwrapped only at the HTTP cookie boundary.
    cookies = response.cookies
    return {
        "Cookie": Redacted(
            f"{SESSION_COOKIE}={cookies[SESSION_COOKIE]}; {CSRF_COOKIE}={cookies[CSRF_COOKIE]}"
        ),
        CSRF_HEADER: Redacted(cookies[CSRF_COOKIE]),
    }


def _send(client: object, case: RouteCase, values: dict[str, object], headers: dict) -> object:
    path = case.path.format(**values)
    bodies = {
        "investigate": {},
        "incident": {"title": "matrix incident", "alert_ids": []},
        "ip": {"indicator": "127.0.0.1"},
        "ips": {"indicators": ["127.0.0.1"]},
        "ai": {"alert_id": str(values["alert_id"])},
        "user_create": {
            "username": "matrix-new-user",
            "password": Redacted.random(),
            "role": "analyst",
        },
        "user_patch": {"id": str(values["user_id"]), "is_active": True},
        "key_create": {"name": "matrix-new-key", "ttl_seconds": 300},
    }
    kwargs = {"headers": headers}
    if case.body == "key_delete":
        path += f"?id={values['key_id']}"
    elif case.body:
        kwargs["json"] = bodies[case.body]
    client.cookies.clear()
    return client.request(case.method, path, **kwargs)


def _signed_webhook(signing: Redacted) -> tuple[bytes, dict[str, str | Redacted]]:
    body = json.dumps({"source": "matrix", "rule_id": "r", "severity": "high"}).encode()
    stamp = str(int(time.time()))
    event_id = str(uuid4())
    message = stamp.encode() + b"." + event_id.encode() + b"." + body
    signature = Redacted(
        "sha256=" + hmac.digest(signing.reveal().encode(), message, "sha256").hex()
    )
    return body, {
        "X-Webhook-Timestamp": stamp,
        "X-Webhook-Id": event_id,
        "X-Webhook-Signature": signature,
        "Content-Type": "application/json",
    }


def test_full_legacy_allow_deny_matrix(pb2_api: PB2API) -> None:
    client = pb2_api.client
    credentials: dict[str, dict[str, Redacted]] = {
        role: pb2_api.login(role) for role in ("admin", "senior", "analyst")
    }
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE users SET is_active=true WHERE username='inactive'"))
            db.execute(text("INSERT INTO roles (name) VALUES ('unlisted')"))
            db.execute(
                text(
                    "INSERT INTO users (username, password_hash, role_id) "
                    "VALUES ('outsider', :digest, (SELECT id FROM roles WHERE name='unlisted'))"
                ),
                {"digest": pb2_api.accounts["inactive"].digest.reveal()},
            )
            alert_id = db.execute(
                text(
                    "INSERT INTO alerts (source, rule_id, severity, raw, fingerprint) "
                    "VALUES ('matrix', 'rule', 'high', '{}'::jsonb, :fingerprint) RETURNING id"
                ),
                {"fingerprint": hashlib.sha256(b"matrix-alert").digest()},
            ).scalar_one()
            incident_id = db.execute(
                text("INSERT INTO incidents (title) VALUES ('matrix seed') RETURNING id")
            ).scalar_one()
        credentials["inactive"] = pb2_api.login("inactive")
        with engine.begin() as db:
            db.execute(text("UPDATE users SET is_active=false WHERE username='inactive'"))
        client.cookies.clear()
        outsider_login = client.post(
            "/api/auth/login",
            json={"username": "outsider", "password": pb2_api.accounts["inactive"].password},
        )
        assert outsider_login.status_code == 200
        credentials["outsider"] = _cookie_headers(outsider_login)
        client.cookies.clear()
        issued = client.post(
            "/api/api-keys",
            headers=credentials["admin"],
            json={"name": "matrix-service", "ttl_seconds": 300},
        )
        assert issued.status_code == 201
        service_key = Redacted(issued.json()["secret"])
        credentials["service"] = {"Authorization": Redacted(f"Bearer {service_key.reveal()}")}
        client.cookies.clear()
        issued_delete = client.post(
            "/api/api-keys",
            headers=credentials["admin"],
            json={"name": "matrix-delete", "ttl_seconds": 300},
        )
        assert issued_delete.status_code == 201
        delete_id = issued_delete.json()["key"]["id"]
        delete_secret = Redacted(issued_delete.json()["secret"])
        assert isinstance(delete_secret, Redacted)
        credentials["anonymous"] = {}
        values = {
            "alert_id": alert_id,
            "incident_id": incident_id,
            "key_id": delete_id,
            "user_id": pb2_api.accounts["analyst"].id,
        }
        for case in ROLE_ROUTES:
            for principal, authentic in credentials.items():
                headers = {**authentic, "X-Role": "admin"}
                response = _send(client, case, values, headers)
                if principal in {"anonymous", "inactive"}:
                    expected = 401
                elif principal in {"outsider", "service"}:
                    expected = 403
                elif case.access == "admin" and principal != "admin":
                    expected = 403
                else:
                    expected = case.success
                assert response.status_code == expected, f"{case.method} {case.path} as {principal}"
        # Every unsafe cookie request is denied before its handler without CSRF.
        for case in ROLE_ROUTES:
            if case.method != "GET":
                response = _send(client, case, values, {"Cookie": credentials["admin"]["Cookie"]})
                assert response.status_code == 403, f"CSRF: {case.method} {case.path}"
        for path, body in (
            (
                "/api/auth/login",
                {"username": "admin", "password": pb2_api.accounts["admin"].password},
            ),
            ("/api/auth/reauth", {"password": pb2_api.accounts["admin"].password}),
            ("/api/auth/logout", {}),
            ("/api/alerts/webhook", {}),
        ):
            client.cookies.clear()
            response = client.post(
                path, headers={"Cookie": credentials["admin"]["Cookie"]}, json=body
            )
            assert response.status_code == 403, f"CSRF: {path}"
        # A valid service credential never inherits its owner's privileges.
        for principal, headers in credentials.items():
            client.cookies.clear()
            response = client.get("/api/auth/me", headers=headers)
            assert response.status_code == (401 if principal in {"anonymous", "inactive"} else 200)
            client.cookies.clear()
            password = (
                pb2_api.accounts[principal].password
                if principal in pb2_api.accounts
                else pb2_api.accounts["inactive"].password
            )
            response = client.post("/api/auth/reauth", headers=headers, json={"password": password})
            expected = (
                401
                if principal in {"anonymous", "inactive"}
                else 403
                if principal == "service"
                else 204
            )
            assert response.status_code == expected, f"reauth as {principal}"
        client.cookies.clear()
        assert client.get("/api/health").status_code == 200
        response = client.post(
            "/api/auth/login",
            json={"username": "inactive", "password": pb2_api.accounts["inactive"].password},
        )
        assert response.status_code == 401
        signing = Redacted(app.state.pb2_settings.webhook_secret.get_secret_value())
        for principal, headers in credentials.items():
            client.cookies.clear()
            assert (
                client.post("/api/alerts/webhook", headers=headers, content=b"{}").status_code
                == 401
            )
            body, signature = _signed_webhook(signing)
            client.cookies.clear()
            response = client.post(
                "/api/alerts/webhook", headers={**headers, **signature}, content=body
            )
            assert response.status_code == (401 if principal == "inactive" else 202)
        client.cookies.clear()
        mixed = {**credentials["admin"], **credentials["service"]}
        assert client.get("/api/incidents", headers=mixed).status_code == 401
        for principal, headers in credentials.items():
            client.cookies.clear()
            response = client.post("/api/auth/logout", headers=headers)
            expected = (
                401
                if principal in {"anonymous", "inactive"}
                else 403
                if principal == "service"
                else 204
            )
            assert response.status_code == expected, f"logout as {principal}"
    finally:
        engine.dispose()
