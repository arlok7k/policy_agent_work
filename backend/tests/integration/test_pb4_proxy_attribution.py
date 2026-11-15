"""Client IP attribution must ignore direct spoofing and trust only configured peers."""

from ipaddress import ip_address

import pytest
from sqlalchemy import create_engine, text

from app.core.security import credential_digest
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def test_direct_spoof_is_ignored_but_explicit_proxy_address_is_used_for_audit_and_throttle(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = pb2_api
    wrong = Redacted.random()
    owner = create_engine(api.database_url, hide_parameters=True)
    settings = app.state.settings
    try:
        api.client.cookies.clear()
        direct = api.client.post(
            "/api/auth/login",
            headers={"X-Forwarded-For": "203.0.113.200", "X-Real-IP": "203.0.113.201"},
            json={"username": "admin", "password": wrong},
        )
        assert direct.status_code == 401
        proxy_settings = settings.model_copy(
            update={"trusted_proxy_ips": (ip_address("127.0.0.1"),)}
        )
        monkeypatch.setitem(app.state._state, "settings", proxy_settings)
        api.client.cookies.clear()
        proxied = api.client.post(
            "/api/auth/login",
            headers={"X-Forwarded-For": "198.51.100.8"},
            json={"username": "admin", "password": wrong},
        )
        assert proxied.status_code == 401
        with owner.connect() as db:
            addresses = (
                db.execute(
                    text(
                        "SELECT host(ip) FROM case_activities "
                        "WHERE action='auth.login_failed' ORDER BY id"
                    )
                )
                .scalars()
                .all()
            )
            assert addresses == ["127.0.0.1", "198.51.100.8"]

            def bucket(address: str) -> int | None:
                digest = credential_digest(settings.session_signing_secret, "throttle-ip", address)
                return db.execute(
                    text(
                        "SELECT failure_count FROM auth_login_throttle WHERE bucket_digest=:digest"
                    ),
                    {"digest": digest},
                ).scalar_one_or_none()

            assert bucket("127.0.0.1") == 1
            assert bucket("198.51.100.8") == 1
            assert bucket("203.0.113.200") is None
            assert bucket("203.0.113.201") is None
        for forwarded in (None, "", "198.51.100.1, 198.51.100.2", "invalid"):
            headers = {} if forwarded is None else {"X-Forwarded-For": forwarded}
            api.client.cookies.clear()
            response = api.client.post(
                "/api/auth/login", headers=headers, json={"username": "admin", "password": wrong}
            )
            assert response.status_code == 400
        api.client.cookies.clear()
        duplicate = api.client.post(
            "/api/auth/login",
            headers=[("X-Forwarded-For", "198.51.100.1"), ("X-Forwarded-For", "198.51.100.2")],
            json={"username": "admin", "password": wrong},
        )
        assert duplicate.status_code == 400
    finally:
        owner.dispose()
