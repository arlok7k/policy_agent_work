"""A missing legacy policy entry cannot silently permit a host route."""

from uuid import uuid4

import pytest

from app.main import app
from tests.integration.conftest import PB2API


def test_missing_operation_rules_fail_closed(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = pb2_api.login("admin")
    cases = (
        ("users", "GET", "/api/users", None),
        ("api_keys", "GET", "/api/api-keys", None),
        ("alerts_read", "GET", "/api/alerts", None),
        ("threat_intel", "POST", "/api/threat-intel/check-ip", {"indicator": "127.0.0.1"}),
        ("ai", "POST", "/api/ai/summarize", {"alert_id": str(uuid4())}),
        ("incidents_read", "GET", "/api/incidents", None),
        ("incidents_write", "POST", "/api/incidents", {"title": "not persisted"}),
        ("investigate", "POST", f"/api/alerts/{uuid4()}/investigate", {}),
    )
    original = dict(app.state.legacy_policy)
    for operation, method, path, body in cases:
        missing = {key: roles for key, roles in original.items() if key != operation}
        with monkeypatch.context() as patch:
            # Starlette State stores attributes in its backing mapping; patching
            # that mapping preserves the original entry across loop iterations.
            patch.setitem(app.state._state, "legacy_policy", missing)
            pb2_api.client.cookies.clear()
            response = pb2_api.client.request(method, path, headers=headers, json=body)
        assert response.status_code == 503, f"missing policy: {operation}"
