"""Reproducible OpenAPI and representative real status/schema contracts."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from openapi_spec_validator import validate
from redis.exceptions import ConnectionError as RedisConnectionError

from app.main import app
from app.threat_intel.providers import IPAddress, MockProvider, ProviderVerdict
from tests.contract.assertions import assert_response_contract
from tests.contract.test_legacy_matrix import ROLE_ROUTES, _signed_webhook
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def test_export_is_reproducible_valid_and_matches_authentication_boundaries() -> None:
    document = app.openapi()
    generated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    artifact = Path(__file__).resolve().parents[3] / "openapi.host.json"
    assert artifact.read_text(encoding="utf-8") == generated
    validate(document)
    schemas = document["components"]["schemas"]
    for name in ("SummaryResult", "RecommendationResult", "ComprehensiveResult"):
        assert "mock" in schemas[name]["required"]
        assert schemas[name]["properties"]["mock"]["const"] is True
    assert "accepted" in schemas["WebhookAccepted"]["required"]
    assert schemas["WebhookAccepted"]["properties"]["accepted"]["const"] is True
    assert "HTTPValidationError" not in schemas
    for case in ROLE_ROUTES:
        operation = document["paths"][case.path][case.method.lower()]
        expected = {"admin"} if case.access == "admin" else {"analyst", "senior_analyst", "admin"}
        assert set(operation["x-legacy-roles"]) == expected
        if case.method == "GET":
            assert operation["security"] == [{"SessionCookie": []}]
        else:
            assert operation["security"] == [
                {"SessionCookie": [], "CSRFCookie": [], "CSRFHeader": []}
            ]
        for status, response in operation["responses"].items():
            if int(status) >= 400:
                assert set(response["content"]) == {"application/problem+json"}
                assert response["content"]["application/problem+json"]["schema"] == {
                    "$ref": "#/components/schemas/Problem"
                }
    assert document["paths"]["/api/auth/me"]["get"]["security"] == [
        {"SessionCookie": []},
        {"ServiceBearer": []},
    ]
    assert document["paths"]["/api/health"]["get"]["security"] == []
    assert document["paths"]["/api/auth/login"]["post"]["security"] == []
    assert document["paths"]["/api/alerts/webhook"]["post"]["security"] == [
        {"WebhookTimestamp": [], "WebhookEventId": [], "WebhookSignature": []}
    ]


def test_representative_error_statuses_match_published_schemas(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = pb2_api.client
    headers = pb2_api.login("analyst")
    protected = [pb2_api.accounts["analyst"].password, pb2_api.accounts["analyst"].digest]
    response = client.get("/api/alerts/not-a-uuid", headers=headers)
    assert response.status_code == 400
    assert_response_contract("GET", "/api/alerts/{alert_id}", response, *protected)
    response = client.get(f"/api/incidents/{uuid4()}", headers=headers)
    assert response.status_code == 404
    assert_response_contract("GET", "/api/incidents/{incident_id}", response, *protected)
    response = client.post(
        "/api/incidents",
        headers=headers,
        json={"title": "too many", "alert_ids": [str(uuid4()) for _ in range(4)]},
    )
    assert response.status_code == 422
    assert_response_contract("POST", "/api/incidents", response, *protected)

    signing = Redacted(app.state.pb2_settings.webhook_secret.get_secret_value())
    body, signed = _signed_webhook(signing)
    signature = signed["X-Webhook-Signature"]
    assert isinstance(signature, Redacted)
    protected.extend((signing, signature))
    client.cookies.clear()
    accepted = client.post("/api/alerts/webhook", headers=signed, content=body)
    assert accepted.status_code == 202
    assert_response_contract("POST", "/api/alerts/webhook", accepted, *protected)
    replay = client.post("/api/alerts/webhook", headers=signed, content=body)
    assert replay.status_code == 409
    assert_response_contract("POST", "/api/alerts/webhook", replay, *protected)
    oversized = client.post(
        "/api/alerts/webhook", content=b"x" * (app.state.pb2_settings.webhook_max_body_bytes + 1)
    )
    assert oversized.status_code == 413
    assert_response_contract("POST", "/api/alerts/webhook", oversized, *protected)

    def unavailable(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(app.state.redis_cache, "get", unavailable)
        client.cookies.clear()
        response = client.post(
            "/api/threat-intel/check-ip", headers=headers, json={"indicator": "8.8.4.4"}
        )
    assert response.status_code == 503
    assert_response_contract("POST", "/api/threat-intel/check-ip", response, *protected)

    marker = Redacted.random()

    class BrokenMock(MockProvider):
        async def check_ip(self, indicator: IPAddress) -> ProviderVerdict:
            raise RuntimeError(marker.reveal())

    with monkeypatch.context() as patch:
        patch.setitem(app.state._state, "threat_provider", BrokenMock())
        client.cookies.clear()
        response = client.post(
            "/api/threat-intel/check-ip", headers=headers, json={"indicator": "8.8.4.4"}
        )
    assert response.status_code == 500
    assert_response_contract("POST", "/api/threat-intel/check-ip", response, *protected, marker)

    bad = Redacted.random()
    settings = app.state.settings.model_copy(update={"login_failure_limit": 1})
    with monkeypatch.context() as patch:
        patch.setitem(app.state._state, "settings", settings)
        client.cookies.clear()
        first = client.post("/api/auth/login", json={"username": "analyst", "password": bad})
        assert first.status_code == 401
        blocked = client.post("/api/auth/login", json={"username": "analyst", "password": bad})
    assert blocked.status_code == 429
    assert_response_contract("POST", "/api/auth/login", blocked, *protected, bad)
