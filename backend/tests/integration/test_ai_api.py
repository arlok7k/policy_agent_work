"""Structured mock AI endpoints, legacy roles and data minimization."""

import hashlib
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text

from app.ai.providers import AlertContext, MockLLM
from app.main import app
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted, assert_not_disclosed


@pytest.fixture
def alert_id(pb2_api: PB2API) -> UUID:
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            return db.execute(
                text(
                    "INSERT INTO alerts (source, rule_id, severity, raw, fingerprint) "
                    "VALUES (:source, 'rule-ai', 'high', CAST(:raw AS jsonb), :digest) RETURNING id"
                ),
                {
                    "source": "<script>plain source</script>",
                    "raw": '{"governance_canary":"DO_NOT_SEND_GOVERNANCE"}',
                    "digest": hashlib.sha256(b"ai-alert").digest(),
                },
            ).scalar_one()
    finally:
        engine.dispose()


def test_all_roles_receive_deterministic_labelled_mock_results(
    pb2_api: PB2API, alert_id: UUID
) -> None:
    paths = ["/api/ai/summarize", "/api/ai/recommendations", "/api/ai/analyze-comprehensive"]
    expected = {}
    for role in ("admin", "senior", "analyst"):
        headers = pb2_api.login(role)
        for path in paths:
            response = pb2_api.client.post(path, headers=headers, json={"alert_id": str(alert_id)})
            assert response.status_code == 200
            assert response.json()["mock"] is True
            assert response.json()["alert_id"] == str(alert_id)
            assert "DO_NOT_SEND_GOVERNANCE" not in response.text
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["cache-control"] == "no-store"
            if path in expected:
                assert response.json() == expected[path]
            else:
                expected[path] = response.json()
    assert "<script>plain source</script>" in expected["/api/ai/summarize"]["summary"]
    assert expected["/api/ai/recommendations"]["recommendations"][0]["action"] == "review_alert"
    assert expected["/api/ai/analyze-comprehensive"]["analysis"] == {
        "severity": "high",
        "agent_present": False,
        "indicator_present": False,
    }


def test_ai_provider_receives_no_raw_or_governance_data(
    pb2_api: PB2API, alert_id: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ObservingMock(MockLLM):
        received: AlertContext | None = None

        def summarize(self, alert: AlertContext):
            self.received = alert
            return super().summarize(alert)

    provider = ObservingMock()
    headers = pb2_api.login("analyst")
    with monkeypatch.context() as patch:
        patch.setattr(app.state, "llm_provider", provider)
        response = pb2_api.client.post(
            "/api/ai/summarize", headers=headers, json={"alert_id": str(alert_id)}
        )
    assert response.status_code == 200
    assert provider.received is not None
    assert not hasattr(provider.received, "raw") and not hasattr(provider.received, "governance")
    assert "DO_NOT_SEND_GOVERNANCE" not in repr(provider.received)


def test_ai_rejects_missing_ids_unknown_fields_and_missing_csrf(
    pb2_api: PB2API, alert_id: UUID
) -> None:
    headers = pb2_api.login("analyst")
    path = "/api/ai/summarize"
    assert (
        pb2_api.client.post(path, headers=headers, json={"alert_id": str(uuid4())}).status_code
        == 404
    )
    assert (
        pb2_api.client.post(
            path, headers=headers, json={"alert_id": str(alert_id), "governance": "unexpected"}
        ).status_code
        == 400
    )
    assert (
        pb2_api.client.post(
            path, headers={"Cookie": headers["Cookie"]}, json={"alert_id": str(alert_id)}
        ).status_code
        == 403
    )
    pb2_api.client.cookies.clear()
    assert pb2_api.client.post(path, json={"alert_id": str(alert_id)}).status_code == 401


def test_ai_provider_failure_is_generic_and_not_fabricated(
    pb2_api: PB2API, alert_id: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = Redacted.random()

    class FailedMock(MockLLM):
        def summarize(self, alert: AlertContext):
            raise RuntimeError(marker.reveal())

    headers = pb2_api.login("analyst")
    with monkeypatch.context() as patch:
        patch.setattr(app.state, "llm_provider", FailedMock())
        response = pb2_api.client.post(
            "/api/ai/summarize", headers=headers, json={"alert_id": str(alert_id)}
        )
    assert response.status_code == 503
    assert "summary" not in response.json()
    assert_not_disclosed("AI failure response", response.text, marker)
