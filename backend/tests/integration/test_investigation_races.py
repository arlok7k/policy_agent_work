"""Concurrency and rollback edges for PB2 incident investigations."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest
from sqlalchemy import create_engine, text

from tests.integration.conftest import PB2API


@pytest.fixture
def three_alerts(pb2_api: PB2API) -> list[UUID]:
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            return [
                db.execute(
                    text(
                        "INSERT INTO alerts (source, rule_id, severity, raw, fingerprint) "
                        "VALUES ('sensor', :rule, 'high', '{}'::jsonb, :digest) RETURNING id"
                    ),
                    {"rule": str(index), "digest": hashlib.sha256(str(index).encode()).digest()},
                ).scalar_one()
                for index in range(3)
            ]
    finally:
        engine.dispose()


def test_concurrent_additions_cannot_exceed_incident_limit(
    pb2_api: PB2API, three_alerts: list[UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Replace the immutable test settings with a smaller configured limit.
    from app.main import app

    smaller = app.state.pb2_settings.model_copy(update={"incident_max_alerts": 2})
    credentials = [pb2_api.login(role) for role in ("admin", "senior", "analyst")]
    incident = pb2_api.client.post(
        "/api/incidents",
        headers=credentials[0],
        json={"title": "bounded", "alert_ids": [str(three_alerts[0])]},
    )
    assert incident.status_code == 201
    identifier = incident.json()["id"]
    with monkeypatch.context() as patch:
        patch.setattr(app.state, "pb2_settings", smaller)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    pb2_api.client.post,
                    f"/api/alerts/{alert}/investigate",
                    headers=auth,
                    json={"incident_id": identifier},
                )
                for alert, auth in zip(three_alerts[1:], credentials[1:], strict=True)
            ]
            responses = [future.result(timeout=15) for future in futures]
    assert sorted(response.status_code for response in responses) == [200, 422]
    detail = pb2_api.client.get(f"/api/incidents/{identifier}", headers=credentials[0])
    assert detail.status_code == 200 and len(detail.json()["alert_ids"]) == 2
    evidence = pb2_api.client.get(f"/api/incidents/{identifier}/evidence", headers=credentials[0])
    assert evidence.status_code == 200 and len(evidence.json()["items"]) == 2


def test_create_rolls_back_when_activity_append_is_denied(
    pb2_api: PB2API, three_alerts: list[UUID]
) -> None:
    headers = pb2_api.login("admin")
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        response = pb2_api.client.post(
            "/api/incidents",
            headers=headers,
            json={"title": "must roll back", "alert_ids": [str(three_alerts[0])]},
        )
        assert response.status_code == 503
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM incidents")).scalar_one() == 0
            assert db.execute(text("SELECT count(*) FROM incident_alerts")).scalar_one() == 0
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()


def test_destination_ip_is_used_when_source_is_missing(
    pb2_api: PB2API, three_alerts: list[UUID]
) -> None:
    headers = pb2_api.login("analyst")
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text("UPDATE alerts SET dst_ip=CAST('2001:db8::5' AS inet) WHERE id=:id"),
                {"id": three_alerts[0]},
            )
        result = pb2_api.client.post(
            f"/api/alerts/{three_alerts[0]}/investigate", headers=headers, json={}
        )
        assert result.status_code == 200
        assert result.json()["intelligence"]["indicator"] == "2001:db8::5"
        assert result.json()["ai"]["analysis"]["indicator_present"] is True
    finally:
        engine.dispose()
