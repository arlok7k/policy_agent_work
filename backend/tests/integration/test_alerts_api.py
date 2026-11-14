"""Alert reads, filters, keyset pagination and role-protected summaries."""

import hashlib
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text

from tests.integration.conftest import PB2API


@pytest.fixture
def seeded_alerts(pb2_api: PB2API) -> list[UUID]:
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    rows = [
        ("sensor", "r1", "high", "node-a", "2001:db8::1", "open", 1),
        ("sensor", "r2", "low", None, "192.0.2.1", "open", 2),
        ("collector", "r3", "high", "node-b", "2001:db8::2", "reviewed", 3),
        ("sensor", "r4", "medium", None, None, "open", 4),
        ("sensor", "r5", "low", None, None, "open", 26),
    ]
    result = []
    try:
        with engine.begin() as db:
            for source, rule, severity, agent, src_ip, status, hours in rows:
                digest = hashlib.sha256(rule.encode("utf-8")).digest()
                result.append(
                    db.execute(
                        text(
                            "INSERT INTO alerts "
                            "(source, rule_id, severity, agent, src_ip, status, raw, "
                            "fingerprint, created_at) "
                            "VALUES (:source, :rule, :severity, :agent, CAST(:ip AS inet), "
                            ":status, CAST(:raw AS jsonb), :digest, "
                            "now() - :hours * interval '1 hour') RETURNING id"
                        ),
                        {
                            "source": source,
                            "rule": rule,
                            "severity": severity,
                            "agent": agent,
                            "ip": src_ip,
                            "status": status,
                            "raw": '{"message":"<script>alert(1)</script>; DROP TABLE alerts"}',
                            "digest": digest,
                            "hours": hours,
                        },
                    ).scalar_one()
                )
        return result
    finally:
        engine.dispose()


def test_all_legacy_roles_can_read_and_anonymous_users_cannot(
    pb2_api: PB2API, seeded_alerts: list[UUID]
) -> None:
    client = pb2_api.client
    for role in ("admin", "senior", "analyst"):
        headers = pb2_api.login(role)
        for url in ("/api/alerts", f"/api/alerts/{seeded_alerts[0]}", "/api/alerts/stats/summary"):
            assert client.get(url, headers=headers).status_code == 200
    client.cookies.clear()
    for url in ("/api/alerts", f"/api/alerts/{seeded_alerts[0]}", "/api/alerts/stats/summary"):
        assert client.get(url).status_code == 401


def test_keyset_pages_are_stable_when_new_alerts_arrive(
    pb2_api: PB2API, seeded_alerts: list[UUID]
) -> None:
    headers = pb2_api.login("analyst")
    first = pb2_api.client.get("/api/alerts?limit=2", headers=headers)
    assert first.status_code == 200
    page = first.json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    seen = [item["id"] for item in page["items"]]
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            inserted = db.execute(
                text(
                    "INSERT INTO alerts (source, rule_id, severity, raw, fingerprint) "
                    "VALUES ('new', 'new', 'high', '{}'::jsonb, :digest) RETURNING id"
                ),
                {"digest": hashlib.sha256(b"new-arrival").digest()},
            ).scalar_one()
    finally:
        engine.dispose()
    cursor = page["next_cursor"]
    while cursor is not None:
        response = pb2_api.client.get(
            "/api/alerts", params={"limit": 2, "cursor": cursor}, headers=headers
        )
        assert response.status_code == 200
        page = response.json()
        seen.extend(item["id"] for item in page["items"])
        cursor = page["next_cursor"]
    assert len(seen) == len(set(seen)) == 5
    assert set(seen) == {str(identifier) for identifier in seeded_alerts}
    assert str(inserted) not in seen


def test_cursor_tie_breaker_returns_each_alert_once(
    pb2_api: PB2API, seeded_alerts: list[UUID]
) -> None:
    headers = pb2_api.login("analyst")
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE alerts SET created_at = now()"))
    finally:
        engine.dispose()
    seen = []
    cursor = None
    while True:
        params = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        response = pb2_api.client.get("/api/alerts", params=params, headers=headers)
        assert response.status_code == 200
        page = response.json()
        seen.extend(item["id"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == sorted((str(identifier) for identifier in seeded_alerts), reverse=True)


def test_filters_and_summary_use_database_time(pb2_api: PB2API, seeded_alerts: list[UUID]) -> None:
    headers = pb2_api.login("senior")
    client = pb2_api.client
    filtered = client.get(
        "/api/alerts",
        params={"severity": "HIGH", "source": "sensor", "src_ip": "2001:0db8::1"},
        headers=headers,
    )
    assert filtered.status_code == 200
    assert [item["id"] for item in filtered.json()["items"]] == [str(seeded_alerts[0])]
    agent = client.get("/api/alerts?agent=node-b&status=REVIEWED", headers=headers)
    assert [item["id"] for item in agent.json()["items"]] == [str(seeded_alerts[2])]
    injected = client.get("/api/alerts", params={"source": "sensor' OR 1=1 --"}, headers=headers)
    assert injected.status_code == 200 and injected.json()["items"] == []
    summary = client.get("/api/alerts/stats/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json() == {
        "by_severity": {"high": 2, "low": 2, "medium": 1},
        "by_status": {"open": 4, "reviewed": 1},
        "last_24h": 4,
    }


def test_detail_is_json_data_and_invalid_identifiers_are_not_disclosed(
    pb2_api: PB2API, seeded_alerts: list[UUID]
) -> None:
    headers = pb2_api.login("analyst")
    client = pb2_api.client
    response = client.get(f"/api/alerts/{seeded_alerts[0]}", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["raw"]["message"] == "<script>alert(1)</script>; DROP TABLE alerts"
    assert "fingerprint" not in response.json()
    assert client.get(f"/api/alerts/{uuid4()}", headers=headers).status_code == 404
    assert client.get("/api/alerts/not-a-uuid", headers=headers).status_code == 400
    assert client.get("/api/alerts?cursor=invalid", headers=headers).status_code == 400
    assert client.get("/api/alerts?limit=5", headers=headers).status_code == 422
    assert client.get("/api/alerts?src_ip=not-an-ip", headers=headers).status_code == 400
    assert (
        client.get("/api/alerts", params={"source": "x" * 129}, headers=headers).status_code == 400
    )


def test_disabled_user_cannot_continue_reading(pb2_api: PB2API, seeded_alerts: list[UUID]) -> None:
    headers = pb2_api.login("analyst")
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE users SET is_active = false WHERE username = 'analyst'"))
    finally:
        engine.dispose()
    assert pb2_api.client.get(f"/api/alerts/{seeded_alerts[0]}", headers=headers).status_code == 401
