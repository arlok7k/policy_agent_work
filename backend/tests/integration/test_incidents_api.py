"""Incident investigations, transactional audit and shared-tenant ID boundaries."""

import asyncio
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text

from app.main import app
from app.threat_intel.providers import IPAddress, MockProvider, ProviderVerdict
from tests.integration.conftest import PB2API


@pytest.fixture
def alerts(pb2_api: PB2API) -> list[UUID]:
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    identifiers = []
    try:
        with engine.begin() as db:
            for index, address in enumerate(("10.0.0.5", None, "2001:db8::1", "127.0.0.1")):
                identifiers.append(
                    db.execute(
                        text(
                            "INSERT INTO alerts (source, rule_id, severity, src_ip, raw, "
                            "fingerprint) VALUES (:source, :rule, 'high', CAST(:ip AS inet), "
                            "CAST(:raw AS jsonb), :digest) RETURNING id"
                        ),
                        {
                            "source": "<script>plain source</script>",
                            "rule": f"rule-{index}",
                            "ip": address,
                            "raw": '{"governance_canary":"DO_NOT_SEND_GOVERNANCE"}',
                            "digest": hashlib.sha256(f"investigation-{index}".encode()).digest(),
                        },
                    ).scalar_one()
                )
        return identifiers
    finally:
        engine.dispose()


def _counts(api: PB2API) -> tuple[int, int, int, int]:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            return db.execute(
                text(
                    "SELECT (SELECT count(*) FROM incidents), "
                    "(SELECT count(*) FROM incident_alerts), "
                    "(SELECT count(*) FROM evidence), "
                    "(SELECT count(*) FROM case_activities "
                    "WHERE action IN ('incident.create', 'alert.investigate'))"
                )
            ).one()
    finally:
        engine.dispose()


def test_create_list_detail_and_cursor_are_shared_plain_data(
    pb2_api: PB2API, alerts: list[UUID]
) -> None:
    client = pb2_api.client
    ids = []
    title = "<script>plain</script>'; DROP TABLE incidents; --"
    for index, role in enumerate(("admin", "senior", "analyst")):
        headers = pb2_api.login(role)
        response = client.post(
            "/api/incidents",
            headers=headers,
            json={
                "title": title,
                "description": "<img src=x onerror=alert(1)>",
                "alert_ids": [str(alerts[index])],
            },
        )
        assert response.status_code == 201
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        result = response.json()
        assert result["title"] == title and result["description"] == "<img src=x onerror=alert(1)>"
        assert result["status"] == "open" and result["alert_ids"] == [str(alerts[index])]
        ids.append(result["id"])
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE incidents SET created_at = now()"))
    finally:
        engine.dispose()
    # Every active role may read incidents created by any of the others.
    for role in ("admin", "senior", "analyst"):
        headers = pb2_api.login(role)
        for identifier in ids:
            result = client.get(f"/api/incidents/{identifier}", headers=headers)
            assert result.status_code == 200 and result.json()["title"] == title
    seen = []
    cursor = None
    while True:
        params = {"limit": 1}
        if cursor:
            params["cursor"] = cursor
        result = client.get("/api/incidents", headers=headers, params=params)
        assert result.status_code == 200
        seen.extend(item["id"] for item in result.json()["items"])
        cursor = result.json()["next_cursor"]
        if cursor is None:
            break
    assert seen == sorted(ids, reverse=True)
    assert client.get("/api/incidents?cursor=invalid", headers=headers).status_code == 400
    assert client.get("/api/incidents?limit=5", headers=headers).status_code == 422
    assert _counts(pb2_api) == (3, 3, 0, 3)


def test_incident_input_bounds_missing_alert_and_atomic_failures(
    pb2_api: PB2API, alerts: list[UUID]
) -> None:
    headers = pb2_api.login("analyst")
    path = "/api/incidents"
    invalid = [
        ({"title": " "}, 400),
        ({"title": "x" * 129}, 400),
        ({"title": "valid", "description": "x" * 129}, 400),
        ({"title": "valid\u0000bad"}, 400),
        ({"title": "valid", "unknown": "field"}, 400),
        ({"title": "valid", "alert_ids": [str(alerts[0]), str(alerts[0])]}, 400),
        ({"title": "valid", "alert_ids": [str(item) for item in alerts]}, 422),
        ({"title": "valid", "alert_ids": [str(alerts[0]), str(uuid4())]}, 404),
        ({"title": "valid", "alert_ids": ["not-a-uuid"]}, 400),
    ]
    for body, expected in invalid:
        assert pb2_api.client.post(path, headers=headers, json=body).status_code == expected
        assert _counts(pb2_api) == (0, 0, 0, 0)
    assert pb2_api.client.get(f"/api/incidents/{uuid4()}", headers=headers).status_code == 404
    assert pb2_api.client.get("/api/incidents/not-a-uuid", headers=headers).status_code == 400
    assert (
        pb2_api.client.get(f"/api/incidents/{uuid4()}/evidence", headers=headers).status_code == 404
    )


def test_investigation_creates_reuses_and_records_enrichment_and_audit(
    pb2_api: PB2API, alerts: list[UUID]
) -> None:
    headers = pb2_api.login("analyst")
    client = pb2_api.client
    path = f"/api/alerts/{alerts[0]}/investigate"
    result = client.post(path, headers=headers, json={})
    assert result.status_code == 200
    body = result.json()
    incident_id = body["incident"]["id"]
    assert body["incident"]["alert_ids"] == [str(alerts[0])]
    assert body["intelligence"]["indicator"] == "10.0.0.5"
    assert body["intelligence"]["verdict"] == "suspicious"
    assert body["intelligence"]["mock"] is True and body["intelligence"]["degraded"] is False
    assert body["ai"]["mock"] is True and body["ai"]["alert_id"] == str(alerts[0])
    assert "<script>plain source</script>" in body["ai"]["summary"]
    assert "DO_NOT_SEND_GOVERNANCE" not in result.text
    alert = client.get(f"/api/alerts/{alerts[0]}", headers=headers)
    assert alert.json()["status"] == "investigating"
    repeated = client.post(path, headers=headers, json={})
    assert repeated.status_code == 200 and repeated.json()["incident"]["id"] == incident_id
    page = client.get(f"/api/incidents/{incident_id}/evidence?limit=2", headers=headers).json()
    records = page["items"]
    assert page["next_cursor"]
    page2 = client.get(
        f"/api/incidents/{incident_id}/evidence",
        headers=headers,
        params={"limit": 2, "cursor": page["next_cursor"]},
    ).json()
    records += page2["items"]
    assert len(records) == len({item["id"] for item in records}) == 4
    assert {item["kind"] for item in records} == {"ai_comprehensive", "threat_intel"}
    assert all(
        item["incident_id"] == incident_id and item["alert_id"] == str(alerts[0])
        for item in records
    )
    assert "DO_NOT_SEND_GOVERNANCE" not in str(records)
    assert _counts(pb2_api) == (1, 1, 4, 2)
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            events = db.execute(
                text(
                    "SELECT username, target, details FROM case_activities "
                    "WHERE action='alert.investigate' ORDER BY id"
                )
            ).all()
            assert [row.username for row in events] == ["analyst", "analyst"]
            assert all(row.target == f"incident:{incident_id}" for row in events)
            assert [row.details["incident_created"] for row in events] == [True, False]
            assert all(row.details["mock"] is True for row in events)
            assert db.execute(text("SELECT count(*) FROM ioc_cache")).scalar_one() == 1
    finally:
        engine.dispose()


def test_explicit_incident_linking_evidence_scope_and_bounds(
    pb2_api: PB2API, alerts: list[UUID]
) -> None:
    headers = pb2_api.login("admin")
    client = pb2_api.client
    first = client.post("/api/incidents", headers=headers, json={"title": "first"}).json()["id"]
    second = client.post("/api/incidents", headers=headers, json={"title": "second"}).json()["id"]
    for identifier in alerts[:3]:
        response = client.post(
            f"/api/alerts/{identifier}/investigate", headers=headers, json={"incident_id": first}
        )
        assert response.status_code == 200 and response.json()["incident"]["id"] == first
    full = client.post(
        f"/api/alerts/{alerts[3]}/investigate", headers=headers, json={"incident_id": first}
    )
    assert full.status_code == 422
    assert (
        client.post(
            f"/api/alerts/{alerts[0]}/investigate", headers=headers, json={"incident_id": first}
        ).status_code
        == 200
    )
    other = client.post(
        f"/api/alerts/{alerts[3]}/investigate", headers=headers, json={"incident_id": second}
    )
    assert other.status_code == 200
    # Knowledge of another valid ID does not bypass incident scoping of evidence.
    first_page = client.get(f"/api/incidents/{first}/evidence?limit=4", headers=headers).json()
    other_page = client.get(f"/api/incidents/{second}/evidence", headers=headers).json()
    assert first_page["items"] and len(other_page["items"]) == 2
    assert all(item["incident_id"] == first for item in first_page["items"])
    assert all(item["incident_id"] == second for item in other_page["items"])
    assert not (
        {item["id"] for item in first_page["items"]} & {item["id"] for item in other_page["items"]}
    )
    assert (
        client.get(f"/api/incidents/{first}/evidence?cursor=invalid", headers=headers).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/alerts/{uuid4()}/investigate", headers=headers, json={"incident_id": first}
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/alerts/{alerts[3]}/investigate",
            headers=headers,
            json={"incident_id": str(uuid4())},
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/alerts/{alerts[3]}/investigate", headers=headers, json={"unexpected": True}
        ).status_code
        == 400
    )
    assert _counts(pb2_api) == (2, 4, 10, 7)


def test_no_indicator_and_timeout_do_not_invent_a_verdict(
    pb2_api: PB2API, alerts: list[UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = pb2_api.login("senior")
    client = pb2_api.client
    no_ip = client.post(f"/api/alerts/{alerts[1]}/investigate", headers=headers, json={})
    assert no_ip.status_code == 200 and no_ip.json()["intelligence"] is None
    assert no_ip.json()["ai"]["analysis"]["indicator_present"] is False
    evidence = client.get(
        f"/api/incidents/{no_ip.json()['incident']['id']}/evidence", headers=headers
    ).json()["items"]
    assert next(item for item in evidence if item["kind"] == "threat_intel")["data"] == {
        "checked": False,
        "reason": "no_indicator",
    }

    class SlowMock(MockProvider):
        async def check_ip(self, indicator: IPAddress) -> ProviderVerdict:
            await asyncio.sleep(1)
            return ProviderVerdict("benign", 0, ("mock",), True)

    with monkeypatch.context() as patch:
        patch.setattr(app.state, "threat_provider", SlowMock())
        degraded = client.post(f"/api/alerts/{alerts[2]}/investigate", headers=headers, json={})
    assert degraded.status_code == 200
    assert degraded.json()["intelligence"] == {
        "indicator": "2001:db8::1",
        "verdict": "unknown",
        "score": None,
        "sources": [],
        "mock": True,
        "degraded": True,
        "expires_at": None,
    }
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM ioc_cache")).scalar_one() == 0
            details = (
                db.execute(
                    text(
                        "SELECT details FROM case_activities "
                        "WHERE action='alert.investigate' ORDER BY id"
                    )
                )
                .scalars()
                .all()
            )
            assert all(value["intelligence_degraded"] is True for value in details)
    finally:
        engine.dispose()


def test_audit_failure_rolls_back_every_database_mutation_and_orphan_cache_is_ignored(
    pb2_api: PB2API, alerts: list[UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = pb2_api.login("analyst")
    path = f"/api/alerts/{alerts[0]}/investigate"
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        result = pb2_api.client.post(path, headers=headers, json={})
        assert result.status_code == 503
        assert _counts(pb2_api) == (0, 0, 0, 0)
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM ioc_cache")).scalar_one() == 0
            assert (
                db.execute(
                    text("SELECT status FROM alerts WHERE id=:id"), {"id": alerts[0]}
                ).scalar_one()
                == "open"
            )
        assert pb2_api.cache.exists("threat-intel:ip:10.0.0.5") == 1
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()

    class CountingMock(MockProvider):
        calls = 0

        async def check_ip(self, indicator: IPAddress) -> ProviderVerdict:
            self.calls += 1
            return await super().check_ip(indicator)

    provider = CountingMock()
    with monkeypatch.context() as patch:
        patch.setattr(app.state, "threat_provider", provider)
        assert pb2_api.client.post(path, headers=headers, json={}).status_code == 200
    assert provider.calls == 1
    assert _counts(pb2_api) == (1, 1, 2, 1)


def test_concurrent_investigations_of_same_alert_make_only_one_incident(
    pb2_api: PB2API, alerts: list[UUID]
) -> None:
    credentials = [pb2_api.login(role) for role in ("admin", "senior", "analyst")]
    path = f"/api/alerts/{alerts[0]}/investigate"
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(pb2_api.client.post, path, headers=auth, json={})
            for auth in credentials
        ]
        responses = [future.result(timeout=15) for future in futures]
    assert [response.status_code for response in responses] == [200, 200, 200]
    assert len({response.json()["incident"]["id"] for response in responses}) == 1
    assert _counts(pb2_api) == (1, 1, 6, 3)


@pytest.mark.parametrize("operation", ["create", "investigate"])
def test_disabled_actor_is_rechecked_inside_transaction_before_mutation(
    pb2_api: PB2API, alerts: list[UUID], monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    import app.incidents.service as service

    headers = pb2_api.login("analyst")
    reached = threading.Event()
    resume = threading.Event()
    original = service.lock_authorized_actor

    def pause_before_recheck(*args: object, **kwargs: object) -> object:
        reached.set()
        assert resume.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "lock_authorized_actor", pause_before_recheck)
    path = "/api/incidents" if operation == "create" else f"/api/alerts/{alerts[0]}/investigate"
    body = {"title": "not persisted"} if operation == "create" else {}
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(pb2_api.client.post, path, headers=headers, json=body)
            try:
                assert reached.wait(10)
                with engine.begin() as db:
                    db.execute(text("UPDATE users SET is_active = false WHERE username='analyst'"))
            finally:
                resume.set()
            assert future.result(timeout=15).status_code == 401
        assert _counts(pb2_api) == (0, 0, 0, 0)
    finally:
        engine.dispose()
