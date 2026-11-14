"""Mock threat-intelligence endpoints and two-layer cache behavior."""

import asyncio

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import create_engine, text

from app.main import app
from app.threat_intel.providers import IPAddress, MockProvider, ProviderVerdict
from tests.integration.conftest import PB2API


def _row_count(api: PB2API) -> int:
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.connect() as db:
            return db.execute(text("SELECT count(*) FROM ioc_cache")).scalar_one()
    finally:
        engine.dispose()


def test_cache_writes_both_layers_and_repairs_tampered_redis(pb2_api: PB2API) -> None:
    headers = pb2_api.login("analyst")
    response = pb2_api.client.post(
        "/api/threat-intel/check-ip", headers=headers, json={"indicator": "10.0.0.5"}
    )
    assert response.status_code == 200
    verdict = response.json()
    assert verdict["indicator"] == "10.0.0.5"
    assert verdict["verdict"] == "suspicious" and verdict["score"] == 50
    assert verdict["mock"] is True and verdict["degraded"] is False
    assert verdict["sources"] == ["mock"] and verdict["expires_at"] is not None
    key = "threat-intel:ip:10.0.0.5"
    assert _row_count(pb2_api) == 1 and pb2_api.cache.exists(key) == 1
    assert 0 < pb2_api.cache.ttl(key) <= 60
    pb2_api.cache.set(key, b'{"verdict":"benign"}', ex=60)
    again = pb2_api.client.post(
        "/api/threat-intel/check-ip", headers=headers, json={"indicator": "10.0.0.5"}
    )
    assert again.status_code == 200 and again.json() == verdict
    assert pb2_api.cache.get(key) != b'{"verdict":"benign"}'
    assert again.headers["x-content-type-options"] == "nosniff"


def test_bulk_cap_validation_order_and_stats(pb2_api: PB2API) -> None:
    headers = pb2_api.login("senior")
    client = pb2_api.client
    path = "/api/threat-intel/bulk-check"
    too_many = {"indicators": ["127.0.0.1", "10.0.0.5", "2001:db8::1", "8.8.8.8"]}
    assert client.post(path, json=too_many, headers=headers).status_code == 422
    assert _row_count(pb2_api) == 0 and pb2_api.cache.dbsize() == 0
    assert (
        client.post(
            path, json={"indicators": ["127.0.0.1", "invalid"]}, headers=headers
        ).status_code
        == 400
    )
    assert _row_count(pb2_api) == 0 and pb2_api.cache.dbsize() == 0
    assert client.post(path, json={"indicators": []}, headers=headers).status_code == 422
    addresses = ["127.0.0.1", "10.0.0.5", "2001:0db8::1"]
    response = client.post(path, json={"indicators": addresses}, headers=headers)
    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["indicator"] for item in items] == ["127.0.0.1", "10.0.0.5", "2001:db8::1"]
    assert all(item["mock"] and not item["degraded"] for item in items)
    assert _row_count(pb2_api) == 3 and pb2_api.cache.dbsize() == 3
    stats = client.get("/api/threat-intel/cache/stats", headers=headers)
    assert stats.status_code == 200
    assert stats.json() == {"fresh": 3, "expired": 0, "redis_available": True}


def test_expired_database_row_is_not_revived_by_stale_redis(pb2_api: PB2API) -> None:
    headers = pb2_api.login("admin")
    path = "/api/threat-intel/check-ip"
    assert (
        pb2_api.client.post(path, json={"indicator": "10.0.0.5"}, headers=headers).status_code
        == 200
    )
    engine = create_engine(pb2_api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            db.execute(
                text(
                    "UPDATE ioc_cache SET cached_at = now() - interval '2 hours', "
                    "expires_at = now() - interval '1 hour' WHERE indicator = '10.0.0.5'"
                )
            )
        stats = pb2_api.client.get("/api/threat-intel/cache/stats", headers=headers).json()
        assert stats == {"fresh": 0, "expired": 1, "redis_available": True}
        assert pb2_api.cache.exists("threat-intel:ip:10.0.0.5") == 1
        result = pb2_api.client.post(path, json={"indicator": "10.0.0.5"}, headers=headers)
        assert result.status_code == 200 and result.json()["mock"] is True
        with engine.connect() as db:
            assert db.execute(
                text(
                    "SELECT expires_at > clock_timestamp() FROM ioc_cache "
                    "WHERE indicator='10.0.0.5'"
                )
            ).scalar_one()
    finally:
        engine.dispose()


def test_provider_timeout_is_degraded_unknown_and_never_cached(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SlowMock(MockProvider):
        async def check_ip(self, indicator: IPAddress) -> ProviderVerdict:
            await asyncio.sleep(1)
            return ProviderVerdict("benign", 0, ("mock",), True)

    headers = pb2_api.login("analyst")
    with monkeypatch.context() as patch:
        patch.setattr(app.state, "threat_provider", SlowMock())
        response = pb2_api.client.post(
            "/api/threat-intel/check-ip", headers=headers, json={"indicator": "8.8.8.8"}
        )
    assert response.status_code == 200
    assert response.json() == {
        "indicator": "8.8.8.8",
        "verdict": "unknown",
        "score": None,
        "sources": [],
        "mock": True,
        "degraded": True,
        "expires_at": None,
    }
    assert _row_count(pb2_api) == 0 and pb2_api.cache.dbsize() == 0


def test_cache_failure_is_unavailable_not_a_fabricated_verdict(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = pb2_api.login("analyst")

    def fail(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(app.state.redis_cache, "get", fail)
        response = pb2_api.client.post(
            "/api/threat-intel/check-ip", headers=headers, json={"indicator": "8.8.8.8"}
        )
    assert response.status_code == 503
    assert _row_count(pb2_api) == 0 and pb2_api.cache.dbsize() == 0


def test_redis_write_failure_rolls_back_database_cache(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = pb2_api.login("analyst")

    def fail(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(app.state.redis_cache, "set", fail)
        response = pb2_api.client.post(
            "/api/threat-intel/check-ip", headers=headers, json={"indicator": "10.0.0.5"}
        )
    assert response.status_code == 503
    assert _row_count(pb2_api) == 0 and pb2_api.cache.dbsize() == 0


def test_all_roles_can_use_intel_anonymous_cannot(pb2_api: PB2API) -> None:
    for role in ("admin", "senior", "analyst"):
        headers = pb2_api.login(role)
        assert (
            pb2_api.client.post(
                "/api/threat-intel/check-ip", headers=headers, json={"indicator": "127.0.0.1"}
            ).status_code
            == 200
        )
        assert (
            pb2_api.client.get("/api/threat-intel/cache/stats", headers=headers).status_code == 200
        )
    pb2_api.client.cookies.clear()
    assert pb2_api.client.get("/api/threat-intel/cache/stats").status_code == 401
    assert (
        pb2_api.client.post(
            "/api/threat-intel/check-ip", json={"indicator": "127.0.0.1"}
        ).status_code
        == 401
    )
