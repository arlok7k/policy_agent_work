"""Concurrent alert deduplication against the restricted PostgreSQL role."""

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.alerts.normalize import normalize_alert, store_alert


def test_concurrent_duplicate_alerts_store_one_row(runtime_url: str) -> None:
    engine = create_engine(runtime_url, hide_parameters=True)
    sessions = sessionmaker(engine, expire_on_commit=False)
    payload = {
        "source": "<img src=x onerror=alert(1)>",
        "rule_id": "'; DROP TABLE incidents; --",
        "severity": "HIGH",
        "raw": {"content": "<script>plain text</script>"},
    }
    alert = normalize_alert(payload, max_field_chars=128)

    def insert_one(_: int) -> tuple[object, bool]:
        with sessions.begin() as db:
            return store_alert(db, alert)

    try:
        with ThreadPoolExecutor(max_workers=6) as workers:
            results = list(workers.map(insert_one, range(6)))
        assert len({identifier for identifier, _ in results}) == 1
        assert sum(created for _, created in results) == 1
        with engine.connect() as db:
            row = db.execute(text("SELECT source, rule_id, severity, agent, raw FROM alerts")).one()
            assert row.source == payload["source"]
            assert row.rule_id == payload["rule_id"]
            assert row.severity == "high" and row.agent is None
            assert row.raw == payload["raw"]
            assert db.execute(text("SELECT count(*) FROM incidents")).scalar_one() == 0
    finally:
        engine.dispose()
