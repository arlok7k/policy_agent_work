"""PB2 schema constraints and reversible migrations on disposable PostgreSQL."""

import hashlib

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


def test_pb2_schema_columns_indexes_and_runtime_privileges(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        inspector = inspect(engine)
        expected = {
            "alerts": {
                "id",
                "source",
                "rule_id",
                "severity",
                "agent",
                "src_ip",
                "dst_ip",
                "raw",
                "status",
                "fingerprint",
                "created_at",
            },
            "incidents": {"id", "title", "description", "status", "created_at", "updated_at"},
            "incident_alerts": {"incident_id", "alert_id", "created_at"},
            "evidence": {"id", "incident_id", "alert_id", "kind", "data", "created_at"},
            "ioc_cache": {
                "indicator",
                "verdict",
                "score",
                "sources",
                "is_mock",
                "cached_at",
                "expires_at",
            },
        }
        for table, columns in expected.items():
            assert {column["name"] for column in inspector.get_columns(table)} == columns
        assert any(
            constraint["column_names"] == ["fingerprint"]
            for constraint in inspector.get_unique_constraints("alerts")
        )
        assert {index["name"] for index in inspector.get_indexes("evidence")} >= {
            "ix_evidence_incident_created_id"
        }
        allowed = {
            "alerts": {"SELECT", "INSERT", "UPDATE"},
            "incidents": {"SELECT", "INSERT", "UPDATE"},
            "incident_alerts": {"SELECT", "INSERT"},
            "evidence": {"SELECT", "INSERT"},
            "ioc_cache": {"SELECT", "INSERT", "UPDATE"},
        }
        with engine.connect() as db:
            for table, privileges in allowed.items():
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                    granted = db.execute(
                        text("SELECT has_table_privilege('hpb_app', :table, :privilege)"),
                        {"table": table, "privilege": privilege},
                    ).scalar_one()
                    assert granted is (privilege in privileges)
            for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
                assert not db.execute(
                    text("SELECT has_table_privilege('hpb_app', 'case_activities', :privilege)"),
                    {"privilege": privilege},
                ).scalar_one()
    finally:
        engine.dispose()


def test_alert_fingerprints_are_unique_and_raw_values_are_objects(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    digest = hashlib.sha256(b"same normalized test alert").digest()
    insert = text(
        "INSERT INTO alerts (source, rule_id, severity, raw, fingerprint) "
        "VALUES (:source, :rule, :severity, CAST(:raw AS jsonb), :fingerprint)"
    )
    values = {
        "source": "test",
        "rule": "rule-1",
        "severity": "high",
        "raw": '{"value":"<script>not executable</script>"}',
        "fingerprint": digest,
    }
    try:
        with engine.begin() as db:
            db.execute(insert, values)
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(insert, values)
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(insert, {**values, "fingerprint": b"short"})
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(insert, {**values, "fingerprint": bytes(32), "raw": "[]"})
        with engine.connect() as db:
            raw = db.execute(text("SELECT raw FROM alerts")).scalar_one()
            assert raw == {"value": "<script>not executable</script>"}
    finally:
        engine.dispose()


def test_evidence_cannot_reference_an_alert_from_a_different_incident(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            alert = db.execute(
                text(
                    "INSERT INTO alerts (source, rule_id, severity, raw, fingerprint) "
                    "VALUES ('test', 'rule', 'high', '{}'::jsonb, :digest) RETURNING id"
                ),
                {"digest": bytes(32)},
            ).scalar_one()
            first = db.execute(text("INSERT INTO incidents (title) VALUES ('first') RETURNING id"))
            first_id = first.scalar_one()
            second_id = db.execute(
                text("INSERT INTO incidents (title) VALUES ('second') RETURNING id")
            ).scalar_one()
            db.execute(
                text(
                    "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (:incident, :alert)"
                ),
                {"incident": first_id, "alert": alert},
            )
            db.execute(
                text(
                    "INSERT INTO evidence (incident_id, alert_id, kind, data) "
                    "VALUES (:incident, :alert, 'test', '{}'::jsonb)"
                ),
                {"incident": first_id, "alert": alert},
            )
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(
                text(
                    "INSERT INTO evidence (incident_id, alert_id, kind, data) "
                    "VALUES (:incident, :alert, 'test', '{}'::jsonb)"
                ),
                {"incident": second_id, "alert": alert},
            )
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM evidence")).scalar_one() == 1
    finally:
        engine.dispose()


def test_ioc_cache_rejects_invalid_score_sources_and_expiry(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    statement = text(
        "INSERT INTO ioc_cache (indicator, verdict, score, sources, is_mock, expires_at) "
        "VALUES (:indicator, 'unknown', :score, CAST(:sources AS jsonb), true, "
        "now() + :seconds * interval '1 second')"
    )
    try:
        with engine.begin() as db:
            db.execute(
                statement, {"indicator": "192.0.2.1", "score": 42, "sources": "[]", "seconds": 60}
            )
        for bad in (
            {"indicator": "a", "score": 101, "sources": "[]", "seconds": 60},
            {"indicator": "b", "score": -1, "sources": "[]", "seconds": 60},
            {"indicator": "c", "score": None, "sources": "{}", "seconds": 60},
            {"indicator": "d", "score": None, "sources": "[]", "seconds": -1},
        ):
            with pytest.raises(IntegrityError), engine.begin() as db:
                db.execute(statement, bad)
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM ioc_cache")).scalar_one() == 1
    finally:
        engine.dispose()


def test_pb2_revisions_downgrade_and_reupgrade_individually(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        command.downgrade(Config("alembic.ini"), "004_alerts_incidents")
        names = set(inspect(engine).get_table_names())
        assert "ioc_cache" not in names
        assert {"alerts", "incidents", "incident_alerts", "evidence"} <= names
        command.downgrade(Config("alembic.ini"), "003_case_activities")
        names = set(inspect(engine).get_table_names())
        assert not ({"alerts", "incidents", "incident_alerts", "evidence", "ioc_cache"} & names)
        assert {"roles", "users", "auth_sessions", "case_activities"} <= names
        command.upgrade(Config("alembic.ini"), "head")
        names = set(inspect(engine).get_table_names())
        assert {"alerts", "incidents", "incident_alerts", "evidence", "ioc_cache"} <= names
        with engine.connect() as db:
            assert db.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
                "005_ioc_cache"
            )
    finally:
        engine.dispose()
