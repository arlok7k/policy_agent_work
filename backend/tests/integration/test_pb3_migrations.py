"""PB3 schema invariants and reversible migrations on disposable PostgreSQL."""

from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, IntegrityError

from tests.integration.conftest import PB2Account


def _incident(engine: Engine) -> UUID:
    with engine.begin() as db:
        return db.execute(
            text("INSERT INTO incidents (title) VALUES ('response case') RETURNING id")
        ).scalar_one()


def _action(engine: Engine, incident_id: UUID, requester: UUID, *, level: int = 3) -> UUID:
    mode = "manual" if level == 3 else "automatic"
    ttl = 3600 if level == 2 else None
    with engine.begin() as db:
        return db.execute(
            text(
                "INSERT INTO response_actions "
                "(incident_id, action_type, target, params, level, approval_mode, "
                "requested_by, ttl_seconds) "
                "VALUES (:incident, 'test_action', '{\"agent_id\":\"004\"}'::jsonb, '{}'::jsonb, "
                ":level, :mode, :requester, :ttl) RETURNING id"
            ),
            {
                "incident": incident_id,
                "level": level,
                "mode": mode,
                "requester": requester,
                "ttl": ttl,
            },
        ).scalar_one()


def test_response_schema_seed_facts_and_runtime_privileges(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        inspector = inspect(engine)
        expected = {
            "response_actions": {
                "id",
                "incident_id",
                "action_type",
                "target",
                "params",
                "level",
                "approval_mode",
                "status",
                "requested_by",
                "decided_by",
                "ttl_seconds",
                "ttl_expires_at",
                "rollback_of_id",
                "rollback_requested_by",
                "rollback_requested_at",
                "created_at",
                "updated_at",
            },
            "response_approvals": {
                "id",
                "action_id",
                "approver_id",
                "decision",
                "reason",
                "decided_at",
            },
            "executed_commands": {
                "id",
                "action_id",
                "phase",
                "connector",
                "command",
                "target",
                "params",
                "initiator",
                "simulated",
                "executed_at",
            },
            "kill_switch_state": {"id", "engaged", "changed_by", "changed_at"},
            "response_safeguard_rule": {"code", "kind", "value"},
        }
        for table, columns in expected.items():
            assert {column["name"] for column in inspector.get_columns(table)} == columns
        approval_uniques = {
            tuple(item["column_names"])
            for item in inspector.get_unique_constraints("response_approvals")
        }
        assert {("action_id", "approver_id"), ("action_id",)} <= approval_uniques
        assert any(
            item["column_names"] == ["action_id", "phase"]
            for item in inspector.get_unique_constraints("executed_commands")
        )
        assert "ix_response_actions_ttl_due" in {
            index["name"] for index in inspector.get_indexes("response_actions")
        }
        allowed = {
            "response_actions": {"SELECT", "INSERT", "UPDATE"},
            "response_approvals": {"SELECT", "INSERT"},
            "executed_commands": {"SELECT", "INSERT"},
            "kill_switch_state": {"SELECT", "UPDATE"},
            "response_safeguard_rule": {"SELECT"},
        }
        with engine.connect() as db:
            assert db.execute(text("SELECT id, engaged FROM kill_switch_state")).all() == [
                (1, False)
            ]
            facts = set(db.execute(text("SELECT kind, value FROM response_safeguard_rule")).all())
            assert facts == {
                ("agent", "000"),
                ("network", "10.0.0.0/8"),
                ("network", "172.16.0.0/12"),
                ("network", "192.168.0.0/16"),
                ("network", "127.0.0.0/8"),
                ("network", "169.254.0.0/16"),
                ("network", "::1/128"),
                ("network", "fe80::/10"),
                ("shell", "baseline"),
            }
            for table, privileges in allowed.items():
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                    granted = db.execute(
                        text("SELECT has_table_privilege('hpb_app', :table, :privilege)"),
                        {"table": table, "privilege": privilege},
                    ).scalar_one()
                    assert granted is (privilege in privileges)
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(text("INSERT INTO kill_switch_state (id, engaged) VALUES (2, true)"))
        with pytest.raises(DBAPIError) as error, engine.begin() as db:
            db.execute(text("DELETE FROM kill_switch_state"))
        assert getattr(error.value.orig, "sqlstate", None) == "55000"
    finally:
        engine.dispose()


def test_action_constraints_reject_invalid_initial_modes_ttls_and_incidents(
    migrated_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        incident_id = _incident(engine)
        requester = pb2_accounts["analyst"].id
        assert _action(engine, incident_id, requester, level=2)
        insert = text(
            "INSERT INTO response_actions "
            "(incident_id, action_type, target, params, level, approval_mode, "
            "status, requested_by, ttl_seconds) "
            "VALUES (:incident, 'test', CAST(:target AS jsonb), '{}'::jsonb, :level, :mode, "
            ":status, :requester, :ttl)"
        )
        base = {
            "incident": incident_id,
            "target": "{}",
            "level": 2,
            "mode": "automatic",
            "status": "requested",
            "requester": requester,
            "ttl": 3600,
        }
        invalid = (
            {"ttl": None},
            {"ttl": 0},
            {"level": 3, "ttl": None, "mode": "automatic"},
            {"level": 0, "ttl": None, "mode": "automatic"},
            {"target": "[]"},
            {"status": "approved"},
            {"incident": uuid4()},
        )
        for changes in invalid:
            with pytest.raises(DBAPIError), engine.begin() as db:
                db.execute(insert, {**base, **changes})
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM response_actions")).scalar_one() == 1
    finally:
        engine.dispose()


def test_database_prevents_self_approval_duplicate_decisions_and_tampering(
    migrated_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        requester, approver, other = (
            pb2_accounts[key].id for key in ("admin", "senior", "analyst")
        )
        action = _action(engine, _incident(engine), requester)
        with engine.begin() as db:
            db.execute(
                text("UPDATE response_actions SET status='pending_approval' WHERE id=:id"),
                {"id": action},
            )
        insert = text(
            "INSERT INTO response_approvals (action_id, approver_id, decision) "
            "VALUES (:action, :approver, 'approved')"
        )
        with pytest.raises(DBAPIError) as error, engine.begin() as db:
            db.execute(insert, {"action": action, "approver": requester})
        assert getattr(error.value.orig, "sqlstate", None) == "23514"
        with pytest.raises(DBAPIError), engine.begin() as db:
            db.execute(
                text(
                    "UPDATE response_actions SET status='approved', decided_by=:actor WHERE id=:id"
                ),
                {"actor": approver, "id": action},
            )
        with engine.begin() as db:
            db.execute(insert, {"action": action, "approver": approver})
        for actor in (approver, other):
            with pytest.raises(IntegrityError), engine.begin() as db:
                db.execute(insert, {"action": action, "approver": actor})
        with engine.begin() as db:
            db.execute(
                text(
                    "UPDATE response_actions SET status='approved', decided_by=:actor WHERE id=:id"
                ),
                {"actor": approver, "id": action},
            )
        for sql in (
            "UPDATE response_actions SET target='{}'::jsonb WHERE id=:id",
            "UPDATE response_actions SET requested_by=decided_by WHERE id=:id",
            "UPDATE response_actions SET status='executed' WHERE id=:id",
        ):
            with pytest.raises(DBAPIError) as error, engine.begin() as db:
                db.execute(text(sql), {"id": action})
            assert getattr(error.value.orig, "sqlstate", None) == "23514"
        with engine.connect() as db:
            assert (
                db.execute(
                    text("SELECT status FROM response_actions WHERE id=:id"), {"id": action}
                ).scalar_one()
                == "approved"
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("table", ["response_approvals", "executed_commands"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_response_logs_are_append_only_even_for_owner(
    migrated_url: str, pb2_accounts: dict[str, PB2Account], table: str, operation: str
) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    statements = {
        ("response_approvals", "UPDATE"): "UPDATE response_approvals SET decision='rejected'",
        ("response_approvals", "DELETE"): "DELETE FROM response_approvals",
        ("response_approvals", "TRUNCATE"): "TRUNCATE response_approvals",
        ("executed_commands", "UPDATE"): "UPDATE executed_commands SET command='changed'",
        ("executed_commands", "DELETE"): "DELETE FROM executed_commands",
        ("executed_commands", "TRUNCATE"): "TRUNCATE executed_commands",
    }
    try:
        action = _action(engine, _incident(engine), pb2_accounts["admin"].id)
        with engine.begin() as db:
            db.execute(
                text("UPDATE response_actions SET status='pending_approval' WHERE id=:id"),
                {"id": action},
            )
            db.execute(
                text(
                    "INSERT INTO response_approvals (action_id, approver_id, decision) "
                    "VALUES (:id, :actor, 'approved')"
                ),
                {"id": action, "actor": pb2_accounts["senior"].id},
            )
            db.execute(
                text(
                    "INSERT INTO executed_commands "
                    "(action_id, phase, connector, command, target, params, initiator) "
                    "VALUES (:id, 'execute', 'simulation', 'test', '{}'::jsonb, '{}'::jsonb, "
                    "'user:test')"
                ),
                {"id": action},
            )
        with pytest.raises(DBAPIError) as error, engine.begin() as db:
            db.execute(text(statements[(table, operation)]))
        assert getattr(error.value.orig, "sqlstate", None) == "55000"
        with engine.connect() as db:
            counts = {
                "response_approvals": db.execute(text("SELECT count(*) FROM response_approvals")),
                "executed_commands": db.execute(text("SELECT count(*) FROM executed_commands")),
            }
            assert counts[table].scalar_one() == 1
    finally:
        engine.dispose()


def test_pb3_revisions_downgrade_and_reupgrade_individually(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        command.downgrade(Config("alembic.ini"), "007_response_audit")
        names = set(inspect(engine).get_table_names())
        assert {"response_actions", "response_approvals", "executed_commands"} <= names
        assert not ({"kill_switch_state", "response_safeguard_rule"} & names)
        command.downgrade(Config("alembic.ini"), "006_response_actions")
        names = set(inspect(engine).get_table_names())
        assert "response_actions" in names
        assert not ({"response_approvals", "executed_commands"} & names)
        command.downgrade(Config("alembic.ini"), "005_ioc_cache")
        names = set(inspect(engine).get_table_names())
        assert "response_actions" not in names
        assert {"alerts", "incidents", "ioc_cache", "case_activities"} <= names
        command.upgrade(Config("alembic.ini"), "head")
        names = set(inspect(engine).get_table_names())
        assert {
            "response_actions",
            "response_approvals",
            "executed_commands",
            "kill_switch_state",
            "response_safeguard_rule",
        } <= names
        with engine.connect() as db:
            assert (
                db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "008_response_safety"
            )
    finally:
        engine.dispose()


def _baseline_schema(engine: Engine) -> dict[str, object]:
    tables = (
        "roles",
        "users",
        "auth_sessions",
        "api_keys",
        "auth_login_throttle",
        "case_activities",
        "alerts",
        "incidents",
        "incident_alerts",
        "evidence",
        "ioc_cache",
    )
    inspector = inspect(engine)
    snapshot: dict[str, object] = {}
    with engine.connect() as db:
        for table in tables:
            columns = tuple(
                (item["name"], str(item["type"]), item["nullable"], item["default"])
                for item in inspector.get_columns(table)
            )
            constraints = tuple(
                db.execute(
                    text(
                        "SELECT con.conname, pg_get_constraintdef(con.oid) "
                        "FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid "
                        "JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname=current_schema() AND c.relname=:table ORDER BY con.conname"
                    ),
                    {"table": table},
                ).all()
            )
            indexes = tuple(
                db.execute(
                    text(
                        "SELECT indexname, indexdef FROM pg_indexes "
                        "WHERE schemaname=current_schema() AND tablename=:table ORDER BY indexname"
                    ),
                    {"table": table},
                ).all()
            )
            triggers = tuple(
                db.execute(
                    text(
                        "SELECT t.tgname, pg_get_triggerdef(t.oid) FROM pg_trigger t "
                        "JOIN pg_class c ON c.oid=t.tgrelid "
                        "JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname=current_schema() AND c.relname=:table "
                        "AND NOT t.tgisinternal ORDER BY t.tgname"
                    ),
                    {"table": table},
                ).all()
            )
            privileges = tuple(
                db.execute(
                    text("SELECT has_table_privilege('hpb_app', :table, :privilege)"),
                    {"table": table, "privilege": privilege},
                ).scalar_one()
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
            )
            snapshot[table] = (columns, constraints, indexes, triggers, privileges)
    return snapshot


def test_pb3_migrations_leave_the_pb1_pb2_schema_unchanged(migrated_url: str) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        command.downgrade(Config("alembic.ini"), "005_ioc_cache")
        before = _baseline_schema(engine)
        command.upgrade(Config("alembic.ini"), "head")
        after = _baseline_schema(engine)
        assert after == before
    finally:
        engine.dispose()


def test_new_rollback_actor_can_replace_a_lost_or_revoked_request(
    migrated_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        action = _action(engine, _incident(engine), pb2_accounts["analyst"].id, level=2)
        with engine.begin() as db:
            for status in ("approved", "executing"):
                db.execute(
                    text("UPDATE response_actions SET status=:status WHERE id=:id"),
                    {"status": status, "id": action},
                )
            db.execute(
                text(
                    "UPDATE response_actions SET status='executed', "
                    "ttl_expires_at=clock_timestamp()+interval '1 hour' WHERE id=:id"
                ),
                {"id": action},
            )
            for name in ("admin", "senior"):
                db.execute(
                    text(
                        "UPDATE response_actions SET rollback_requested_by=:actor, "
                        "rollback_requested_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"actor": pb2_accounts[name].id, "id": action},
                )
        with engine.connect() as db:
            current = db.execute(
                text("SELECT rollback_requested_by FROM response_actions WHERE id=:id"),
                {"id": action},
            ).scalar_one()
            assert current == pb2_accounts["senior"].id
        with pytest.raises(DBAPIError), engine.begin() as db:
            db.execute(
                text(
                    "UPDATE response_actions SET rollback_requested_by=NULL, "
                    "rollback_requested_at=NULL WHERE id=:id"
                ),
                {"id": action},
            )
        with engine.begin() as db:
            db.execute(
                text("UPDATE response_actions SET status='rolled_back' WHERE id=:id"),
                {"id": action},
            )
        with pytest.raises(DBAPIError), engine.begin() as db:
            db.execute(
                text(
                    "UPDATE response_actions SET rollback_requested_by=:actor, "
                    "rollback_requested_at=clock_timestamp() WHERE id=:id"
                ),
                {"actor": pb2_accounts["admin"].id, "id": action},
            )
    finally:
        engine.dispose()
