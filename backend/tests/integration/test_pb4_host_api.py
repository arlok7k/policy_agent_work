"""PB4 host-only presentation settings and real response-log read APIs."""

from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.auth.legacy_policy import load_legacy_policy
from app.core.pb3_config import load_pb3_settings
from app.main import app
from app.response.execution import execute_approved
from tests.contract.assertions import assert_response_contract
from tests.integration.conftest import PB2API
from tests.sensitive import Redacted


def _send(
    api: PB2API, method: str, path: str, headers: dict[str, Redacted], body: object = None
) -> object:
    api.client.cookies.clear()
    return api.client.request(method, path, headers=headers, **({"json": body} if body else {}))


def test_settings_are_admin_only_strict_csrf_protected_and_audited(pb2_api: PB2API) -> None:
    api = pb2_api
    admin, senior, analyst = (api.login(role) for role in ("admin", "senior", "analyst"))
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        for headers, expected in (({}, 401), (analyst, 403), (senior, 403)):
            assert _send(api, "GET", "/api/settings", headers).status_code == expected
            assert (
                _send(api, "PATCH", "/api/settings", headers, {"display_name": "No"}).status_code
                == expected
            )
        assert _send(api, "GET", "/api/presentation", {}).status_code == 401
        presentation = _send(api, "GET", "/api/presentation", analyst)
        assert presentation.status_code == 200
        assert set(presentation.json()) == {"display_name", "default_direction"}
        assert_response_contract("GET", "/api/presentation", presentation)
        response = _send(api, "GET", "/api/settings", admin)
        assert response.status_code == 200
        assert response.json()["display_name"] == "SMART SOC"
        assert response.json()["default_direction"] == "rtl"
        assert response.headers["Cache-Control"] == "no-store"
        assert_response_contract("GET", "/api/settings", response)
        assert (
            _send(
                api,
                "PATCH",
                "/api/settings",
                {"Cookie": admin["Cookie"]},
                {"display_name": "No CSRF"},
            ).status_code
            == 403
        )
        for body, expected in (
            ({"operational_policy": True}, 400),
            ({"default_direction": "sideways"}, 400),
            ({"display_name": None}, 400),
            ({"display_name": "   "}, 422),
            ({"display_name": "x" * 129}, 422),
            ({"display_name": "bad\nname"}, 422),
        ):
            assert _send(api, "PATCH", "/api/settings", admin, body).status_code == expected
        response = _send(
            api,
            "PATCH",
            "/api/settings",
            admin,
            {"display_name": "  Blue team  ", "default_direction": "ltr"},
        )
        assert response.status_code == 200
        assert response.json()["display_name"] == "Blue team"
        assert response.json()["default_direction"] == "ltr"
        assert_response_contract("PATCH", "/api/settings", response)
        shared = _send(api, "GET", "/api/presentation", analyst)
        assert shared.json() == {"display_name": "Blue team", "default_direction": "ltr"}
        with engine.connect() as db:
            activity = db.execute(
                text("SELECT username, details FROM case_activities WHERE action='settings.update'")
            ).one()
            assert activity.username == "admin"
            assert activity.details["fields"] == ["default_direction", "display_name"]
            assert activity.details["before"]["display_name"] == "SMART SOC"
            assert activity.details["after"]["display_name"] == "Blue team"
        # Audit insertion and settings change are a single fail-closed transaction.
        with engine.begin() as db:
            db.execute(text("REVOKE INSERT ON case_activities FROM hpb_app"))
        assert (
            _send(api, "PATCH", "/api/settings", admin, {"display_name": "No audit"}).status_code
            == 503
        )
        with engine.connect() as db:
            assert (
                db.execute(text("SELECT display_name FROM host_settings")).scalar_one()
                == "Blue team"
            )
    finally:
        with engine.begin() as db:
            db.execute(text("GRANT INSERT ON case_activities TO hpb_app"))
        engine.dispose()


def test_settings_fail_closed_if_policy_is_accidentally_permissive(
    pb2_api: PB2API, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyst = pb2_api.login("analyst")
    policy = dict(app.state.legacy_policy)
    policy["settings"] = ("analyst", "admin")
    monkeypatch.setitem(app.state._state, "legacy_policy", policy)
    assert _send(pb2_api, "GET", "/api/settings", analyst).status_code == 403
    assert (
        _send(pb2_api, "PATCH", "/api/settings", analyst, {"display_name": "No"}).status_code == 403
    )


def test_switch_read_and_command_log_return_actual_executions(pb2_api: PB2API) -> None:
    api = pb2_api
    analyst, admin = (api.login(role) for role in ("analyst", "admin"))
    assert _send(api, "GET", "/api/response/commands", {}).status_code == 401
    assert _send(api, "GET", "/api/response/kill-switch", {}).status_code == 401
    initial = _send(api, "GET", "/api/response/kill-switch", analyst)
    assert initial.status_code == 200
    assert initial.json()["engaged"] is False
    assert initial.json()["changed_by"] is None
    assert_response_contract("GET", "/api/response/kill-switch", initial)
    engine = create_engine(api.database_url, hide_parameters=True)
    try:
        with engine.begin() as db:
            incident = db.execute(
                text("INSERT INTO incidents (title) VALUES ('case') RETURNING id")
            ).scalar_one()
        actions = []
        for value in ("first", "second", "third"):
            created = _send(
                api,
                "POST",
                "/api/response/actions",
                analyst,
                {
                    "incident_id": str(incident),
                    "action_type": "ioc_add",
                    "target": {"value": value},
                    "params": {},
                },
            )
            assert created.status_code == 201
            action = UUID(created.json()["id"])
            actions.append(action)
            with app.state.session_factory.begin() as db:
                assert (
                    execute_approved(db, action, load_legacy_policy(), load_pb3_settings())
                    == "executed"
                )
        # A pending request does not manufacture a command-log row.
        pending = _send(
            api,
            "POST",
            "/api/response/actions",
            analyst,
            {
                "incident_id": str(incident),
                "action_type": "isolate_host",
                "target": {"agent_id": "004", "ip": "8.8.8.8"},
                "params": {},
            },
        )
        assert pending.status_code == 201
        page = _send(api, "GET", "/api/response/commands?limit=2", analyst)
        assert page.status_code == 200
        assert page.headers["Cache-Control"] == "no-store"
        assert_response_contract("GET", "/api/response/commands", page)
        assert len(page.json()["items"]) == 2
        assert all(item["simulated"] for item in page.json()["items"])
        assert page.json()["items"][0]["action_id"] == str(actions[2])
        cursor = page.json()["next_before_id"]
        second = _send(api, "GET", f"/api/response/commands?limit=2&before_id={cursor}", analyst)
        assert [item["action_id"] for item in second.json()["items"]] == [str(actions[0])]
        assert second.json()["next_before_id"] is None
        filtered = _send(api, "GET", f"/api/response/commands?action_id={actions[1]}", analyst)
        assert len(filtered.json()["items"]) == 1
        assert filtered.json()["items"][0]["command"] == "ioc_add"
        empty = _send(
            api, "GET", f"/api/response/commands?action_id={pending.json()['id']}", analyst
        )
        assert empty.json()["items"] == []
        assert (
            _send(api, "POST", "/api/response/kill-switch", admin, {"engaged": True}).status_code
            == 200
        )
        assert _send(api, "GET", "/api/response/kill-switch", analyst).json()["engaged"] is True
    finally:
        engine.dispose()


def test_presentation_migration_is_additive_reversible_and_minimally_granted(
    migrated_url: str,
) -> None:
    engine = create_engine(migrated_url, hide_parameters=True)
    try:
        inspector = inspect(engine)
        assert {item["name"] for item in inspector.get_columns("host_settings")} == {
            "id",
            "display_name",
            "default_direction",
            "updated_at",
        }
        with engine.connect() as db:
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                granted = db.execute(
                    text("SELECT has_table_privilege('hpb_app', 'host_settings', :privilege)"),
                    {"privilege": privilege},
                ).scalar_one()
                assert granted is (privilege in {"SELECT", "UPDATE"})
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(text("UPDATE host_settings SET default_direction='other'"))
        with pytest.raises(DBAPIError), engine.begin() as db:
            db.execute(text("INSERT INTO host_settings (id) VALUES (2)"))
        command.downgrade(Config("alembic.ini"), "008_response_safety")
        assert "host_settings" not in inspect(engine).get_table_names()
        assert "response_actions" in inspect(engine).get_table_names()
        command.upgrade(Config("alembic.ini"), "head")
        assert "host_settings" in inspect(engine).get_table_names()
    finally:
        engine.dispose()
