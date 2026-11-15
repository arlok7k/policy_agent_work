"""Both simulated connectors append structured commands in the caller transaction."""

import json
from datetime import timedelta
from ipaddress import ip_address
from uuid import UUID

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from app.connectors.internal import InternalConnector
from app.connectors.simulated_wazuh import SimulatedWazuhConnector
from app.response.gate import transition
from app.response.models import ResponseAction
from app.response.rules import lock_safety_snapshot
from tests.integration.conftest import PB2Account


def test_both_connectors_persist_structured_simulated_commands(
    migrated_url: str, runtime_url: str, pb2_accounts: dict[str, PB2Account]
) -> None:
    owner = create_engine(migrated_url, hide_parameters=True)
    runtime = create_engine(runtime_url, hide_parameters=True)
    requester = pb2_accounts["analyst"].id
    try:
        with owner.begin() as db:
            incident = db.execute(
                text("INSERT INTO incidents (title) VALUES ('connector test') RETURNING id")
            ).scalar_one()
            actions: list[UUID] = []
            for name, level, target, params, ttl in (
                ("notify", 1, {"value": "analysts"}, {"message": "Review alert"}, None),
                ("firewall_drop", 2, {"agent_id": "004", "ip": "8.8.8.8"}, {}, 60),
            ):
                action = db.execute(
                    text(
                        "INSERT INTO response_actions "
                        "(incident_id, action_type, target, params, level, approval_mode, "
                        "requested_by, ttl_seconds) "
                        "VALUES (:incident, :name, CAST(:target AS jsonb), CAST(:params AS jsonb), "
                        ":level, 'automatic', :requester, :ttl) RETURNING id"
                    ),
                    {
                        "incident": incident,
                        "name": name,
                        "target": json.dumps(target),
                        "params": json.dumps(params),
                        "level": level,
                        "requester": requester,
                        "ttl": ttl,
                    },
                ).scalar_one()
                for state in ("approved", "executing"):
                    db.execute(
                        text("UPDATE response_actions SET status=:state WHERE id=:id"),
                        {"state": state, "id": action},
                    )
                actions.append(action)
        for identifier, connector in zip(
            actions, (InternalConnector(), SimulatedWazuhConnector()), strict=True
        ):
            with Session(runtime) as db, db.begin():
                safety = lock_safety_snapshot(db)
                action = db.execute(
                    select(ResponseAction).where(ResponseAction.id == identifier).with_for_update()
                ).scalar_one()
                connector.execute(
                    db,
                    action,
                    phase="execute",
                    initiator=f"user:{requester}",
                    automated=True,
                    safety=safety,
                )
                db.flush()
                if action.level == 2:
                    action.ttl_expires_at = db.execute(
                        select(func.clock_timestamp())
                    ).scalar_one() + timedelta(seconds=60)
                transition(db, action, "executed", username="analyst", ip=ip_address("127.0.0.1"))
        with owner.connect() as db:
            rows = db.execute(
                text(
                    "SELECT connector, command, simulated, phase FROM executed_commands ORDER BY id"
                )
            ).all()
            assert rows == [
                ("internal", "notify", True, "execute"),
                ("simulated_wazuh", "firewall_drop", True, "execute"),
            ]
            assert (
                db.execute(
                    text("SELECT count(*) FROM case_activities WHERE action='response.transition'")
                ).scalar_one()
                == 2
            )
    finally:
        owner.dispose()
        runtime.dispose()
