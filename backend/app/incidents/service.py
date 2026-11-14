"""Transactional incident creation and alert investigation."""

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from redis import Redis
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.ai.providers import LLMProvider
from app.ai.service import invoke_provider, load_alert_context
from app.alerts.models import Alert
from app.auth.session import SessionIdentity
from app.auth.transactions import lock_authorized_actor
from app.core.activity import append_activity
from app.core.config import Settings
from app.core.exceptions import BadRequest, NotFound, SemanticError
from app.core.pb2_config import PB2Settings
from app.incidents.models import Evidence, Incident, IncidentAlert
from app.incidents.schemas import IncidentCreate, IncidentView, InvestigateResult
from app.threat_intel.providers import ThreatIntelProvider
from app.threat_intel.service import check_indicator

PeerIP = IPv4Address | IPv6Address


def incident_views(db: Session, incidents: Sequence[Incident]) -> list[IncidentView]:
    ids = [incident.id for incident in incidents]
    linked: dict[UUID, list[UUID]] = {identifier: [] for identifier in ids}
    if ids:
        rows = db.execute(
            select(IncidentAlert.incident_id, IncidentAlert.alert_id)
            .where(IncidentAlert.incident_id.in_(ids))
            .order_by(IncidentAlert.incident_id, IncidentAlert.alert_id)
        ).all()
        for incident_id, alert_id in rows:
            linked[incident_id].append(alert_id)
    return [
        IncidentView(
            id=incident.id,
            title=incident.title,
            description=incident.description,
            status=incident.status,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            alert_ids=linked[incident.id],
        )
        for incident in incidents
    ]


def _bounded_text(value: str, maximum: int, *, empty_allowed: bool = False) -> str:
    result = value.strip()
    try:
        result.encode("utf-8")
    except UnicodeError:
        raise BadRequest() from None
    if (not result and not empty_allowed) or len(result) > maximum or "\x00" in result:
        raise BadRequest()
    return result


def create_incident(
    db: Session,
    settings: Settings,
    pb2: PB2Settings,
    identity: SessionIdentity,
    session_token: str,
    allowed_roles: Sequence[str],
    body: IncidentCreate,
    ip: PeerIP,
) -> IncidentView:
    title = _bounded_text(body.title, pb2.incident_max_text_chars)
    description = (
        _bounded_text(body.description, pb2.incident_max_text_chars, empty_allowed=True)
        if body.description is not None
        else None
    )
    if len(body.alert_ids) > pb2.incident_max_alerts:
        raise SemanticError()
    if len(set(body.alert_ids)) != len(body.alert_ids):
        raise BadRequest()
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, session_token, identity, allowed_roles)
        alert_ids = sorted(body.alert_ids)
        if alert_ids:
            found = list(
                db.execute(
                    select(Alert.id)
                    .where(Alert.id.in_(alert_ids))
                    .order_by(Alert.id)
                    .with_for_update()
                ).scalars()
            )
            if found != alert_ids:
                raise NotFound()
        incident = Incident(title=title, description=description)
        db.add(incident)
        db.flush()
        db.add_all(
            IncidentAlert(incident_id=incident.id, alert_id=identifier) for identifier in alert_ids
        )
        append_activity(
            db,
            username=actor.username,
            ip=ip,
            action="incident.create",
            target=f"incident:{incident.id}",
            details={"alert_ids": [str(identifier) for identifier in alert_ids]},
        )
        db.flush()
        result = incident_views(db, [incident])[0]
    return result


def investigate_alert(
    db: Session,
    settings: Settings,
    pb2: PB2Settings,
    identity: SessionIdentity,
    session_token: str,
    allowed_roles: Sequence[str],
    alert_id: UUID,
    requested_incident_id: UUID | None,
    ip: PeerIP,
    cache: Redis,
    threat_provider: ThreatIntelProvider,
    llm_provider: LLMProvider,
) -> InvestigateResult:
    with db.begin():
        actor, _ = lock_authorized_actor(db, settings, session_token, identity, allowed_roles)
        alert = db.execute(
            select(Alert).where(Alert.id == alert_id).with_for_update()
        ).scalar_one_or_none()
        if alert is None:
            raise NotFound()
        created = False
        if requested_incident_id is not None:
            incident = db.execute(
                select(Incident).where(Incident.id == requested_incident_id).with_for_update()
            ).scalar_one_or_none()
            if incident is None:
                raise NotFound()
        else:
            incident = db.execute(
                select(Incident)
                .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
                .where(IncidentAlert.alert_id == alert_id)
                .order_by(Incident.created_at, Incident.id)
                .limit(1)
                .with_for_update(of=Incident)
            ).scalar_one_or_none()
            if incident is None:
                incident = Incident(title=f"Investigation of alert {alert.id}", description=None)
                db.add(incident)
                db.flush()
                created = True
        existing = db.get(IncidentAlert, (incident.id, alert.id))
        if existing is None:
            linked_count = db.execute(
                select(func.count())
                .select_from(IncidentAlert)
                .where(IncidentAlert.incident_id == incident.id)
            ).scalar_one()
            if linked_count >= pb2.incident_max_alerts:
                raise SemanticError()
            db.execute(
                insert(IncidentAlert)
                .values(incident_id=incident.id, alert_id=alert.id)
                .on_conflict_do_nothing(
                    index_elements=[IncidentAlert.incident_id, IncidentAlert.alert_id]
                )
            )
        context = load_alert_context(db, alert.id)
        indicator = context.src_ip or context.dst_ip
        intelligence = (
            check_indicator(db, cache, threat_provider, pb2, indicator)
            if indicator is not None
            else None
        )
        ai = invoke_provider(llm_provider.analyze_comprehensive, context)
        threat_data = (
            {"checked": True, "result": intelligence.model_dump(mode="json")}
            if intelligence is not None
            else {"checked": False, "reason": "no_indicator"}
        )
        db.add_all(
            [
                Evidence(
                    incident_id=incident.id,
                    alert_id=alert.id,
                    kind="threat_intel",
                    data=threat_data,
                ),
                Evidence(
                    incident_id=incident.id,
                    alert_id=alert.id,
                    kind="ai_comprehensive",
                    data={"result": ai.model_dump(mode="json")},
                ),
            ]
        )
        alert.status = "investigating"
        incident.updated_at = db.execute(select(func.clock_timestamp())).scalar_one()
        append_activity(
            db,
            username=actor.username,
            ip=ip,
            action="alert.investigate",
            target=f"incident:{incident.id}",
            details={
                "alert_id": str(alert.id),
                "incident_created": created,
                "intelligence_degraded": intelligence.degraded
                if intelligence is not None
                else True,
                "mock": True,
            },
        )
        db.flush()
        result = InvestigateResult(
            incident=incident_views(db, [incident])[0], intelligence=intelligence, ai=ai
        )
    return result
