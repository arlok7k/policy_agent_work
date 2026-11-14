"""Role-protected PB2 incident, evidence and investigation routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from redis import Redis
from sqlalchemy import select, tuple_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ai.providers import LLMProvider
from app.auth.roles import operation_roles, require_operation
from app.auth.session import SESSION_COOKIE, SessionIdentity
from app.core.config import Settings
from app.core.db import get_db
from app.core.exceptions import NotFound, Unavailable
from app.core.http import page_size, private_json, request_peer_ip
from app.core.pagination import decode_cursor, encode_cursor
from app.core.pb2_config import PB2Settings
from app.incidents.models import Evidence, Incident
from app.incidents.schemas import (
    EvidencePage,
    EvidenceView,
    IncidentCreate,
    IncidentPage,
    IncidentView,
    InvestigateRequest,
    InvestigateResult,
)
from app.incidents.service import create_incident, incident_views, investigate_alert
from app.threat_intel.providers import ThreatIntelProvider

router = APIRouter(tags=["incidents"])
Database = Annotated[Session, Depends(get_db)]
IncidentReader = Annotated[SessionIdentity, Depends(require_operation("incidents_read"))]
IncidentWriter = Annotated[SessionIdentity, Depends(require_operation("incidents_write"))]
Investigator = Annotated[SessionIdentity, Depends(require_operation("investigate"))]


@router.post("/api/incidents", response_model=IncidentView, status_code=status.HTTP_201_CREATED)
def create(
    body: IncidentCreate,
    request: Request,
    response: Response,
    identity: IncidentWriter,
    db: Database,
) -> IncidentView:
    settings: Settings = request.app.state.settings
    pb2: PB2Settings = request.app.state.pb2_settings
    try:
        result = create_incident(
            db,
            settings,
            pb2,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "incidents_write"),
            body,
            request_peer_ip(request),
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.get("/api/incidents", response_model=IncidentPage)
def list_incidents(
    request: Request,
    response: Response,
    identity: IncidentReader,
    db: Database,
    limit: Annotated[int | None, Query(gt=0)] = None,
    cursor: str | None = None,
) -> IncidentPage:
    settings: Settings = request.app.state.settings
    size = page_size(settings, limit)
    query = select(Incident)
    if cursor is not None:
        timestamp, identifier = decode_cursor(cursor)
        query = query.where(
            tuple_(Incident.created_at, Incident.id) < tuple_(timestamp, identifier)
        )
    try:
        incidents = list(
            db.execute(
                query.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(size + 1)
            )
            .scalars()
            .all()
        )
        page = incidents[:size]
        next_cursor = (
            encode_cursor(page[-1].created_at, page[-1].id) if len(incidents) > size else None
        )
        result = IncidentPage(items=incident_views(db, page), next_cursor=next_cursor)
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.get("/api/incidents/{incident_id}", response_model=IncidentView)
def detail(
    incident_id: UUID, response: Response, identity: IncidentReader, db: Database
) -> IncidentView:
    try:
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise NotFound()
        result = incident_views(db, [incident])[0]
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.get("/api/incidents/{incident_id}/evidence", response_model=EvidencePage)
def evidence(
    incident_id: UUID,
    request: Request,
    response: Response,
    identity: IncidentReader,
    db: Database,
    limit: Annotated[int | None, Query(gt=0)] = None,
    cursor: str | None = None,
) -> EvidencePage:
    settings: Settings = request.app.state.settings
    size = page_size(settings, limit)
    query = select(Evidence).where(Evidence.incident_id == incident_id)
    if cursor is not None:
        timestamp, identifier = decode_cursor(cursor)
        query = query.where(
            tuple_(Evidence.created_at, Evidence.id) < tuple_(timestamp, identifier)
        )
    try:
        if db.get(Incident, incident_id) is None:
            raise NotFound()
        records = list(
            db.execute(
                query.order_by(Evidence.created_at.desc(), Evidence.id.desc()).limit(size + 1)
            )
            .scalars()
            .all()
        )
        page = records[:size]
        next_cursor = (
            encode_cursor(page[-1].created_at, page[-1].id) if len(records) > size else None
        )
        result = EvidencePage(
            items=[EvidenceView.model_validate(item) for item in page], next_cursor=next_cursor
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result


@router.post("/api/alerts/{alert_id}/investigate", response_model=InvestigateResult)
def investigate(
    alert_id: UUID,
    body: InvestigateRequest,
    request: Request,
    response: Response,
    identity: Investigator,
    db: Database,
) -> InvestigateResult:
    settings: Settings = request.app.state.settings
    pb2: PB2Settings = request.app.state.pb2_settings
    cache: Redis = request.app.state.redis_cache
    threat_provider: ThreatIntelProvider = request.app.state.threat_provider
    llm_provider: LLMProvider = request.app.state.llm_provider
    try:
        result = investigate_alert(
            db,
            settings,
            pb2,
            identity,
            request.cookies.get(SESSION_COOKIE, ""),
            operation_roles(request, "investigate"),
            alert_id,
            body.incident_id,
            request_peer_ip(request),
            cache,
            threat_provider,
            llm_provider,
        )
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result
