"""Legacy-role-protected mock IP reputation and cache endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from redis import Redis
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.roles import require_operation
from app.auth.session import SessionIdentity
from app.core.db import get_db
from app.core.exceptions import SemanticError, Unavailable
from app.core.http import private_json
from app.core.pb2_config import PB2Settings
from app.threat_intel.providers import ThreatIntelProvider
from app.threat_intel.schemas import (
    BulkCheckRequest,
    BulkCheckResult,
    CacheStats,
    CheckIPRequest,
    IntelResult,
)
from app.threat_intel.service import cache_stats, check_indicator

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])
Database = Annotated[Session, Depends(get_db)]
IntelUser = Annotated[SessionIdentity, Depends(require_operation("threat_intel"))]


@router.post("/check-ip", response_model=IntelResult)
def check_ip(
    body: CheckIPRequest, request: Request, response: Response, identity: IntelUser, db: Database
) -> IntelResult:
    settings: PB2Settings = request.app.state.pb2_settings
    cache: Redis = request.app.state.redis_cache
    provider: ThreatIntelProvider = request.app.state.threat_provider
    try:
        result = check_indicator(db, cache, provider, settings, body.indicator)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise Unavailable() from None
    private_json(response)
    return result


@router.post("/bulk-check", response_model=BulkCheckResult)
def bulk_check(
    body: BulkCheckRequest, request: Request, response: Response, identity: IntelUser, db: Database
) -> BulkCheckResult:
    settings: PB2Settings = request.app.state.pb2_settings
    if not body.indicators or len(body.indicators) > settings.threat_intel_bulk_max_items:
        raise SemanticError()
    cache: Redis = request.app.state.redis_cache
    provider: ThreatIntelProvider = request.app.state.threat_provider
    try:
        results = [check_indicator(db, cache, provider, settings, ip) for ip in body.indicators]
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise Unavailable() from None
    private_json(response)
    return BulkCheckResult(items=results)


@router.get("/cache/stats", response_model=CacheStats)
def get_cache_stats(
    request: Request, response: Response, identity: IntelUser, db: Database
) -> CacheStats:
    cache: Redis = request.app.state.redis_cache
    try:
        result = cache_stats(db, cache)
    except SQLAlchemyError:
        raise Unavailable() from None
    private_json(response)
    return result
