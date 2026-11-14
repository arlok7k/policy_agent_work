"""Legacy-role-protected deterministic mock AI endpoints."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.ai.providers import AlertContext, LLMProvider
from app.ai.schemas import AIRequest, ComprehensiveResult, RecommendationResult, SummaryResult
from app.ai.service import load_alert_context
from app.auth.roles import require_operation
from app.auth.session import SessionIdentity
from app.core.db import get_db
from app.core.exceptions import Unavailable
from app.core.http import private_json

router = APIRouter(prefix="/api/ai", tags=["ai"])
Database = Annotated[Session, Depends(get_db)]
AIUser = Annotated[SessionIdentity, Depends(require_operation("ai"))]


def _invoke[T](method: Callable[[AlertContext], T], alert: AlertContext) -> T:
    try:
        return method(alert)
    except Exception:
        raise Unavailable() from None


@router.post("/summarize", response_model=SummaryResult)
def summarize(
    body: AIRequest, request: Request, response: Response, identity: AIUser, db: Database
) -> SummaryResult:
    provider: LLMProvider = request.app.state.llm_provider
    result = _invoke(provider.summarize, load_alert_context(db, body.alert_id))
    private_json(response)
    return result


@router.post("/recommendations", response_model=RecommendationResult)
def recommendations(
    body: AIRequest, request: Request, response: Response, identity: AIUser, db: Database
) -> RecommendationResult:
    provider: LLMProvider = request.app.state.llm_provider
    result = _invoke(provider.recommendations, load_alert_context(db, body.alert_id))
    private_json(response)
    return result


@router.post("/analyze-comprehensive", response_model=ComprehensiveResult)
def comprehensive(
    body: AIRequest, request: Request, response: Response, identity: AIUser, db: Database
) -> ComprehensiveResult:
    provider: LLMProvider = request.app.state.llm_provider
    result = _invoke(provider.analyze_comprehensive, load_alert_context(db, body.alert_id))
    private_json(response)
    return result
