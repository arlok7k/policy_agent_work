"""Legacy-role-protected deterministic mock AI endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.ai.providers import LLMProvider
from app.ai.schemas import AIRequest, ComprehensiveResult, RecommendationResult, SummaryResult
from app.ai.service import invoke_provider, load_alert_context
from app.auth.roles import require_operation
from app.auth.session import SessionIdentity
from app.core.db import get_db
from app.core.http import private_json

router = APIRouter(prefix="/api/ai", tags=["ai"])
Database = Annotated[Session, Depends(get_db)]
AIUser = Annotated[SessionIdentity, Depends(require_operation("ai"))]


@router.post("/summarize", response_model=SummaryResult)
def summarize(
    body: AIRequest, request: Request, response: Response, identity: AIUser, db: Database
) -> SummaryResult:
    provider: LLMProvider = request.app.state.llm_provider
    result = invoke_provider(provider.summarize, load_alert_context(db, body.alert_id))
    private_json(response)
    return result


@router.post("/recommendations", response_model=RecommendationResult)
def recommendations(
    body: AIRequest, request: Request, response: Response, identity: AIUser, db: Database
) -> RecommendationResult:
    provider: LLMProvider = request.app.state.llm_provider
    result = invoke_provider(provider.recommendations, load_alert_context(db, body.alert_id))
    private_json(response)
    return result


@router.post("/analyze-comprehensive", response_model=ComprehensiveResult)
def comprehensive(
    body: AIRequest, request: Request, response: Response, identity: AIUser, db: Database
) -> ComprehensiveResult:
    provider: LLMProvider = request.app.state.llm_provider
    result = invoke_provider(provider.analyze_comprehensive, load_alert_context(db, body.alert_id))
    private_json(response)
    return result
