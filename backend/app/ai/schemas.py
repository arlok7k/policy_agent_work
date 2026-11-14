"""Structured host AI inputs and explicitly mock outputs."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: UUID


class Recommendation(BaseModel):
    action: str
    reason: str


class SummaryResult(BaseModel):
    mock: Literal[True] = True
    alert_id: UUID
    summary: str


class RecommendationResult(BaseModel):
    mock: Literal[True] = True
    alert_id: UUID
    recommendations: list[Recommendation]


class AnalysisDetails(BaseModel):
    severity: str
    agent_present: bool
    indicator_present: bool


class ComprehensiveResult(BaseModel):
    mock: Literal[True] = True
    alert_id: UUID
    summary: str
    recommendations: list[Recommendation]
    analysis: AnalysisDetails
