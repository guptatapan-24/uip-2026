# services/gateway/routes/decisions.py
"""
Decision history and retrieval endpoints.

Provides read access to validation decisions with optional filtering by outcome, date range, alert_id.
"""

from datetime import datetime
from typing import List, Optional

from auth import CurrentUser, get_current_user
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from services.gateway.state import get_gateway_state
from services.gateway.persistence import get_decision, list_decisions as list_decisions_db

router = APIRouter()


class DecisionSummary(BaseModel):
    """Summary of a validation decision."""

    decision_id: str
    alert_id: str
    outcome: str  # ALLOW | FLAG | BLOCK | CORRECT
    risk_score: float = Field(..., ge=0.0, le=1.0)
    created_at: str
    created_by: str


class DecisionDetail(BaseModel):
    """Detailed decision record including explainability."""

    decision_id: str
    alert_id: str
    llm_output: str
    outcome: str
    risk_score: float
    validation_results: List[dict] = Field(default_factory=list)
    analyst_rationale: str
    analyst_override: Optional[str] = None  # If overridden by SOC_ADMIN
    created_at: str
    created_by: str
    updated_at: Optional[str] = None


@router.get(
    "/decisions",
    response_model=List[DecisionSummary],
    summary="List validation decisions with optional filtering",
)
async def list_decisions(
    outcome: Optional[str] = Query(
        None, description="Filter by outcome: ALLOW | FLAG | BLOCK | CORRECT"
    ),
    alert_id: Optional[str] = Query(None, description="Filter by alert ID"),
    start_date: Optional[str] = Query(
        None, description="Filter by start date (ISO 8601)"
    ),
    end_date: Optional[str] = Query(None, description="Filter by end date (ISO 8601)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
) -> List[DecisionSummary]:
    """
    List validation decisions with optional filtering.

    Args:
        outcome: Filter by decision outcome
        alert_id: Filter by SOC alert ID
        start_date: Filter from date (ISO 8601)
        end_date: Filter to date (ISO 8601)
        limit: Result limit
        offset: Result offset for pagination
        current_user: Authenticated user

    Returns:
        List of decision summaries
    """
    start_dt = None
    end_dt = None

    if start_date:
        start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
    if end_date:
        end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))

    decisions = await list_decisions_db(
        outcome=outcome,
        alert_id=alert_id,
        start_dt=start_dt,
        end_dt=end_dt,
        limit=limit,
        offset=offset,
    )
    if decisions is None:
        decisions = get_gateway_state().list_decisions()
        if outcome:
            decisions = [d for d in decisions if d.outcome == outcome]
        if alert_id:
            decisions = [d for d in decisions if d.alert_id == alert_id]
        if start_dt:
            decisions = [
                d
                for d in decisions
                if datetime.fromisoformat(d.created_at.replace("Z", "+00:00")) >= start_dt
            ]
        if end_dt:
            decisions = [
                d
                for d in decisions
                if datetime.fromisoformat(d.created_at.replace("Z", "+00:00")) <= end_dt
            ]
        decisions = decisions[offset : offset + limit]

    return [
        DecisionSummary(
            decision_id=item.decision_id,
            alert_id=item.alert_id,
            outcome=item.outcome,
            risk_score=item.risk_score,
            created_at=item.created_at,
            created_by=item.created_by,
        )
        for item in decisions
    ]


@router.get(
    "/decisions/{decision_id}",
    response_model=DecisionDetail,
    summary="Retrieve detailed decision record",
)
async def get_decision_detail(
    decision_id: str, current_user: CurrentUser = Depends(get_current_user)
) -> DecisionDetail:
    """
    Retrieve full decision details including validation chain and explainability.

    Args:
        decision_id: UUID of decision
        current_user: Authenticated user

    Returns:
        Detailed decision record

    Raises:
        404: Decision not found
    """
    decision = await get_decision(decision_id)
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision {decision_id} not found",
        )

    return DecisionDetail(
        decision_id=decision.decision_id,
        alert_id=decision.alert_id,
        llm_output=decision.llm_output,
        outcome=decision.outcome,
        risk_score=decision.risk_score,
        validation_results=decision.validation_results,
        analyst_rationale=decision.analyst_rationale,
        analyst_override=decision.analyst_override,
        created_at=decision.created_at,
        created_by=decision.created_by,
        updated_at=decision.updated_at,
    )


@router.get("/decisions/stats/summary", summary="Get aggregated decision statistics")
async def get_decision_stats(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Get summary statistics on decision outcomes over time period.

    Args:
        start_date: Start of date range
        end_date: End of date range
        current_user: Authenticated user

    Returns:
        {"total": int, "allow": int, "flag": int, "block": int, "correct": int}
    """
    start_dt = None
    end_dt = None
    if start_date:
        start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
    if end_date:
        end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))

    decisions = await list_decisions_db(start_dt=start_dt, end_dt=end_dt, limit=10_000, offset=0)
    if decisions is None:
        decisions = get_gateway_state().list_decisions()
    if start_dt:
        decisions = [
            d
            for d in decisions
            if datetime.fromisoformat(d.created_at.replace("Z", "+00:00")) >= start_dt
        ]
    if end_dt:
        decisions = [
            d
            for d in decisions
            if datetime.fromisoformat(d.created_at.replace("Z", "+00:00")) <= end_dt
        ]

    stats = {"total": len(decisions), "allow": 0, "flag": 0, "block": 0, "correct": 0}
    for decision in decisions:
        outcome = decision.outcome.lower()
        if outcome in stats:
            stats[outcome] += 1
    return stats
