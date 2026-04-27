# services/gateway/routes/decisions.py
"""
Decision history and retrieval endpoints.

Provides read access to validation decisions with optional filtering by outcome, date range, alert_id.
"""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, HTTPException, status, Query
from auth import CurrentUser, get_current_user

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
    summary="List validation decisions with optional filtering"
)
async def list_decisions(
    outcome: Optional[str] = Query(None, description="Filter by outcome: ALLOW | FLAG | BLOCK | CORRECT"),
    alert_id: Optional[str] = Query(None, description="Filter by alert ID"),
    start_date: Optional[str] = Query(None, description="Filter by start date (ISO 8601)"),
    end_date: Optional[str] = Query(None, description="Filter by end date (ISO 8601)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: CurrentUser = Depends(get_current_user)
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
    # TODO: Query PostgreSQL with filters
    # TODO: Apply pagination
    # TODO: Return summaries
    
    return []


@router.get(
    "/decisions/{decision_id}",
    response_model=DecisionDetail,
    summary="Retrieve detailed decision record"
)
async def get_decision_detail(
    decision_id: str,
    current_user: CurrentUser = Depends(get_current_user)
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
    # TODO: Query PostgreSQL
    # TODO: Reconstruct decision details
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Decision {decision_id} not found"
    )


@router.get(
    "/decisions/stats/summary",
    summary="Get aggregated decision statistics"
)
async def get_decision_stats(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    current_user: CurrentUser = Depends(get_current_user)
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
    # TODO: Aggregate decision counts by outcome from PostgreSQL
    
    return {
        "total": 0,
        "allow": 0,
        "flag": 0,
        "block": 0,
        "correct": 0
    }
