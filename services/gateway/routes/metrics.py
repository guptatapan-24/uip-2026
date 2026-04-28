# services/gateway/routes/metrics.py
"""
Application metrics and monitoring data endpoints.

Provides operational metrics: validation latency, decision distribution,
threat intel retrieval performance, etc.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List

from auth import CurrentUser, get_current_user
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from services.gateway.state import get_gateway_state
from services.gateway.persistence import get_outcome_counts

router = APIRouter()


class MetricSnapshot(BaseModel):
    """Single metric data point."""

    timestamp: str
    value: float
    unit: str


class PerformanceMetrics(BaseModel):
    """Performance metrics for monitoring."""

    validation_latency_p50_ms: float
    validation_latency_p95_ms: float
    validation_latency_p99_ms: float
    avg_validation_latency_ms: float
    total_validations: int
    validations_per_minute: float


@router.get(
    "/metrics/performance",
    response_model=PerformanceMetrics,
    summary="Get performance metrics",
)
async def get_performance_metrics(
    time_window_minutes: int = Query(60, ge=1, le=1440),
    current_user: CurrentUser = Depends(get_current_user),
) -> PerformanceMetrics:
    """
    Get current performance metrics for monitoring.

    Args:
        time_window_minutes: Metric window (1-1440 minutes)
        current_user: Authenticated user

    Returns:
        Performance metrics snapshot
    """
    latencies = get_gateway_state().get_latency_window(time_window_minutes)
    if not latencies:
        return PerformanceMetrics(
            validation_latency_p50_ms=0.0,
            validation_latency_p95_ms=0.0,
            validation_latency_p99_ms=0.0,
            avg_validation_latency_ms=0.0,
            total_validations=0,
            validations_per_minute=0.0,
        )

    sorted_lats = sorted(latencies)

    def percentile(values: list[float], p: float) -> float:
        if not values:
            return 0.0
        index = int((len(values) - 1) * p)
        return values[index]

    return PerformanceMetrics(
        validation_latency_p50_ms=round(percentile(sorted_lats, 0.50), 2),
        validation_latency_p95_ms=round(percentile(sorted_lats, 0.95), 2),
        validation_latency_p99_ms=round(percentile(sorted_lats, 0.99), 2),
        avg_validation_latency_ms=round(sum(latencies) / len(latencies), 2),
        total_validations=len(latencies),
        validations_per_minute=round(len(latencies) / max(1, time_window_minutes), 4),
    )


@router.get("/metrics/outcomes", summary="Get decision outcome distribution")
async def get_outcome_metrics(
    time_window_minutes: int = Query(60, ge=1, le=1440),
    current_user: CurrentUser = Depends(get_current_user),
) -> Dict[str, int]:
    """
    Get distribution of decision outcomes over time window.

    Args:
        time_window_minutes: Metric window
        current_user: Authenticated user

    Returns:
        {"ALLOW": int, "FLAG": int, "BLOCK": int, "CORRECT": int}
    """
    threshold = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    counts = await get_outcome_counts()
    if counts is None:
        counts = {"ALLOW": 0, "FLAG": 0, "BLOCK": 0, "CORRECT": 0}

        for decision in get_gateway_state().list_decisions():
            created_at = datetime.fromisoformat(decision.created_at.replace("Z", "+00:00"))
            if created_at < threshold:
                continue
            if decision.outcome in counts:
                counts[decision.outcome] += 1

    return counts


@router.get("/metrics/rag-quality", summary="Get RAG retrieval quality metrics")
async def get_rag_metrics(
    current_user: CurrentUser = Depends(get_current_user),
) -> Dict[str, float]:
    """
    Get FAISS vector retrieval quality metrics.

    Args:
        current_user: Authenticated user

    Returns:
        {
            "avg_similarity_score": float,
            "retrieval_success_rate": float,
            "index_size_mb": float,
            "avg_retrieval_latency_ms": float
        }
    """
    decisions = get_gateway_state().list_decisions()
    total = len(decisions)
    if total == 0:
        return {
            "avg_similarity_score": 0.0,
            "retrieval_success_rate": 0.0,
            "index_size_mb": 0.0,
            "avg_retrieval_latency_ms": 0.0,
        }

    # Proxy metrics until FAISS-specific telemetry is wired.
    has_validation_payload = sum(1 for d in decisions if d.validation_results)
    success_rate = has_validation_payload / total

    return {
        "avg_similarity_score": 0.0,
        "retrieval_success_rate": round(success_rate, 4),
        "index_size_mb": 0.0,
        "avg_retrieval_latency_ms": 0.0,
    }
