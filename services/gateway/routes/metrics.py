# services/gateway/routes/metrics.py
"""
Application metrics and monitoring data endpoints.

Provides operational metrics: validation latency, decision distribution,
threat intel retrieval performance, etc.
"""

from typing import Dict, List

from auth import CurrentUser, get_current_user
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

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
    # TODO: Query Prometheus or in-memory metrics store

    return PerformanceMetrics(
        validation_latency_p50_ms=150.0,
        validation_latency_p95_ms=500.0,
        validation_latency_p99_ms=1200.0,
        avg_validation_latency_ms=300.0,
        total_validations=0,
        validations_per_minute=0.0,
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
    # TODO: Aggregate decision outcomes from database

    return {"ALLOW": 0, "FLAG": 0, "BLOCK": 0, "CORRECT": 0}


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
    # TODO: Query FAISS metrics from rag_pipeline

    return {
        "avg_similarity_score": 0.75,
        "retrieval_success_rate": 0.95,
        "index_size_mb": 512.0,
        "avg_retrieval_latency_ms": 50.0,
    }
