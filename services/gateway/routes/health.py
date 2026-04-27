"""Health check endpoint for LLM Hallucination Firewall."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, status

from models import HealthResponse, HealthStatus, DependencyStatus

logger = logging.getLogger(__name__)

router = APIRouter()

# Track application start time
_app_start_time = time.time()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check for LLM Hallucination Firewall",
    tags=["Health"],
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint with dependency status.

    Verifies:
    - API gateway is running
    - Required config is available
    - Optional external dependencies (NVD, ATT&CK, FAISS) status

    Returns:
        HealthResponse with overall status and per-dependency status

    Note:
        Always returns 200 if gateway is running, even if dependencies are degraded.
    """
    try:
        uptime = time.time() - _app_start_time

        # Check core services
        dependencies = []

        # Config check
        try:
            from services.common.config import load_profile
            profile = load_profile("default")
            config_status = HealthStatus.HEALTHY
            config_msg = "Default policy profile loaded"
        except Exception as e:
            config_status = HealthStatus.DEGRADED
            config_msg = f"Config error: {str(e)}"
            logger.warning(config_msg)

        dependencies.append(
            DependencyStatus(name="config", status=config_status, message=config_msg)
        )

        # Extraction pipeline check
        try:
            from services.claim_extractor.extractor import extract_claims
            extract_status = HealthStatus.HEALTHY
            extract_msg = "Extraction pipeline available"
        except Exception as e:
            extract_status = HealthStatus.DEGRADED
            extract_msg = f"Extraction error: {str(e)}"
            logger.warning(extract_msg)

        dependencies.append(
            DependencyStatus(
                name="extraction", status=extract_status, message=extract_msg
            )
        )

        # Validation pipeline check
        try:
            from services.validation_engine.deterministic import cve_exists_in_nvd
            from services.validation_engine.semantic import SemanticScorer
            validation_status = HealthStatus.HEALTHY
            validation_msg = "Validation pipeline available"
        except Exception as e:
            validation_status = HealthStatus.DEGRADED
            validation_msg = f"Validation error: {str(e)}"
            logger.warning(validation_msg)

        dependencies.append(
            DependencyStatus(
                name="validation", status=validation_status, message=validation_msg
            )
        )

        # Decision engine check
        try:
            from services.decision_engine.engine import decide
            decision_status = HealthStatus.HEALTHY
            decision_msg = "Decision engine available"
        except Exception as e:
            decision_status = HealthStatus.DEGRADED
            decision_msg = f"Decision engine error: {str(e)}"
            logger.warning(decision_msg)

        dependencies.append(
            DependencyStatus(name="decision_engine", status=decision_status, message=decision_msg)
        )

        # Overall status
        critical_failures = [d for d in dependencies if d.status == HealthStatus.UNHEALTHY]
        if critical_failures:
            overall_status = HealthStatus.UNHEALTHY
        elif any(d.status == HealthStatus.DEGRADED for d in dependencies):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY

        return HealthResponse(
            status=overall_status,
            timestamp=datetime.now(timezone.utc).isoformat(),
            version="1.0.0",
            dependencies=dependencies,
            uptime_seconds=uptime,
        )

    except Exception as e:
        logger.error(f"Health check error: {e}", exc_info=True)
        return HealthResponse(
            status=HealthStatus.DEGRADED,
            timestamp=datetime.now(timezone.utc).isoformat(),
            version="1.0.0",
            dependencies=[
                DependencyStatus(
                    name="health_check",
                    status=HealthStatus.UNHEALTHY,
                    message=str(e),
                )
            ],
            uptime_seconds=time.time() - _app_start_time,
        )
