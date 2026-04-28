"""Decision endpoint for policy-driven validation outcomes."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from services.decision_engine.engine import decide
from services.common.models import RuleResult, RuleSignal
from services.audit.audit_log import get_audit_log
from services.gateway.state import StoredDecision, get_gateway_state
from services.gateway.persistence import get_db_session, save_decision

from models import DecideRequest, DecisionResponse, CorrectionCandidateResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/decide",
    response_model=DecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate policy-driven validation decision",
    tags=["Decision"],
)
async def decide_endpoint(request: DecideRequest) -> DecisionResponse:
    """
    Generate final validation decision using policy-driven decision engine.

    Computes risk score from validation rule results using weighted signal scoring,
    applies policy thresholds to determine outcome (ALLOW, FLAG, BLOCK, CORRECT).

    Args:
        request: DecideRequest with validation results and policy profile

    Returns:
        DecisionResponse with outcome, risk score, and rationale

    Raises:
        HTTPException: If decision engine fails or policy profile is invalid
    """
    try:
        start_time = time.perf_counter()

        # Convert API models back to internal RuleResult models
        rule_results = [
            RuleResult(
                rule_id=r.rule_id,
                passed=r.passed,
                evidence=r.evidence,
                confidence=r.confidence,
                signal=RuleSignal(r.signal) if r.signal else None,
                hard_fail=r.hard_fail,
                correction_candidates=r.correction_candidates,
                metadata=r.metadata,
            )
            for r in request.validation_results
        ]

        # Call Tanushree's decision engine
        decision_result = await decide(rule_results, profile_name=request.policy_profile)

        # Convert correction candidate if present
        correction = None
        if decision_result.correction is not None:
            correction = CorrectionCandidateResponse(
                value=decision_result.correction.value,
                reason=decision_result.correction.reason,
                score=decision_result.correction.score,
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        decision_id = str(uuid.uuid4())

        stored_decision = StoredDecision(
            decision_id=decision_id,
            alert_id=request.alert_id,
            llm_output="",
            outcome=decision_result.outcome,
            risk_score=decision_result.risk_score,
            validation_results=[r.model_dump() for r in request.validation_results],
            analyst_rationale=decision_result.rationale,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by="system",
        )
        get_gateway_state().add_decision(stored_decision)
        await save_decision(
            stored_decision,
            policy_profile_name=decision_result.applied_profile,
            correction_candidate=decision_result.correction.model_dump() if decision_result.correction else None,
        )
        audit_session = await get_db_session()
        try:
            audit_log = get_audit_log(audit_session)
            await audit_log.initialize()
            await audit_log.append(
            decision_id=decision_id,
            record_data={
                "type": "decision",
                "decision_id": decision_id,
                "alert_id": request.alert_id,
                "outcome": decision_result.outcome,
                "risk_score": decision_result.risk_score,
                "applied_profile": decision_result.applied_profile,
                "hard_fail_rule_ids": decision_result.hard_fail_rule_ids,
            },
            )
        finally:
            if audit_session is not None:
                await audit_session.close()

        return DecisionResponse(
            decision_id=decision_id,
            alert_id=request.alert_id,
            outcome=decision_result.outcome,
            risk_score=decision_result.risk_score,
            correction=correction,
            applied_profile=decision_result.applied_profile,
            signal_scores=decision_result.signal_scores,
            hard_fail_rule_ids=decision_result.hard_fail_rule_ids,
            rationale=decision_result.rationale,
            decision_timestamp=datetime.now(timezone.utc).isoformat(),
            latency_ms=round(elapsed_ms, 2),
        )

    except KeyError as e:
        logger.warning(f"Invalid policy profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown policy profile: {str(e)}",
        )
    except ValueError as e:
        logger.warning(f"Decision request validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision request: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Decision endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decision engine failed",
        )
