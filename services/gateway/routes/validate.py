"""Validation endpoint for deterministic and semantic validation."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, status
from services.claim_extractor.extractor import extract_claims
from services.common.models import RuleSignal
from services.validation_engine.deterministic import (
    cve_exists_in_nvd,
    cvss_score_in_range,
    attack_id_valid,
    version_in_affected_range,
)
from services.validation_engine.semantic import SemanticScorer
from services.gateway.rag_integration import get_rag_pipeline
from services.gateway.state import get_gateway_state

from models import ValidateRequest, ValidateResponse, RuleResultResponse

logger = logging.getLogger(__name__)

router = APIRouter()


async def run_deterministic_validations(
    claims: list[dict[str, Any] | RuleResultResponse], nvd_data: dict[str, Any], attack_data: dict[str, Any]
) -> list[RuleResultResponse]:
    """
    Run deterministic validation rules against extracted claims.

    Args:
        claims: List of extracted claims (dict or RuleResultResponse)
        nvd_data: NVD payload for CVE validation
        attack_data: ATT&CK payload for technique validation

    Returns:
        List of validation rule results
    """
    results = []

    # Validate each CVE claim
    for claim in claims:
        # Handle both dict and Pydantic model
        claim_type = claim.get("claim_type") if isinstance(claim, dict) else getattr(claim, "claim_type", None)
        extracted_value = claim.get("extracted_value") if isinstance(claim, dict) else getattr(claim, "extracted_value", None)
        
        if claim_type == "cve":
            cve_id = extracted_value or ""
            try:
                result = cve_exists_in_nvd(cve_id, nvd_data)
                results.append(
                    RuleResultResponse(
                        rule_id=result.rule_id,
                        passed=result.passed,
                        evidence=result.evidence,
                        confidence=result.confidence,
                        signal=result.signal.value if result.signal else None,
                        hard_fail=result.hard_fail,
                        correction_candidates=result.correction_candidates,
                        metadata=result.metadata,
                    )
                )
            except Exception as e:
                logger.error(f"CVE validation error for {cve_id}: {e}")

        elif claim_type == "cvss_score":
            try:
                claimed_score = float(extracted_value or "0")
                nvd_score = float(nvd_data.get("cvss_score", 0.0))
                result = cvss_score_in_range(claimed_score, nvd_score)
                results.append(
                    RuleResultResponse(
                        rule_id=result.rule_id,
                        passed=result.passed,
                        evidence=result.evidence,
                        confidence=result.confidence,
                        signal=result.signal.value if result.signal else None,
                        hard_fail=result.hard_fail,
                        correction_candidates=result.correction_candidates,
                        metadata=result.metadata,
                    )
                )
            except Exception as e:
                logger.error(f"CVSS validation error: {e}")

        elif claim_type == "attack_id":
            technique_id = extracted_value or ""
            try:
                result = attack_id_valid(technique_id, attack_data)
                results.append(
                    RuleResultResponse(
                        rule_id=result.rule_id,
                        passed=result.passed,
                        evidence=result.evidence,
                        confidence=result.confidence,
                        signal=result.signal.value if result.signal else None,
                        hard_fail=result.hard_fail,
                        correction_candidates=result.correction_candidates,
                        metadata=result.metadata,
                    )
                )
            except Exception as e:
                logger.error(f"ATT&CK validation error for {technique_id}: {e}")

    return results


async def run_semantic_validation(
    llm_output: str,
    claims: list[dict[str, Any]],
    policy_profile: str = "default",
) -> RuleResultResponse | None:
    """
    Run semantic validation on extracted claims.

    Args:
        llm_output: Original LLM output
        claims: List of extracted claims
        policy_profile: Policy profile name for threshold override

    Returns:
        Semantic validation result or None if no mitigation claims
    """
    try:
        # Find mitigation or remediation claims
        mitigation_claims = [
            c for c in claims if c.get("claim_type") in ("mitigation", "remediation")
        ]
        if not mitigation_claims:
            return None

        scorer = SemanticScorer(profile_name=policy_profile)
        claim_texts = [c.get("extracted_value", "") for c in mitigation_claims]

        # Score best similarity
        best_text, similarity_score = await scorer.similarity(llm_output, claim_texts)

        # Get the full validation result
        validation_result = await scorer.score(llm_output, claim_texts)

        return RuleResultResponse(
            rule_id="semantic_mitigation_relevance",
            passed=validation_result.passed,
            evidence=f"Semantic similarity: {similarity_score:.4f}, threshold: {validation_result.threshold:.2f}",
            confidence=similarity_score,
            signal="mitigation_relevance",
            hard_fail=False,
            correction_candidates=[],
            metadata={
                "model_name": validation_result.model_name,
                "similarity_score": similarity_score,
                "threshold": validation_result.threshold,
            },
        )

    except Exception as e:
        logger.error(f"Semantic validation error: {e}", exc_info=True)
        return None


@router.post(
    "/validate",
    response_model=ValidateResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate extracted claims",
    tags=["Validation"],
)
async def validate_endpoint(request: ValidateRequest) -> ValidateResponse:
    """
    Validate extracted claims using deterministic rules and semantic similarity.

    Runs:
    1. Deterministic validators: CVE existence, CVSS range, ATT&CK format/existence
    2. Semantic validator: Mitigation relevance using sentence transformers

    Args:
        request: ValidateRequest with LLM output and optional pre-extracted claims

    Returns:
        ValidateResponse with validation rule results and latency metrics

    Raises:
        HTTPException: If validation pipeline fails
    """
    try:
        start_time = time.perf_counter()

        # Extract claims if not provided
        if request.extracted_claims:
            extracted = request.extracted_claims
        else:
            extracted_claims = await extract_claims(request.llm_output)
            extracted = [
                {
                    "claim_type": c.claim_type.value,
                    "raw_text": c.raw_text,
                    "extracted_value": c.extracted_value,
                    "position": c.position,
                    "confidence": c.confidence,
                }
                for c in extracted_claims
            ]

        # Prepare validation data
        nvd_data = request.nvd_data or {}
        attack_data = request.attack_data or {}

        # Enrich from RAG sources when caller did not provide authoritative payloads.
        if not nvd_data or not attack_data:
            rag_pipeline = get_rag_pipeline()

            cve_claims = []
            attack_claims = []
            for item in extracted:
                claim_type = item.get("claim_type") if isinstance(item, dict) else getattr(item, "claim_type", None)
                value = item.get("extracted_value") if isinstance(item, dict) else getattr(item, "extracted_value", None)
                if claim_type == "cve" and value:
                    cve_claims.append(str(value))
                elif claim_type == "attack_id" and value:
                    attack_claims.append(str(value))

            if not nvd_data and cve_claims:
                # Deterministic validators support multiple payload shapes; we pass the first
                # successfully retrieved record and let validation degrade gracefully if empty.
                for cve_id in cve_claims:
                    candidate = await rag_pipeline.retrieve_cve_data(cve_id)
                    if candidate:
                        nvd_data = candidate
                        break

            if not attack_data and attack_claims:
                for technique_id in attack_claims:
                    candidate = await rag_pipeline.retrieve_attack_technique(technique_id)
                    if candidate:
                        attack_data = candidate
                        break

        # Run deterministic validations
        det_results = await run_deterministic_validations(extracted, nvd_data, attack_data)

        # Run semantic validation
        sem_result = await run_semantic_validation(
            request.llm_output, extracted, request.context.policy_profile
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        get_gateway_state().record_validation_latency(elapsed_ms)

        return ValidateResponse(
            alert_id=request.context.alert_id,
            deterministic_rules=det_results,
            semantic_validation=sem_result,
            total_latency_ms=round(elapsed_ms, 2),
        )

    except ValueError as e:
        logger.warning(f"Validation request error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid validation request: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Validation endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Validation pipeline failed",
        )
