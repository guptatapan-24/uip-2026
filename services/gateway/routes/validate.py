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
from services.common.models import RuleResult, RuleSignal
from services.validation_engine.deterministic import (
    DeterministicValidator,
    cve_exists_in_nvd,
    cvss_score_in_range,
    attack_id_valid,
    version_in_affected_range,
)
from services.validation_engine.llm_verifier import get_llm_verifier
from services.validation_engine.semantic import SemanticScorer
from services.decision_engine.engine import decide
from services.explainability.report_builder import ReportBuilder
from services.audit.audit_log import get_audit_log
from services.gateway.persistence import get_db_session, save_decision
from services.gateway.rag_integration import get_rag_pipeline
from services.gateway.state import StoredDecision, get_gateway_state

from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ExtractedClaimResponse,
    RuleResultResponse,
    ValidateRequest,
    ValidateResponse,
)

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


def _mock_threat_intel_enabled() -> bool:
    return os.getenv("MOCK_THREAT_INTEL", "false").lower() in {"1", "true", "yes"}


def _mock_nvd_data(cve_id: str) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "cvss_score": 7.5,
        "affected_versions": ["1.0", "2.0"],
        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        "source": "mock_nvd",
        "vulnerabilities": [{"cve": {"id": cve_id}}],
    }


def _mock_attack_data(technique_id: str) -> dict[str, Any]:
    return {
        "technique_id": technique_id,
        "name": "Mock ATT&CK technique",
        "tactics": ["initial-access"],
        "platforms": ["Windows", "Linux"],
        "source": "mock_attack",
        "techniques": [technique_id],
    }


def _flatten_threat_intel_texts(threat_intel: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for value in threat_intel.values():
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, dict):
            for inner in value.values():
                if isinstance(inner, str):
                    texts.append(inner)
                elif isinstance(inner, list):
                    texts.extend(str(item) for item in inner if isinstance(item, str))
        elif isinstance(value, list):
            texts.extend(str(item) for item in value if isinstance(item, str))
    return texts


async def _retrieve_threat_intel_for_claim(
    claim: dict[str, Any], rag_pipeline: Any
) -> dict[str, Any]:
    claim_type = claim.get("claim_type")
    extracted_value = str(claim.get("extracted_value", "")).strip()
    if not extracted_value:
        return {}

    if claim_type == "cve":
        return await rag_pipeline.retrieve_threat_intel(cve_id=extracted_value)

    if claim_type == "attack_id":
        return await rag_pipeline.retrieve_threat_intel(technique_id=extracted_value)

    return {}


def _claim_to_response(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_type": claim.get("claim_type", ""),
        "raw_text": claim.get("raw_text", ""),
        "extracted_value": claim.get("extracted_value", ""),
        "position": claim.get("position", (0, 0)),
        "confidence": float(claim.get("confidence", 0.0) or 0.0),
    }


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

@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Run the full analysis pipeline and return a decision",
    tags=["Analysis"],
)
async def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Run the complete claim extraction, retrieval, validation, decision, explainability, audit, and persistence pipeline."""
    start_time = time.perf_counter()
    decision_id = str(uuid.uuid4())
    rag_pipeline = get_rag_pipeline()
    llm_verifier = get_llm_verifier()
    report_builder = ReportBuilder()

    try:
        # Step 1: Extract claims if not provided.
        if request.extracted_claims is not None:
            extracted_claims = [claim.model_dump() for claim in request.extracted_claims]
        else:
            extracted = await extract_claims(request.llm_output)
            extracted_claims = [
                {
                    "claim_type": claim.claim_type.value,
                    "raw_text": claim.raw_text,
                    "extracted_value": claim.extracted_value,
                    "position": claim.position,
                    "confidence": claim.confidence,
                }
                for claim in extracted
            ]

        # Step 2: Retrieve threat intelligence per claim.
        claim_intel_map: dict[int, dict[str, Any]] = {}
        threat_intel_matches: list[dict[str, Any]] = []
        for index, claim in enumerate(extracted_claims):
            threat_intel = await _retrieve_threat_intel_for_claim(claim, rag_pipeline)
            claim_intel_map[index] = threat_intel
            threat_intel_matches.append(
                {
                    "claim_index": index,
                    "claim_type": claim.get("claim_type"),
                    "extracted_value": claim.get("extracted_value"),
                    "threat_intel": threat_intel,
                }
            )

        # Combine intelligence for downstream scoring and verification.
        combined_intel: dict[str, Any] = {
            "nvd": {},
            "kev": {},
            "attack": {},
        }
        for intel in claim_intel_map.values():
            if "nvd" in intel and intel["nvd"]:
                combined_intel["nvd"] = intel["nvd"]
            if "kev" in intel and intel["kev"]:
                combined_intel["kev"] = intel["kev"]
            if "attack" in intel and intel["attack"]:
                combined_intel["attack"] = intel["attack"]

        # Step 3: Deterministic validation across claims.
        validator = DeterministicValidator()
        deterministic_results: list[RuleResult] = []
        cve_claims = [claim for claim in extracted_claims if claim.get("claim_type") == "cve"]
        attack_claims = [claim for claim in extracted_claims if claim.get("claim_type") == "attack_id"]

        if cve_claims:
            deterministic_results.extend(
                await validator.validate(cve_claims, combined_intel.get("nvd", {}))
            )
        if attack_claims:
            deterministic_results.extend(
                await validator.validate(attack_claims, combined_intel.get("attack", {}))
            )

        # Step 4: Semantic validation using mitigation relevance.
        semantic_results: list[RuleResult] = []
        evidence_texts = []
        for intel in claim_intel_map.values():
            evidence_texts.extend(_flatten_threat_intel_texts(intel))
        if evidence_texts:
            scorer = SemanticScorer(profile_name=request.context.policy_profile)
            semantic_validation = await scorer.score(request.llm_output, evidence_texts)
            semantic_results.append(
                RuleResult(
                    rule_id="semantic_validation",
                    passed=semantic_validation.passed,
                    evidence=f"Semantic similarity {semantic_validation.similarity:.4f} vs threshold {semantic_validation.threshold:.4f}",
                    confidence=semantic_validation.similarity,
                    signal=RuleSignal.MITIGATION_RELEVANCE,
                    hard_fail=False,
                    correction_candidates=[],
                    metadata={
                        "model_name": semantic_validation.model_name,
                        "threshold": semantic_validation.threshold,
                    },
                )
            )

        # Step 5: LLM verifier checks.
        verifier = await llm_verifier.verify(request.llm_output, evidence_texts, combined_intel)
        verifier_result = RuleResult(
            rule_id="llm_verification",
            passed=not verifier.contradiction_detected,
            evidence=verifier.explanation,
            confidence=max(0.0, min(1.0, 1.0 - float(verifier.contradiction_prob))),
            signal=None,
            hard_fail=verifier.contradiction_detected,
            correction_candidates=[],
            metadata={
                "provider": verifier.provider,
                "latency_ms": verifier.latency_ms,
                "skipped": verifier.skipped,
            },
        )

        all_results: list[RuleResult] = []
        all_results.extend(deterministic_results)
        all_results.extend(semantic_results)
        all_results.append(verifier_result)

        # Step 6: Decision engine computes final outcome.
        decision_result = await decide(all_results, profile_name=request.context.policy_profile)

        # Step 7: Explainability report.
        latency_ms = (time.perf_counter() - start_time) * 1000
        report = await report_builder.build_report_from_models(
            decision_id=decision_id,
            decision=decision_result,
            validation_results=all_results,
            threat_intel_matches=threat_intel_matches,
            processing_latency_ms=round(latency_ms, 2),
        )
        analyst_rationale = report.analyst_rationale
        rule_trace = report.rule_trace
        source_citations = report.citations

        corrections: list[str] = []
        if decision_result.correction is not None:
            corrections.append(decision_result.correction.value)
        for result in all_results:
            corrections.extend(result.correction_candidates)
        corrections = [value for value in dict.fromkeys(corrections)]

        # Step 8: Audit log append.
        audit_session = await get_db_session()
        audit_entry = None
        try:
            audit_log = get_audit_log(audit_session)
            await audit_log.initialize()
            audit_entry = await audit_log.append(
                decision_id=decision_id,
                record_data={
                    "decision_id": decision_id,
                    "alert_id": request.context.alert_id,
                    "llm_output": request.llm_output,
                    "claims": extracted_claims,
                    "validation_results": [result.model_dump() for result in all_results],
                    "outcome": decision_result.outcome,
                    "risk_score": decision_result.risk_score,
                    "analyst_rationale": analyst_rationale,
                    "rule_trace": rule_trace,
                    "source_citations": source_citations,
                    "corrections": corrections,
                    "policy_profile": request.context.policy_profile,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
        finally:
            if audit_session is not None:
                await audit_session.close()

        audit_hash = audit_entry.curr_hash if audit_entry is not None else ""

        # Step 9: Persist decision.
        stored_decision = StoredDecision(
            decision_id=decision_id,
            alert_id=request.context.alert_id,
            llm_output=request.llm_output,
            outcome=decision_result.outcome,
            risk_score=decision_result.risk_score,
            validation_results=[result.model_dump() for result in all_results],
            analyst_rationale=analyst_rationale,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by="system",
        )
        await save_decision(
            stored_decision,
            policy_profile_name=decision_result.applied_profile,
            correction_candidate=decision_result.correction.model_dump() if decision_result.correction else None,
        )

        return AnalyzeResponse(
            decision_id=decision_id,
            outcome=decision_result.outcome,
            risk_score=decision_result.risk_score,
            claims=[_claim_to_response(claim) for claim in extracted_claims],
            analyst_rationale=analyst_rationale,
            rule_trace=rule_trace,
            source_citations=source_citations,
            corrections=corrections,
            audit_hash=audit_hash,
            latency_ms=round(latency_ms, 2),
        )

    except ValueError as e:
        logger.warning(f"Analyze request error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid analyze request: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Analyze endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis pipeline failed",
        )