"""Extraction endpoint for claim extraction from LLM output."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from services.claim_extractor.extractor import extract_claims

from models import ExtractRequest, ExtractResponse, ExtractedClaimResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/extract",
    response_model=ExtractResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract claims from LLM-generated text",
    tags=["Extraction"],
)
async def extract_endpoint(request: ExtractRequest) -> ExtractResponse:
    """
    Extract security claims (CVE, ATT&CK, CVSS, etc.) from LLM-generated text.

    Uses a three-pass pipeline:
    1. Regex patterns for structured identifiers (CVE, CVSS, T-codes)
    2. spaCy NER with security-specific entity patterns
    3. BERT token classification for mitigation and urgency claims

    Args:
        request: ExtractRequest with LLM output text and extraction config

    Returns:
        ExtractResponse with extracted claims, timestamps, and latency metrics

    Raises:
        HTTPException: If extraction fails or text validation fails
    """
    try:
        start_time = time.perf_counter()

        # Call Tanushree's extraction pipeline
        extracted_claims = await extract_claims(request.text)

        # Convert to response model
        response_claims = [
            ExtractedClaimResponse(
                claim_type=claim.claim_type.value,
                raw_text=claim.raw_text,
                extracted_value=claim.extracted_value,
                position=claim.position,
                confidence=claim.confidence,
                metadata=claim.metadata,
            )
            for claim in extracted_claims
        ]

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ExtractResponse(
            input_text=request.text,
            claims=response_claims,
            extraction_timestamp=datetime.now(timezone.utc).isoformat(),
            latency_ms=round(elapsed_ms, 2),
            model_version=request.model_version,
        )

    except ValueError as e:
        logger.warning(f"Extraction validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid extraction request: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Extraction endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Extraction pipeline failed",
        )
