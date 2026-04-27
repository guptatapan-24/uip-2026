"""Pydantic v2 request/response models for the LLM Hallucination Firewall API."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# EXTRACTION ENDPOINT MODELS
# ============================================================================


class ExtractRequest(BaseModel):
    """Request to extract claims from LLM-generated text."""

    text: str = Field(..., min_length=1, description="LLM-generated security text")
    enable_ner: bool = Field(default=True, description="Use spaCy NER pipeline")
    enable_span_extraction: bool = Field(
        default=True, description="Use BERT for claim span extraction"
    )
    model_version: str = Field(default="v1", description="Extraction model version")

    @field_validator("text")
    @classmethod
    def text_not_blank(cls, v: str) -> str:
        """Ensure text is not just whitespace."""
        if not v or not v.strip():
            raise ValueError("text must contain non-whitespace characters")
        return v


class ExtractedClaimResponse(BaseModel):
    """Single extracted claim from the extraction pipeline."""

    claim_type: str
    raw_text: str
    extracted_value: str
    position: tuple[int, int]
    confidence: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExtractResponse(BaseModel):
    """Response with extracted claims."""

    input_text: str
    claims: list[ExtractedClaimResponse]
    extraction_timestamp: str
    latency_ms: float
    model_version: str


# ============================================================================
# VALIDATION ENDPOINT MODELS
# ============================================================================


class ValidationContext(BaseModel):
    """Context for validation decisions."""

    alert_id: str = Field(..., description="Unique alert identifier")
    severity_hint: str | None = Field(
        None, description="Alert severity: CRITICAL, HIGH, MEDIUM, LOW"
    )
    policy_profile: str = Field(
        default="default", description="Policy profile name for decision thresholds"
    )


class ValidateRequest(BaseModel):
    """Request to validate extracted claims against threat intelligence."""

    llm_output: str = Field(
        ..., min_length=1, description="LLM-generated security recommendation"
    )
    extracted_claims: list[ExtractedClaimResponse] | None = Field(
        None, description="Pre-extracted claims (optional; extracted if omitted)"
    )
    context: ValidationContext
    nvd_data: dict[str, Any] | None = Field(
        None, description="Optional NVD data payload for deterministic validation"
    )
    attack_data: dict[str, Any] | None = Field(
        None, description="Optional ATT&CK data payload for technique validation"
    )

    @field_validator("llm_output")
    @classmethod
    def llm_output_not_blank(cls, v: str) -> str:
        """Ensure llm_output is not just whitespace."""
        if not v or not v.strip():
            raise ValueError("llm_output must contain non-whitespace characters")
        return v


class RuleResultResponse(BaseModel):
    """Single validation rule outcome."""

    rule_id: str
    passed: bool
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)
    signal: str | None = None
    hard_fail: bool = False
    correction_candidates: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidateResponse(BaseModel):
    """Response with validation results."""

    alert_id: str
    deterministic_rules: list[RuleResultResponse]
    semantic_validation: RuleResultResponse | None = None
    total_latency_ms: float


# ============================================================================
# DECISION ENDPOINT MODELS
# ============================================================================


class CorrectionCandidateResponse(BaseModel):
    """Candidate correction surfaced by the decision engine."""

    value: str
    reason: str
    score: float = Field(ge=0.0, le=1.0)


class DecideRequest(BaseModel):
    """Request to generate a final validation decision."""

    alert_id: str = Field(..., description="Unique alert identifier")
    validation_results: list[RuleResultResponse] = Field(
        ..., description="Validation rule results from /validate"
    )
    policy_profile: str = Field(
        default="default", description="Policy profile name for decision thresholds"
    )


class DecisionResponse(BaseModel):
    """Final decision from the policy-driven decision engine."""

    alert_id: str
    outcome: Literal["ALLOW", "FLAG", "BLOCK", "CORRECT"]
    risk_score: float = Field(ge=0.0, le=1.0)
    correction: CorrectionCandidateResponse | None = None
    applied_profile: str
    signal_scores: dict[str, float] = Field(default_factory=dict)
    hard_fail_rule_ids: list[str] = Field(default_factory=list)
    rationale: str
    decision_timestamp: str
    latency_ms: float


# ============================================================================
# HEALTH CHECK MODELS
# ============================================================================


class HealthStatus(str, Enum):
    """Health status enumeration."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class DependencyStatus(BaseModel):
    """Status of a single dependency."""

    name: str
    status: HealthStatus
    message: str | None = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: HealthStatus
    timestamp: str
    version: str
    dependencies: list[DependencyStatus]
    uptime_seconds: float
