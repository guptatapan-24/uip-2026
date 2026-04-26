"""Shared Pydantic models used across extraction, validation, and decisioning."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ClaimType(str, Enum):
    """Supported claim types emitted by the extraction pipeline."""

    CVE = "cve"
    ATTACK_ID = "attack_id"
    CVSS = "cvss_score"
    PRODUCT = "product"
    VERSION = "version"
    SEVERITY = "severity"
    MITIGATION = "mitigation"
    URGENCY = "urgency"


class Claim(BaseModel):
    """Structured claim emitted by any extraction pass."""

    claim_type: ClaimType
    raw_text: str
    extracted_value: str
    position: tuple[int, int]
    confidence: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleSignal(str, Enum):
    """Decision-engine scoring dimensions."""

    CVE_VALIDITY = "cve_validity"
    SEVERITY_ACCURACY = "severity_accuracy"
    MITIGATION_RELEVANCE = "mitigation_relevance"
    URGENCY_CONSISTENCY = "urgency_consistency"


class RuleResult(BaseModel):
    """Atomic validation outcome returned by a deterministic or semantic rule."""

    rule_id: str
    passed: bool
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)
    signal: RuleSignal | None = None
    hard_fail: bool = False
    correction_candidates: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrectionCandidate(BaseModel):
    """Candidate correction surfaced by the decision engine."""

    value: str
    reason: str
    score: float = Field(ge=0.0, le=1.0)


class DecisionResult(BaseModel):
    """Final decision returned by the policy-driven decision engine."""

    outcome: Literal["ALLOW", "FLAG", "BLOCK", "CORRECT"]
    risk_score: float = Field(ge=0.0, le=1.0)
    correction: CorrectionCandidate | None = None
    applied_profile: str
    signal_scores: dict[str, float] = Field(default_factory=dict)
    hard_fail_rule_ids: list[str] = Field(default_factory=list)
    rationale: str


class SemanticValidationResult(BaseModel):
    """Similarity-based validation result for mitigation relevance."""

    claim_text: str
    evidence_text: str
    similarity: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    passed: bool
    model_name: str
    policy_profile: str


class CalibrationPair(BaseModel):
    """Labeled claim/evidence pair for semantic threshold calibration."""

    claim_text: str
    evidence_text: str
    label: bool


class ThresholdMetrics(BaseModel):
    """Metrics for one semantic threshold candidate."""

    threshold: float = Field(ge=0.0, le=1.0)
    accuracy: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    tp: int
    tn: int
    fp: int
    fn: int


class CalibrationReport(BaseModel):
    """Chosen semantic threshold and the candidate metric table."""

    selected_threshold: float = Field(ge=0.0, le=1.0)
    target_threshold: float = Field(ge=0.0, le=1.0)
    objective: str
    metrics: list[ThresholdMetrics]
    profile_name: str


class BenchmarkValidationInput(BaseModel):
    """Structured validation inputs for one synthetic benchmark case."""

    cve_id: str | None = None
    known_cves: list[str] = Field(default_factory=list)
    claimed_cvss: float | None = None
    nvd_cvss: float | None = None
    technique_id: str | None = None
    known_attack_ids: list[str] = Field(default_factory=list)
    version: str | None = None
    cpe_list: list[str | dict[str, Any]] = Field(default_factory=list)
    mitigation_text: str | None = None
    mitigation_mapping_data: dict[str, list[str]] = Field(default_factory=dict)
    evidence_texts: list[str] = Field(default_factory=list)
    severity: str | None = None
    urgency_expected: bool | None = None
    urgency_text_present: bool | None = None


class BenchmarkCase(BaseModel):
    """One synthetic benchmark scenario used for ablation runs."""

    id: str
    text: str
    expected_outcome: Literal["ALLOW", "FLAG", "BLOCK", "CORRECT"]
    hallucinated: bool
    expected_claim_types: list[ClaimType] = Field(default_factory=list)
    validation: BenchmarkValidationInput


class BenchmarkRunResult(BaseModel):
    """Per-case result from one benchmark run."""

    case_id: str
    expected_outcome: str
    actual_outcome: str
    hallucinated: bool
    extraction_recall: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)


class BenchmarkSummary(BaseModel):
    """Aggregate benchmark metrics for one system configuration."""

    scenario_name: str
    case_count: int
    hallucination_catch_rate: float = Field(ge=0.0, le=1.0)
    false_approval_rate: float = Field(ge=0.0, le=1.0)
    false_block_rate: float = Field(ge=0.0, le=1.0)
    decision_consistency: float = Field(ge=0.0, le=1.0)
    extraction_recall: float = Field(ge=0.0, le=1.0)
    results: list[BenchmarkRunResult] = Field(default_factory=list)
