# services/claim_extractor/models.py
"""
Claim extraction data models and schemas.

Defines structured claim representations extracted from unstructured LLM outputs.
"""

from typing import Optional, List
from dataclasses import dataclass
from pydantic import BaseModel, Field


@dataclass
class Claim:
    """Extracted claim from LLM output."""
    claim_id: str
    text: str
    claim_type: str  # CVE_ID, ATTACK_TECHNIQUE, SEVERITY, REMEDIATION, AFFECTED_VERSION, etc.
    confidence: float  # 0.0 to 1.0, based on extraction model confidence
    span_start: int  # Character position in original text
    span_end: int
    evidence_tokens: List[str]  # Supporting tokens/entities from NER


class ClaimRequest(BaseModel):
    """Request to extract claims from text."""
    text: str = Field(..., min_length=1, description="Unstructured LLM output")
    enable_ner: bool = Field(default=True, description="Use spaCy NER pipeline")
    enable_span_extraction: bool = Field(default=True, description="Use BERT for claim span extraction")
    model_version: str = Field(default="v1", description="Extraction model version")


class ClaimResponse(BaseModel):
    """Response with extracted claims."""
    input_text: str
    claims: List[dict] = Field(default_factory=list)
    extraction_timestamp: str
    latency_ms: float
    model_version: str


class CVEClaim(BaseModel):
    """Specific claim for CVE identification."""
    cve_id: str = Field(..., pattern=r"CVE-\d{4}-\d{4,}")
    severity: Optional[str] = None  # CRITICAL, HIGH, MEDIUM, LOW
    base_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    affected_products: Optional[List[str]] = None


class AttackTechniqueClaim(BaseModel):
    """Specific claim for MITRE ATT&CK technique."""
    technique_id: str = Field(..., pattern=r"T\d{4}")
    tactic: Optional[str] = None
    description: Optional[str] = None
    related_cves: Optional[List[str]] = None


class SeverityClaim(BaseModel):
    """Claim about threat severity."""
    severity_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    rationale: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
