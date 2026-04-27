from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CVEClaim(BaseModel):
    id: str
    claimed_severity: str | None = None
    exists: bool = True
    actual_severity: str | None = None
    in_kev: bool = False


class AttackMappingClaim(BaseModel):
    technique_id: str
    claimed_name: str | None = None
    exists: bool = True
    actual_name: str | None = None


class MitigationClaim(BaseModel):
    text: str
    relevance: Literal["low", "medium", "high"] = "medium"
    risk: Literal["low", "medium", "high"] = "medium"


class ClaimsPayload(BaseModel):
    cves: list[CVEClaim] = Field(default_factory=list)
    attack_mappings: list[AttackMappingClaim] = Field(default_factory=list)
    mitigations: list[MitigationClaim] = Field(default_factory=list)


class ValidateRequest(BaseModel):
    raw_recommendation: str = ""
    source: str = "demo-ui"
    scenario_id: str | None = None
    expected_decision: str | None = None
    claims: ClaimsPayload


class ValidateResponse(BaseModel):
    decision: Literal["allow", "flag", "block", "correct"]
    confidence: float
    risk_score: int
    reasoning: list[str]
    failed_rules: list[str]
    corrections: list[str]
    metrics: dict


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
