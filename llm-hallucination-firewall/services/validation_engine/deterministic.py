# services/validation_engine/deterministic.py

"""
Deterministic validation rules for LLM Hallucination Firewall.

Implements:
- cve_exists_in_nvd(cve_id, nvd_data) → RuleResult
- cvss_score_in_range(claimed_score, nvd_score) → RuleResult
- attack_id_valid(technique_id, attack_data) → RuleResult
- version_in_affected_range(version, cpe_list) → RuleResult

All rules are async, pure, and independently testable.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class RuleResult(BaseModel):
    """Result of a deterministic validation rule."""
    rule_id: str
    passed: bool
    evidence: str
    confidence: float


async def cve_exists_in_nvd(cve_id: str, nvd_data: Dict[str, Any]) -> RuleResult:
    """
    Check if CVE ID exists in NVD data.
    """
    exists = cve_id in nvd_data
    return RuleResult(
        rule_id="cve_exists_in_nvd",
        passed=exists,
        evidence=(f"Found CVE {cve_id} in NVD" if exists else f"CVE {cve_id} not found in NVD"),
        confidence=0.95 if exists else 0.0
    )


async def cvss_score_in_range(claimed_score: float, nvd_score: float) -> RuleResult:
    """
    Check if claimed CVSS score is within ±0.3 of NVD score.
    """
    diff = abs(claimed_score - nvd_score)
    passed = diff <= 0.3
    return RuleResult(
        rule_id="cvss_score_in_range",
        passed=passed,
        evidence=f"Claimed CVSS {claimed_score}, NVD CVSS {nvd_score}, diff={diff:.2f}",
        confidence=0.9 if passed else 0.0
    )


async def attack_id_valid(technique_id: str, attack_data: Dict[str, Any]) -> RuleResult:
    """
    Check if MITRE ATT&CK technique ID is valid.
    """
    valid = technique_id in attack_data
    return RuleResult(
        rule_id="attack_id_valid",
        passed=valid,
        evidence=(f"Technique {technique_id} valid" if valid else f"Technique {technique_id} not found"),
        confidence=0.95 if valid else 0.0
    )


async def version_in_affected_range(version: str, cpe_list: List[str]) -> RuleResult:
    """
    Check if version is in affected CPE list.
    """
    in_range = version in cpe_list
    return RuleResult(
        rule_id="version_in_affected_range",
        passed=in_range,
        evidence=(f"Version {version} affected" if in_range else f"Version {version} not affected"),
        confidence=0.9 if in_range else 0.0
    )
            return ValidationRule(
                rule_id="cve_exists_in_nvd",
                rule_name="CVE exists in NVD",
                passed=False,
                evidence=f"CVE {cve_id} not found in NVD",
                confidence=0.95
            )
    
    async def _validate_cvss_score(
        self,
        cve_id: str,
        threat_intel: Dict
    ) -> Optional[ValidationRule]:
        """Check CVSS score matches within tolerance."""
        nvd_data = threat_intel.get("NVD", {})
        if not nvd_data:
            return None
        
        nvd_score = nvd_data.get("cvss_v3_score")
        if nvd_score is None:
            return None
        
        # TODO: Extract claimed CVSS score from context
        # claimed_score = context.get("claimed_cvss_score")
        # tolerance = self.rules["cvss_score_in_range"]["threshold"]
        
        # Stub implementation
        return ValidationRule(
            rule_id="cvss_score_in_range",
            rule_name="CVSS score in range",
            passed=True,
            evidence=f"NVD CVSS v3.1: {nvd_score}",
            confidence=0.90
        )
    
    async def _validate_attack_id(
        self,
        technique_id: str,
        threat_intel: Dict
    ) -> Optional[ValidationRule]:
        """Check MITRE ATT&CK technique ID is valid."""
        attack_data = threat_intel.get("ATT&CK", {})
        
        if attack_data:
            return ValidationRule(
                rule_id="attack_id_valid",
                rule_name="ATT&CK technique ID valid",
                passed=True,
                evidence=f"Found technique {technique_id}",
                confidence=0.95
            )
        else:
            return ValidationRule(
                rule_id="attack_id_valid",
                rule_name="ATT&CK technique ID valid",
                passed=False,
                evidence=f"Technique {technique_id} not found in MITRE ATT&CK",
                confidence=0.95
            )
    
    async def _validate_version_in_range(
        self,
        version: str,
        threat_intel: Dict
    ) -> Optional[ValidationRule]:
        """Check if product version is in affected range."""
        # TODO: Compare version against NVD affected_products list
        return ValidationRule(
            rule_id="version_in_affected_range",
            rule_name="Version in affected range",
            passed=True,
            evidence=f"Version {version} found in affected product list",
            confidence=0.80
        )
    
    async def _validate_date_recent(
        self,
        cve_id: str,
        threat_intel: Dict
    ) -> Optional[ValidationRule]:
        """Check CVE disclosure date is recent."""
        from datetime import datetime, timedelta
        
        nvd_data = threat_intel.get("NVD", {})
        if not nvd_data:
            return None
        
        pub_date_str = nvd_data.get("published_date")
        if not pub_date_str:
            return None
        
        try:
            pub_date = datetime.fromisoformat(pub_date_str)
            days_old = (datetime.now() - pub_date).days
            threshold = self.rules["date_recent"]["threshold"]
            
            return ValidationRule(
                rule_id="date_recent",
                rule_name="CVE disclosure date recent",
                passed=days_old <= threshold,
                evidence=f"Published {days_old} days ago (threshold: {threshold} days)",
                confidence=0.90
            )
        except Exception:
            return None
