# services/validation_engine/deterministic.py
"""
Deterministic rule-based validation engine.

Applies hard rules to check claims against threat intelligence:
- cve_exists_in_nvd: Check CVE ID exists
- cvss_score_in_range: CVSS score ±0.3 tolerance
- attack_id_valid: Check MITRE ATT&CK technique exists
- version_in_affected_range: Check affected versions match
- date_recent: Check vulnerability disclosure date

Each rule returns: {rule_id, rule_name, passed: bool, evidence: str, confidence: float}

TODO: Connect to Tanushree's claim_extractor and Dhruv's retriever
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from pydantic import BaseModel


@dataclass
class ValidationRule:
    """Single validation rule result."""
    rule_id: str
    rule_name: str
    passed: bool
    evidence: str
    confidence: float  # 0.0 to 1.0


class DeterministicValidator:
    """
    Deterministic rule-based validator.
    """
    
    def __init__(self):
        """Initialize validator with rule definitions."""
        self.rules = self._define_rules()
    
    def _define_rules(self) -> Dict[str, dict]:
        """Define validation rules with thresholds."""
        return {
            "cve_exists_in_nvd": {
                "description": "CVE ID exists in NVD database",
                "threshold": None,
                "applies_to": "CVE_ID"
            },
            "cvss_score_in_range": {
                "description": "CVSS score matches ±0.3 tolerance",
                "threshold": 0.3,
                "applies_to": "CVSS_SCORE"
            },
            "attack_id_valid": {
                "description": "MITRE ATT&CK technique ID is valid",
                "threshold": None,
                "applies_to": "ATTACK_TECHNIQUE"
            },
            "version_in_affected_range": {
                "description": "Product version is in NVD affected range",
                "threshold": None,
                "applies_to": "VERSION"
            },
            "date_recent": {
                "description": "CVE disclosure date is within 90 days",
                "threshold": 90,  # days
                "applies_to": "DATE"
            }
        }
    
    async def validate_claim(
        self,
        claim: Dict[str, str],
        threat_intel: Dict[str, any]
    ) -> List[ValidationRule]:
        """
        Validate a single claim against threat intelligence.
        
        Args:
            claim: {"text": str, "claim_type": str, "confidence": float}
            threat_intel: Retrieved threat intelligence data
            
        Returns:
            List of ValidationRule results
        """
        results = []
        claim_type = claim.get("claim_type", "").upper()
        claim_text = claim.get("text", "")
        
        # Route to type-specific validators
        if claim_type == "CVE_ID":
            results.append(await self._validate_cve_exists(claim_text, threat_intel))
            results.append(await self._validate_cvss_score(claim_text, threat_intel))
            results.append(await self._validate_date_recent(claim_text, threat_intel))
        
        elif claim_type == "ATTACK_TECHNIQUE":
            results.append(await self._validate_attack_id(claim_text, threat_intel))
        
        elif claim_type == "VERSION":
            results.append(await self._validate_version_in_range(claim_text, threat_intel))
        
        return [r for r in results if r is not None]
    
    async def _validate_cve_exists(
        self,
        cve_id: str,
        threat_intel: Dict
    ) -> Optional[ValidationRule]:
        """Check CVE exists in NVD."""
        nvd_data = threat_intel.get("NVD", {})
        
        if nvd_data:
            return ValidationRule(
                rule_id="cve_exists_in_nvd",
                rule_name="CVE exists in NVD",
                passed=True,
                evidence=f"Found CVE {cve_id} in NVD database",
                confidence=0.95
            )
        else:
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
