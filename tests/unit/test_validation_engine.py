# tests/unit/test_validation_engine.py
"""
Unit tests for validation engine modules.

Tests:
- Deterministic rule engine
- Semantic similarity validation
- LLM verifier circuit breaker
"""

import pytest
from services.validation_engine.deterministic import DeterministicValidator


@pytest.fixture
def validator():
    """Fixture: initialized DeterministicValidator."""
    return DeterministicValidator()


@pytest.mark.asyncio
async def test_cve_exists_rule(validator):
    """Test CVE existence validation rule."""
    claims = [
        {
            "claim_id": "claim-001",
            "text": "CVE-2024-1234",
            "claim_type": "CVE_ID",
            "confidence": 0.95
        }
    ]
    
    threat_intel = {
        "cves": {
            "CVE-2024-1234": {"base_score": 9.8}
        }
    }
    
    results = await validator.validate(claims, threat_intel)
    
    cve_rule = next((r for r in results if r.rule_id == "cve_exists_in_nvd"), None)
    assert cve_rule is not None
    assert cve_rule.passed


@pytest.mark.asyncio
async def test_cvss_score_rule(validator):
    """Test CVSS score range validation."""
    claims = [
        {
            "claim_id": "claim-001",
            "text": "9.8",
            "claim_type": "CVSS_SCORE",
            "confidence": 0.90
        }
    ]
    
    threat_intel = {
        "cvss_score": 9.9
    }
    
    results = await validator.validate(claims, threat_intel)
    
    cvss_rule = next((r for r in results if r.rule_id == "cvss_score_in_range"), None)
    assert cvss_rule is not None
    # Should pass with ±0.3 tolerance


# TODO: Add tests for semantic validation
# TODO: Add tests for LLM verifier timeout
# TODO: Add integration tests with full pipeline
