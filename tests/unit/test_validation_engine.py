"""Unit tests for deterministic validation compatibility wrappers."""

from __future__ import annotations

import asyncio

import pytest

from services.validation_engine.deterministic import DeterministicValidator


@pytest.fixture
def validator() -> DeterministicValidator:
    """Return a validator instance for legacy-compatibility tests."""
    return DeterministicValidator()


def test_cve_exists_rule(validator: DeterministicValidator) -> None:
    """Validate the legacy CVE existence path against dict-based threat intel."""
    claims = [
        {
            "claim_id": "claim-001",
            "text": "CVE-2024-1234",
            "claim_type": "CVE_ID",
            "confidence": 0.95,
        }
    ]
    threat_intel = {
        "cves": {
            "CVE-2024-1234": {"base_score": 9.8},
        }
    }

    results = asyncio.run(validator.validate(claims, threat_intel))
    cve_rule = next((result for result in results if result.rule_id == "cve_exists_in_nvd"), None)

    assert cve_rule is not None
    assert cve_rule.passed


def test_cvss_score_rule(validator: DeterministicValidator) -> None:
    """Validate the legacy CVSS tolerance path."""
    claims = [
        {
            "claim_id": "claim-001",
            "text": "9.8",
            "claim_type": "CVSS_SCORE",
            "confidence": 0.90,
        }
    ]
    threat_intel = {
        "cvss_score": 9.9,
    }

    results = asyncio.run(validator.validate(claims, threat_intel))
    cvss_rule = next((result for result in results if result.rule_id == "cvss_score_in_range"), None)

    assert cvss_rule is not None
    assert cvss_rule.passed
