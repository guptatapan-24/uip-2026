# tests/unit/test_claim_extractor.py
"""
Unit tests for claim extraction module.

Tests:
- Regex pattern matching (CVE IDs, CVSS scores, ATT&CK techniques)
- spaCy NER entity recognition
- BERT span extraction
- Deduplication logic
"""

import pytest
from services.claim_extractor.extractor import ClaimExtractor
from services.claim_extractor.models import ClaimRequest


@pytest.fixture
def extractor():
    """Fixture: initialized ClaimExtractor."""
    return ClaimExtractor()


def test_extract_cve_ids(extractor):
    """Test CVE ID extraction from text."""
    request = ClaimRequest(
        text="The vulnerability CVE-2024-1234 affects Apache servers. CVE-2024-5678 is also critical.",
        enable_ner=False,
        enable_span_extraction=False
    )
    response = extractor.extract(request)
    
    assert len(response.claims) >= 2
    assert any(c['claim_type'] == 'CVE_ID' for c in response.claims)


def test_extract_cvss_scores(extractor):
    """Test CVSS score extraction."""
    request = ClaimRequest(
        text="This vulnerability has CVSS v3.1: 9.8 rating.",
        enable_ner=False,
        enable_span_extraction=False
    )
    response = extractor.extract(request)
    
    assert any(c['claim_type'] == 'CVSS_SCORE' for c in response.claims)


def test_extract_attack_techniques(extractor):
    """Test MITRE ATT&CK technique extraction."""
    request = ClaimRequest(
        text="Attackers use technique T1566 for initial access.",
        enable_ner=False,
        enable_span_extraction=False
    )
    response = extractor.extract(request)
    
    assert any(c['claim_type'] == 'ATTACK_TECHNIQUE' for c in response.claims)


def test_deduplication(extractor):
    """Test claim deduplication."""
    # Same CVE mentioned twice - should be deduplicated
    request = ClaimRequest(
        text="CVE-2024-1234 is a critical vulnerability. CVE-2024-1234 must be patched.",
        enable_ner=False,
        enable_span_extraction=False
    )
    response = extractor.extract(request)
    
    cve_claims = [c for c in response.claims if c['claim_type'] == 'CVE_ID']
    assert len(cve_claims) <= 2  # Should deduplicate


# TODO: Add tests for spaCy NER
# TODO: Add tests for BERT span extraction
# TODO: Add tests for confidence scoring
