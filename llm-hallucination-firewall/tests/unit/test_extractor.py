"""
Unit tests for ClaimExtractor pipeline.
"""
import pytest
from services.claim_extractor.extractor import ClaimExtractor
from services.claim_extractor.models import ClaimRequest

@pytest.mark.asyncio
def test_valid_cve_extraction():
    extractor = ClaimExtractor()
    req = ClaimRequest(text="This affects CVE-2023-12345.")
    resp = extractor.extract(req)
    assert any('CVE-2023-12345' in c['text'] for c in resp.claims)

@pytest.mark.asyncio
def test_invalid_cve_extraction():
    extractor = ClaimExtractor()
    req = ClaimRequest(text="This affects CVE-2023-12.")
    resp = extractor.extract(req)
    assert not any('CVE-2023-12' in c['text'] for c in resp.claims)

@pytest.mark.asyncio
def test_cvss_extraction():
    extractor = ClaimExtractor()
    req = ClaimRequest(text="CVSS v3.1: 7.8")
    resp = extractor.extract(req)
    assert any(c['claim_type'] == 'CVSS_SCORE' for c in resp.claims)

@pytest.mark.asyncio
def test_attack_id_extraction():
    extractor = ClaimExtractor()
    req = ClaimRequest(text="Technique T1059 was used.")
    resp = extractor.extract(req)
    assert any(c['claim_type'] == 'ATTACK_TECHNIQUE' for c in resp.claims)

@pytest.mark.asyncio
def test_empty_input():
    extractor = ClaimExtractor()
    req = ClaimRequest(text=" ")
    resp = extractor.extract(req)
    assert resp.claims == []
