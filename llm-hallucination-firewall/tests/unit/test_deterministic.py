"""
Unit tests for deterministic validation rules.
"""
import pytest
from services.validation_engine import deterministic

@pytest.mark.asyncio
def test_cve_exists_in_nvd():
    result = deterministic.cve_exists_in_nvd("CVE-2023-12345", {"cves": {"CVE-2023-12345": {}}})
    assert result.passed
    result = deterministic.cve_exists_in_nvd("CVE-2023-99999", {"cves": {}})
    assert not result.passed

@pytest.mark.asyncio
def test_cvss_score_in_range():
    result = deterministic.cvss_score_in_range(7.5, 7.6)
    assert result.passed
    result = deterministic.cvss_score_in_range(7.5, 8.0)
    assert not result.passed

@pytest.mark.asyncio
def test_attack_id_valid():
    result = deterministic.attack_id_valid("T1059", {"techniques": {"T1059": {}}})
    assert result.passed
    result = deterministic.attack_id_valid("T9999", {"techniques": {}})
    assert not result.passed

@pytest.mark.asyncio
def test_version_in_affected_range():
    result = deterministic.version_in_affected_range("1.2.3", [{"version": "1.2.3"}, {"version": "1.2.4"}])
    assert result.passed
    result = deterministic.version_in_affected_range("2.0.0", [{"version": "1.2.3"}, {"version": "1.2.4"}])
    assert not result.passed
