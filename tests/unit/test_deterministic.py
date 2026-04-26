"""Unit tests for deterministic validation rules."""

from __future__ import annotations

from services.validation_engine.deterministic import (
    attack_id_valid,
    cve_exists_in_nvd,
    cvss_score_in_range,
    mitigation_maps_to_attack,
    version_in_affected_range,
)


def test_cve_exists_in_nvd_passes_for_known_cve() -> None:
    result = cve_exists_in_nvd("CVE-2023-23397", {"cves": ["CVE-2023-23397"]})
    assert result.passed is True


def test_cve_exists_in_nvd_fails_for_unknown_cve() -> None:
    result = cve_exists_in_nvd("CVE-2099-99999", {"cves": ["CVE-2023-23397"]})
    assert result.passed is False
    assert result.hard_fail is True


def test_cvss_score_in_range_uses_tolerance() -> None:
    result = cvss_score_in_range(9.8, 9.6)
    assert result.passed is True


def test_attack_id_valid_checks_existence_and_format() -> None:
    result = attack_id_valid("T1190", {"techniques": ["T1190", "T1110"]})
    assert result.passed is True


def test_attack_id_valid_rejects_bad_format() -> None:
    result = attack_id_valid("TX190", {"techniques": ["T1190"]})
    assert result.passed is False


def test_version_in_affected_range_matches_exact_cpe_version() -> None:
    result = version_in_affected_range("2.14.1", ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"])
    assert result.passed is True


def test_version_in_affected_range_matches_range_dict() -> None:
    result = version_in_affected_range(
        "2.15.0",
        [{"versionStartIncluding": "2.14.0", "versionEndExcluding": "2.17.0"}],
    )
    assert result.passed is True


def test_mitigation_maps_to_attack_passes_for_relevant_action() -> None:
    result = mitigation_maps_to_attack(
        "Patch exposed Outlook systems and rotate credentials immediately",
        "T1110",
        {"T1110": ["patch exposed outlook systems", "rotate credentials"]},
    )
    assert result.passed is True


def test_mitigation_maps_to_attack_fails_for_irrelevant_action() -> None:
    result = mitigation_maps_to_attack(
        "Disable all outbound traffic for the finance network",
        "T1110",
        {"T1110": ["patch exposed outlook systems", "rotate credentials"]},
    )
    assert result.passed is False
