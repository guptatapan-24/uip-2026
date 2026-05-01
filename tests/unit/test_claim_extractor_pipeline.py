"""Unit tests for the three-pass claim extraction pipeline."""

from __future__ import annotations

import asyncio

from services.claim_extractor.extractor import extract_claims
from services.common.models import ClaimType


def test_extracts_valid_cve() -> None:
    claims = asyncio.run(extract_claims("Investigate CVE-2023-23397 on Outlook."))
    assert any(claim.claim_type == ClaimType.CVE and claim.extracted_value == "CVE-2023-23397" for claim in claims)


def test_invalid_cve_is_not_extracted() -> None:
    claims = asyncio.run(extract_claims("Investigate CVE-23-23397 before rollout."))
    assert all(claim.claim_type != ClaimType.CVE for claim in claims)


def test_extracts_cvss_score() -> None:
    claims = asyncio.run(extract_claims("The vendor lists CVSS 9.8 for this issue."))
    assert any(claim.claim_type == ClaimType.CVSS and claim.extracted_value == "9.8" for claim in claims)


def test_extracts_attack_id() -> None:
    claims = asyncio.run(extract_claims("Observed ATT&CK technique T1190 during triage."))
    assert any(claim.claim_type == ClaimType.ATTACK_ID and claim.extracted_value.upper() == "T1190" for claim in claims)


def test_empty_input_returns_no_claims() -> None:
    assert asyncio.run(extract_claims("   ")) == []
