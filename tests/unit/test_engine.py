"""Unit tests for the policy-driven decision engine."""

from __future__ import annotations

import asyncio

from services.common.models import RuleResult, RuleSignal
from services.decision_engine.engine import decide


def _rule(
    rule_id: str,
    passed: bool,
    confidence: float,
    signal: RuleSignal,
    hard_fail: bool = False,
    correction_candidates: list[str] | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        passed=passed,
        evidence=f"{rule_id} evidence",
        confidence=confidence,
        signal=signal,
        hard_fail=hard_fail,
        correction_candidates=correction_candidates or [],
    )


def test_engine_returns_allow_for_high_score() -> None:
    result = asyncio.run(
        decide(
        [
            _rule("cve_exists_in_nvd", True, 0.95, RuleSignal.CVE_VALIDITY),
            _rule("cvss_score_in_range", True, 0.94, RuleSignal.SEVERITY_ACCURACY),
            _rule("mitigation_relevance", True, 0.9, RuleSignal.MITIGATION_RELEVANCE),
            _rule("urgency_consistency", True, 0.91, RuleSignal.URGENCY_CONSISTENCY),
        ]
        )
    )
    assert result.outcome == "ALLOW"


def test_engine_returns_flag_for_mid_score() -> None:
    result = asyncio.run(
        decide(
        [
            _rule("cve_exists_in_nvd", True, 0.78, RuleSignal.CVE_VALIDITY),
            _rule("cvss_score_in_range", True, 0.7, RuleSignal.SEVERITY_ACCURACY),
            _rule("mitigation_relevance", True, 0.66, RuleSignal.MITIGATION_RELEVANCE),
            _rule("urgency_consistency", True, 0.61, RuleSignal.URGENCY_CONSISTENCY),
        ]
        )
    )
    assert result.outcome == "FLAG"


def test_engine_returns_block_for_low_score_without_correction() -> None:
    result = asyncio.run(
        decide(
        [
            _rule("cve_exists_in_nvd", True, 0.4, RuleSignal.CVE_VALIDITY),
            _rule("cvss_score_in_range", False, 0.7, RuleSignal.SEVERITY_ACCURACY),
            _rule("mitigation_relevance", False, 0.8, RuleSignal.MITIGATION_RELEVANCE),
            _rule("urgency_consistency", True, 0.55, RuleSignal.URGENCY_CONSISTENCY),
        ]
        )
    )
    assert result.outcome == "BLOCK"


def test_engine_returns_correct_for_hard_fail_with_candidate() -> None:
    result = asyncio.run(
        decide(
        [
            _rule(
                "cve_exists_in_nvd",
                False,
                0.95,
                RuleSignal.CVE_VALIDITY,
                hard_fail=True,
                correction_candidates=["CVE-2023-23397"],
            ),
            _rule("cvss_score_in_range", True, 0.9, RuleSignal.SEVERITY_ACCURACY),
            _rule("mitigation_relevance", True, 0.8, RuleSignal.MITIGATION_RELEVANCE),
            _rule("urgency_consistency", True, 0.8, RuleSignal.URGENCY_CONSISTENCY),
        ]
        )
    )
    assert result.outcome == "CORRECT"
    assert result.correction is not None
