"""
Unit tests for DecisionEngine.
"""
import pytest
from services.decision_engine.engine import DecisionEngine
from services.common.models import RuleResult, RuleSignal

@pytest.mark.asyncio
async def test_allow_outcome():
    engine = DecisionEngine()
    rule_results = [
        RuleResult(rule_id="cve_validity", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.CVE_VALIDITY),
        RuleResult(rule_id="severity_accuracy", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.SEVERITY_ACCURACY),
        RuleResult(rule_id="mitigation_relevance", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.MITIGATION_RELEVANCE),
        RuleResult(rule_id="urgency_consistency", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.URGENCY_CONSISTENCY),
    ]
    result = await engine.decide(rule_results)
    assert result.outcome == "ALLOW"

@pytest.mark.asyncio
async def test_flag_outcome():
    engine = DecisionEngine()
    rule_results = [
        RuleResult(rule_id="cve_validity", passed=True, evidence="ok", confidence=0.7, signal=RuleSignal.CVE_VALIDITY),
        RuleResult(rule_id="severity_accuracy", passed=True, evidence="ok", confidence=0.7, signal=RuleSignal.SEVERITY_ACCURACY),
        RuleResult(rule_id="mitigation_relevance", passed=True, evidence="ok", confidence=0.7, signal=RuleSignal.MITIGATION_RELEVANCE),
        RuleResult(rule_id="urgency_consistency", passed=True, evidence="ok", confidence=0.7, signal=RuleSignal.URGENCY_CONSISTENCY),
    ]
    result = await engine.decide(rule_results)
    assert result.outcome == "FLAG"

@pytest.mark.asyncio
async def test_block_outcome():
    engine = DecisionEngine()
    rule_results = [
        RuleResult(rule_id="cve_validity", passed=False, evidence="fail", confidence=0.0),
        RuleResult(rule_id="severity_accuracy", passed=True, evidence="ok", confidence=1.0),
        RuleResult(rule_id="mitigation_relevance", passed=True, evidence="ok", confidence=1.0),
        RuleResult(rule_id="urgency_consistency", passed=True, evidence="ok", confidence=1.0),
    ]
    result = await engine.decide(rule_results)
    assert result.outcome == "BLOCK"

@pytest.mark.asyncio
async def test_correct_outcome():
    engine = DecisionEngine()
    rule_results = [
        RuleResult(rule_id="cve_exists_in_nvd", passed=False, evidence="fail", confidence=0.8, correction_candidates=["CVE-2023-12345"], signal=RuleSignal.CVE_VALIDITY, hard_fail=True),
        RuleResult(rule_id="severity_accuracy", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.SEVERITY_ACCURACY),
        RuleResult(rule_id="mitigation_relevance", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.MITIGATION_RELEVANCE),
        RuleResult(rule_id="urgency_consistency", passed=True, evidence="ok", confidence=1.0, signal=RuleSignal.URGENCY_CONSISTENCY),
    ]
    result = await engine.decide(rule_results)
    assert result.outcome == "CORRECT"
    assert result.correction is not None and result.correction.value == "CVE-2023-12345"
