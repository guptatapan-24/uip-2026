"""
Unit tests for DecisionEngine.
"""
import pytest
from decision_engine.engine import DecisionEngine, DecisionInput

@pytest.mark.asyncio
def test_allow_outcome():
    engine = DecisionEngine()
    input = DecisionInput(validation_results=[
        {"rule_id": "cve_validity", "passed": True, "score": 1.0},
        {"rule_id": "severity_accuracy", "passed": True, "score": 1.0},
        {"rule_id": "mitigation_relevance", "passed": True, "score": 1.0},
        {"rule_id": "urgency_consistency", "passed": True, "score": 1.0},
    ])
    result = await engine.decide(input)
    assert result.outcome == "ALLOW"

@pytest.mark.asyncio
def test_flag_outcome():
    engine = DecisionEngine()
    input = DecisionInput(validation_results=[
        {"rule_id": "cve_validity", "passed": True, "score": 0.7},
        {"rule_id": "severity_accuracy", "passed": True, "score": 0.7},
        {"rule_id": "mitigation_relevance", "passed": True, "score": 0.7},
        {"rule_id": "urgency_consistency", "passed": True, "score": 0.7},
    ])
    result = await engine.decide(input)
    assert result.outcome == "FLAG"

@pytest.mark.asyncio
def test_block_outcome():
    engine = DecisionEngine()
    input = DecisionInput(validation_results=[
        {"rule_id": "cve_validity", "passed": False, "score": 0.0},
        {"rule_id": "severity_accuracy", "passed": True, "score": 1.0},
        {"rule_id": "mitigation_relevance", "passed": True, "score": 1.0},
        {"rule_id": "urgency_consistency", "passed": True, "score": 1.0},
    ])
    result = await engine.decide(input)
    assert result.outcome == "BLOCK"

@pytest.mark.asyncio
def test_correct_outcome():
    engine = DecisionEngine()
    input = DecisionInput(validation_results=[
        {"rule_id": "cve_validity", "passed": False, "score": 0.0, "correction_candidate": "CVE-2023-12345"},
        {"rule_id": "severity_accuracy", "passed": True, "score": 1.0},
        {"rule_id": "mitigation_relevance", "passed": True, "score": 1.0},
        {"rule_id": "urgency_consistency", "passed": True, "score": 1.0},
    ])
    result = await engine.decide(input)
    assert result.outcome == "CORRECT"
    assert result.correction_candidate == "CVE-2023-12345"
