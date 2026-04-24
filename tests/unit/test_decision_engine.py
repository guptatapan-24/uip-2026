# tests/unit/test_decision_engine.py
"""
Unit tests for decision engine.

Tests:
- Risk score calculation with weighted components
- Decision outcome determination (ALLOW | FLAG | BLOCK | CORRECT)
- Policy profile thresholds
"""

import pytest
from services.decision_engine.engine import DecisionEngine


@pytest.fixture
def engine():
    """Fixture: initialized DecisionEngine."""
    # Use in-memory or test policy profiles
    return DecisionEngine()


def test_risk_score_calculation(engine):
    """Test risk score weighted calculation."""
    # Component scores (each 0-1)
    component_scores = {
        "cve_validity": 0.9,           # 40% weight
        "severity_accuracy": 0.8,      # 30% weight
        "mitigation_relevance": 0.7,   # 20% weight
        "urgency_consistency": 0.6     # 10% weight
    }
    
    # Expected: 0.4*0.9 + 0.3*0.8 + 0.2*0.7 + 0.1*0.6 = 0.36 + 0.24 + 0.14 + 0.06 = 0.8
    expected_score = 0.8
    
    # TODO: Call engine.compute_risk_score(component_scores)
    # assert result == expected_score


def test_allow_outcome(engine):
    """Test ALLOW decision (0.85-1.0 score)."""
    # TODO: Test risk score >= 0.85 → ALLOW


def test_flag_outcome(engine):
    """Test FLAG decision (0.60-0.84 score)."""
    # TODO: Test 0.60 <= risk score < 0.85 → FLAG


def test_block_outcome(engine):
    """Test BLOCK decision (<0.60 or hard-fail)."""
    # TODO: Test risk score < 0.60 → BLOCK
    # TODO: Test hard-fail rule → BLOCK regardless of score


def test_policy_profile_override(engine):
    """Test policy profile threshold override."""
    # TODO: Test that different profiles (strict, permissive) change thresholds
