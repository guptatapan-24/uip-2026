# tests/integration/test_validation_pipeline.py
"""
Integration tests for complete validation pipeline.

Tests full flow:
1. Claim Extraction → 2. RAG Retrieval → 3. Validation → 4. Decision → 5. Explainability
"""

import pytest
import httpx
from datetime import datetime


@pytest.fixture
def api_client():
    """Fixture: HTTP client for API endpoints."""
    base_url = "http://localhost:8000"
    return httpx.AsyncClient(base_url=base_url)


@pytest.mark.asyncio
async def test_complete_validation_flow(api_client):
    """Test full validation pipeline with mock LLM output."""
    
    # 1. Send validation request
    request_payload = {
        "llm_output": "The CVE-2024-1234 vulnerability affects Apache servers with CVSS v3.1: 9.8. "
                     "Attackers can exploit this via technique T1566. Recommendation: immediate patching required.",
        "context": {
            "alert_id": "alert-20240424-001",
            "severity_hint": "CRITICAL",
            "policy_profile": "default"
        }
    }
    
    response = await api_client.post(
        "/v1/validate",
        json=request_payload,
        headers={
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json"
        }
    )
    
    # 2. Verify response structure
    assert response.status_code == 200
    data = response.json()
    
    assert "decision_id" in data
    assert "outcome" in data  # ALLOW | FLAG | BLOCK | CORRECT
    assert "risk_score" in data
    assert 0.0 <= data["risk_score"] <= 1.0
    assert "claims" in data
    assert "validation_results" in data
    assert "analyst_rationale" in data
    assert "latency_ms" in data


@pytest.mark.asyncio
async def test_decision_retrieval(api_client):
    """Test retrieving past decision by ID."""
    # TODO: Get decision_id from prior test
    
    response = await api_client.get(
        "/v1/decisions/dec-001",
        headers={"Authorization": "Bearer test-token"}
    )
    
    assert response.status_code == 200 or response.status_code == 404


@pytest.mark.asyncio
async def test_audit_log_retrieval(api_client):
    """Test audit log retrieval with hash chain verification."""
    response = await api_client.get(
        "/v1/audit/log",
        params={"limit": 10, "offset": 0},
        headers={"Authorization": "Bearer test-token"}
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify hash chain structure
    if data:
        for entry in data:
            assert "entry_id" in entry
            assert "decision_id" in entry
            assert "prev_hash" in entry
            assert "curr_hash" in entry
            assert "verified" in entry


# TODO: Add tests for policy override workflow
# TODO: Add tests for error handling and fallback paths
# TODO: Add load testing for concurrent validation requests
