"""Integration tests for the LLM Hallucination Firewall API gateway."""

from __future__ import annotations

import asyncio
import json
import sys
import os
import pytest
from datetime import datetime, timezone

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

# Add gateway to path
gateway_path = os.path.join(project_root, "services/gateway")
sys.path.insert(0, gateway_path)

from fastapi.testclient import TestClient

# Now import app - will work with path adjustments above
import importlib.util
spec = importlib.util.spec_from_file_location("main", os.path.join(gateway_path, "main.py"))
main_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main_module)
app = main_module.app


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for GET /health endpoint."""

    def test_health_check_returns_200(self, client):
        """Health check should return 200 with healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert data["version"] == "1.0.0"
        assert "dependencies" in data
        assert "uptime_seconds" in data

    def test_health_includes_core_dependencies(self, client):
        """Health check should include core service dependencies."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        dep_names = {d["name"] for d in data["dependencies"]}
        # Should check for core services
        assert any(name in dep_names for name in ["config", "extraction", "validation", "decision_engine"])


class TestExtractEndpoint:
    """Tests for POST /api/v1/extract endpoint."""

    def test_extract_cve(self, client):
        """Extract endpoint should find CVE identifiers."""
        response = client.post(
            "/api/v1/extract",
            json={
                "text": "Investigate CVE-2023-23397 on Outlook for security patches.",
                "enable_ner": True,
                "enable_span_extraction": True,
                "model_version": "v1",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["input_text"] is not None
        assert isinstance(data["claims"], list)
        assert data["extraction_timestamp"] is not None
        assert data["latency_ms"] > 0
        assert data["model_version"] == "v1"
        # Should have extracted CVE
        assert any(c["claim_type"] == "cve" for c in data["claims"])

    def test_extract_attack_technique(self, client):
        """Extract endpoint should find ATT&CK technique identifiers."""
        response = client.post(
            "/api/v1/extract",
            json={
                "text": "Observed ATT&CK technique T1190 during incident response.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["claims"], list)
        # Should have extracted ATT&CK technique
        assert any(c["claim_type"] == "attack_id" for c in data["claims"])

    def test_extract_cvss_score(self, client):
        """Extract endpoint should find CVSS scores."""
        response = client.post(
            "/api/v1/extract",
            json={
                "text": "The vendor reports CVSS 9.8 for this critical vulnerability.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["claims"], list)
        # Should have extracted CVSS score
        assert any(c["claim_type"] == "cvss_score" for c in data["claims"])

    def test_extract_empty_text_fails(self, client):
        """Extract endpoint should reject empty text."""
        response = client.post(
            "/api/v1/extract",
            json={"text": "   "},
        )
        assert response.status_code == 400

    def test_extract_response_structure(self, client):
        """Extract response should have correct structure."""
        response = client.post(
            "/api/v1/extract",
            json={"text": "Sample text with CVE-2024-1234."},
        )
        assert response.status_code == 200
        data = response.json()
        # Verify response structure
        assert "input_text" in data
        assert "claims" in data
        assert "extraction_timestamp" in data
        assert "latency_ms" in data
        assert "model_version" in data
        # Verify claim structure
        if data["claims"]:
            claim = data["claims"][0]
            assert "claim_type" in claim
            assert "raw_text" in claim
            assert "extracted_value" in claim
            assert "position" in claim
            assert "confidence" in claim


class TestValidateEndpoint:
    """Tests for POST /api/v1/validate endpoint."""

    def test_validate_with_extracted_claims(self, client):
        """Validate endpoint should accept pre-extracted claims."""
        # First extract
        extract_response = client.post(
            "/api/v1/extract",
            json={"text": "CVE-2023-23397 has CVSS 9.8"},
        )
        extracted_claims = extract_response.json()["claims"]

        # Then validate
        response = client.post(
            "/api/v1/validate",
            json={
                "llm_output": "CVE-2023-23397 has CVSS 9.8",
                "extracted_claims": extracted_claims,
                "context": {
                    "alert_id": "alert-001",
                    "severity_hint": "HIGH",
                    "policy_profile": "default",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id"] == "alert-001"
        assert isinstance(data["deterministic_rules"], list)
        assert data["total_latency_ms"] > 0

    def test_validate_without_claims_extracts(self, client):
        """Validate endpoint should extract claims if not provided."""
        response = client.post(
            "/api/v1/validate",
            json={
                "llm_output": "CVE-2024-1234 is a critical vulnerability",
                "context": {
                    "alert_id": "alert-002",
                    "severity_hint": "CRITICAL",
                    "policy_profile": "default",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id"] == "alert-002"

    def test_validate_with_nvd_data(self, client):
        """Validate endpoint should accept NVD data payload."""
        response = client.post(
            "/api/v1/validate",
            json={
                "llm_output": "CVE-2024-0001 is valid",
                "context": {
                    "alert_id": "alert-003",
                    "policy_profile": "default",
                },
                "nvd_data": {
                    "CVE-2024-0001": {
                        "cvss_score": 8.5,
                    }
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "deterministic_rules" in data

    def test_validate_response_structure(self, client):
        """Validate response should have correct structure."""
        response = client.post(
            "/api/v1/validate",
            json={
                "llm_output": "Test validation",
                "context": {
                    "alert_id": "alert-004",
                    "policy_profile": "default",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "alert_id" in data
        assert "deterministic_rules" in data
        assert "total_latency_ms" in data
        # Verify rule result structure
        if data["deterministic_rules"]:
            rule = data["deterministic_rules"][0]
            assert "rule_id" in rule
            assert "passed" in rule
            assert "evidence" in rule
            assert "confidence" in rule


class TestDecideEndpoint:
    """Tests for POST /api/v1/decide endpoint."""

    def test_decide_with_rules(self, client):
        """Decide endpoint should generate decision from validation rules."""
        response = client.post(
            "/api/v1/decide",
            json={
                "alert_id": "alert-005",
                "validation_results": [
                    {
                        "rule_id": "test_rule",
                        "passed": True,
                        "evidence": "Test passed",
                        "confidence": 0.95,
                        "signal": "cve_validity",
                        "hard_fail": False,
                        "correction_candidates": [],
                        "metadata": {},
                    }
                ],
                "policy_profile": "default",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id"] == "alert-005"
        assert data["outcome"] in ["ALLOW", "FLAG", "BLOCK", "CORRECT"]
        assert 0 <= data["risk_score"] <= 1
        assert data["applied_profile"] == "default"
        assert "rationale" in data
        assert data["decision_timestamp"] is not None
        assert data["latency_ms"] > 0

    def test_decide_invalid_profile_fails(self, client):
        """Decide endpoint should reject invalid policy profile."""
        response = client.post(
            "/api/v1/decide",
            json={
                "alert_id": "alert-006",
                "validation_results": [],
                "policy_profile": "nonexistent_profile",
            },
        )
        assert response.status_code == 400

    def test_decide_response_structure(self, client):
        """Decide response should have correct structure."""
        response = client.post(
            "/api/v1/decide",
            json={
                "alert_id": "alert-007",
                "validation_results": [
                    {
                        "rule_id": "test",
                        "passed": True,
                        "evidence": "test",
                        "confidence": 0.8,
                        "signal": "cve_validity",
                        "hard_fail": False,
                        "correction_candidates": [],
                        "metadata": {},
                    }
                ],
                "policy_profile": "default",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "alert_id" in data
        assert "outcome" in data
        assert "risk_score" in data
        assert "applied_profile" in data
        assert "signal_scores" in data
        assert "hard_fail_rule_ids" in data
        assert "rationale" in data
        assert "decision_timestamp" in data
        assert "latency_ms" in data


class TestEndToEndFlow:
    """End-to-end integration tests."""

    def test_full_validation_flow(self, client):
        """Test complete flow: extract -> validate -> decide."""
        llm_output = "CVE-2023-23397 has CVSS 9.8 and requires immediate patching."

        # Step 1: Extract
        extract_response = client.post(
            "/api/v1/extract",
            json={"text": llm_output},
        )
        assert extract_response.status_code == 200
        extracted = extract_response.json()
        extracted_claims = extracted["claims"]

        # Step 2: Validate
        validate_response = client.post(
            "/api/v1/validate",
            json={
                "llm_output": llm_output,
                "extracted_claims": extracted_claims,
                "context": {
                    "alert_id": "e2e-001",
                    "severity_hint": "CRITICAL",
                    "policy_profile": "default",
                },
            },
        )
        assert validate_response.status_code == 200
        validation_data = validate_response.json()
        validation_results = validation_data["deterministic_rules"]

        # Convert validation results to decision format
        decision_results = [
            {
                "rule_id": r["rule_id"],
                "passed": r["passed"],
                "evidence": r["evidence"],
                "confidence": r["confidence"],
                "signal": r["signal"],
                "hard_fail": r["hard_fail"],
                "correction_candidates": r["correction_candidates"],
                "metadata": r["metadata"],
            }
            for r in validation_results
        ]

        # Step 3: Decide
        decide_response = client.post(
            "/api/v1/decide",
            json={
                "alert_id": "e2e-001",
                "validation_results": decision_results,
                "policy_profile": "default",
            },
        )
        assert decide_response.status_code == 200
        decision_data = decide_response.json()
        assert decision_data["outcome"] in ["ALLOW", "FLAG", "BLOCK", "CORRECT"]
        assert 0 <= decision_data["risk_score"] <= 1

    def test_api_root(self, client):
        """Test API root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "llm-hallucination-firewall"
        assert data["version"] == "1.0.0"
        assert "endpoints" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
