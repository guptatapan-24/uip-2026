from fastapi.testclient import TestClient
from services.gateway.main import app
from tests.utils import create_auth_headers


client = TestClient(app)


def test_validation_health_and_audit_flow():
    # Health
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json().get("status") == "healthy"

    # Validate endpoint (core pipeline returns a mock FLAG in current implementation)
    payload = {
        "llm_output": "Patch CVE-2024-1234 immediately. CVSS 9.8. Affects Apache 2.4.x.",
        "context": {
            "alert_id": "test-alert-001",
            "severity_hint": "CRITICAL",
            "policy_profile": "default"
        }
    }

    # use RS256 test helper for realistic auth
    headers = create_auth_headers()
    r = client.post("/api/v1/validate", json=payload, headers=headers)
    assert r.status_code == 200
    data = r.json()
    # Current validate response returns validation details (not a decision record)
    assert data.get("alert_id") == payload["context"]["alert_id"]
    assert "deterministic_rules" in data
    assert "total_latency_ms" in data

    # Audit verify-chain endpoint (returns mock verification)
    r = client.get("/api/v1/audit/verify-chain", headers=headers)
    assert r.status_code == 200
    report = r.json()
    assert "valid" in report
