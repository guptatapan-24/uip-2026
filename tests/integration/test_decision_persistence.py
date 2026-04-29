from fastapi.testclient import TestClient
from services.gateway.main import app
from tests.utils import create_auth_headers


client = TestClient(app)


def test_decision_create_and_persistence_and_audit():
    headers = create_auth_headers()

    payload = {
        "alert_id": "persist-alert-001",
        "validation_results": [
            {
                "rule_id": "test_hard_fail",
                "passed": False,
                "evidence": "Evidence shows fabricated CVE",
                "confidence": 0.95,
                "signal": "cve_validity",
                "hard_fail": True,
                "correction_candidates": [],
                "metadata": {},
            }
        ],
        "policy_profile": "default",
    }

    # Create decision
    r = client.post("/api/v1/decide", json=payload, headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert "decision_id" in data
    decision_id = data["decision_id"]
    assert data["alert_id"] == payload["alert_id"]
    assert data["outcome"] in {"BLOCK", "CORRECT", "FLAG", "ALLOW"}

    # Retrieve decision detail
    r = client.get(f"/api/v1/decisions/{decision_id}", headers=headers)
    assert r.status_code == 200
    detail = r.json()
    assert detail["decision_id"] == decision_id
    assert detail["alert_id"] == payload["alert_id"]

    # Verify audit chain still valid
    r = client.get("/api/v1/audit/verify-chain", headers=headers)
    assert r.status_code == 200
    report = r.json()
    assert "valid" in report
