"""Integration tests for gateway decision/audit/policy/metrics routes."""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest
from fastapi.testclient import TestClient

# Add project and gateway paths for dynamic main.py import.
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, project_root)
gateway_path = os.path.join(project_root, "services/gateway")
sys.path.insert(0, gateway_path)

spec = importlib.util.spec_from_file_location("main", os.path.join(gateway_path, "main.py"))
main_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main_module)
app = main_module.app

import auth


@pytest.fixture
def client_admin():
    """Test client with SOC_ADMIN role override."""
    app.dependency_overrides[auth.get_current_user] = lambda: auth.CurrentUser(
        user_id="test-admin", role="SOC_ADMIN"
    )
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_system():
    """Test client with SYSTEM role override."""
    app.dependency_overrides[auth.get_current_user] = lambda: auth.CurrentUser(
        user_id="test-system", role="SYSTEM"
    )
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _decide_payload(alert_id: str) -> dict:
    return {
        "alert_id": alert_id,
        "validation_results": [
            {
                "rule_id": "cve_exists_in_nvd",
                "passed": True,
                "evidence": "Found",
                "confidence": 0.95,
                "signal": "cve_validity",
                "hard_fail": False,
                "correction_candidates": [],
                "metadata": {},
            }
        ],
        "policy_profile": "default",
    }


def test_decision_history_metrics_and_audit(client_admin: TestClient) -> None:
    decide_resp = client_admin.post("/api/v1/decide", json=_decide_payload("admin-001"))
    assert decide_resp.status_code == 200
    decision_id = decide_resp.json().get("decision_id")
    assert decision_id

    list_resp = client_admin.get("/api/v1/decisions")
    assert list_resp.status_code == 200
    listed = list_resp.json()
    assert any(item["decision_id"] == decision_id for item in listed)

    detail_resp = client_admin.get(f"/api/v1/decisions/{decision_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["decision_id"] == decision_id
    assert detail["alert_id"] == "admin-001"

    outcomes_resp = client_admin.get("/api/v1/metrics/outcomes")
    assert outcomes_resp.status_code == 200
    assert outcomes_resp.json()["ALLOW"] >= 0

    perf_resp = client_admin.get("/api/v1/metrics/performance")
    assert perf_resp.status_code == 200
    assert "total_validations" in perf_resp.json()

    audit_resp = client_admin.get("/api/v1/audit/log")
    assert audit_resp.status_code == 200
    audit_entries = audit_resp.json()
    assert any(entry["decision_id"] == decision_id for entry in audit_entries)

    verify_resp = client_admin.get("/api/v1/audit/verify-chain")
    assert verify_resp.status_code == 200
    assert "valid" in verify_resp.json()


def test_policy_override_flow(client_admin: TestClient) -> None:
    decide_resp = client_admin.post("/api/v1/decide", json=_decide_payload("admin-002"))
    decision_id = decide_resp.json()["decision_id"]

    override_resp = client_admin.post(
        "/api/v1/policy/override",
        json={
            "decision_id": decision_id,
            "new_outcome": "BLOCK",
            "rationale": "Manual override for incident containment.",
            "correction_suggestion": "Block and isolate host",
        },
    )
    assert override_resp.status_code == 201
    override_data = override_resp.json()
    assert override_data["decision_id"] == decision_id
    assert override_data["new_outcome"] == "BLOCK"

    detail_resp = client_admin.get(f"/api/v1/decisions/{decision_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["outcome"] == "BLOCK"


def test_policy_profiles_list_system(client_system: TestClient) -> None:
    response = client_system.get("/api/v1/policy/profiles")
    assert response.status_code == 200
    data = response.json()
    assert "profiles" in data
    assert any(profile["name"] == "default" for profile in data["profiles"])
