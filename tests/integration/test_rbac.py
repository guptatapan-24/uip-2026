from fastapi.testclient import TestClient
from services.gateway.main import app
from tests.utils import create_auth_headers


client = TestClient(app)


def test_policy_profiles_rbac():
    # SYSTEM role should be allowed
    headers = create_auth_headers(role="SYSTEM")
    r = client.get("/api/v1/policy/profiles", headers=headers)
    assert r.status_code == 200

    # SOC_ANALYST should be forbidden
    headers = create_auth_headers(role="SOC_ANALYST")
    r = client.get("/api/v1/policy/profiles", headers=headers)
    assert r.status_code == 403
