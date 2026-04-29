import os
import time
from jose import jwt


def create_auth_headers(role: str = "SYSTEM") -> dict:
    # Prefer ephemeral keypair exposed via env by conftest; fall back to on-disk tests/keys
    private = os.getenv("JWT_PRIVATE_KEY")
    if not private:
        base = os.path.join(os.path.dirname(__file__), "keys")
        priv_path = os.path.join(base, "private.pem")
        with open(priv_path, "r") as f:
            private = f.read()

    payload = {
        "sub": "test-user",
        "role": role,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }

    token = jwt.encode(payload, private, algorithm="RS256")
    return {"Authorization": f"Bearer {token}"}
