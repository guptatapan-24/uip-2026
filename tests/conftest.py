import os
from datetime import timedelta

import pytest

from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



@pytest.fixture(scope="session")
def jwt_keys(tmp_path_factory):
    # Generate an ephemeral RSA keypair for tests and store PEMs in tmpdir
    base = tmp_path_factory.mktemp("jwt_keys")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = os.path.join(str(base), "private.pem")
    pub_path = os.path.join(str(base), "public.pem")
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    return {"private": priv_path, "public": pub_path}


# auth_headers fixture removed; use tests.utils.create_auth_headers() where needed


@pytest.fixture(autouse=True, scope="session")
def set_jwt_pub_env(jwt_keys):
    # Load public key into env so the app can verify RS256 tokens
    with open(jwt_keys["public"], "r") as f:
        public = f.read()
    os.environ["JWT_PUBLIC_KEY"] = public
    # Also expose private key for the create_auth_headers helper to use if desired
    os.environ["JWT_PRIVATE_KEY"] = open(jwt_keys["private"]).read()
    os.environ["ALLOW_INSECURE_DEV_AUTH"] = "false"
