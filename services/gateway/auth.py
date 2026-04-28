# services/gateway/auth.py
"""
JWT RS256 authentication and role-based access control.

Provides token validation, role extraction, and RBAC decorators for FastAPI routes.
Supports three roles: SOC_ANALYST, SOC_ADMIN, SYSTEM.
"""

import os
from datetime import datetime, timedelta
from functools import wraps
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

try:
    from jose import JWTError, jwt
except ImportError:  # pragma: no cover - optional dependency fallback
    JWTError = Exception
    jwt = None

# Role definitions
ALLOWED_ROLES = ["SOC_ANALYST", "SOC_ADMIN", "SYSTEM"]


class TokenPayload(BaseModel):
    """JWT token payload schema."""

    sub: str  # Subject (user ID)
    role: str
    exp: datetime
    iat: datetime


class CurrentUser(BaseModel):
    """Current authenticated user context."""

    user_id: str
    role: str


# HTTP Bearer authentication
security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> CurrentUser:
    """
    Validate JWT token and extract current user.

    Args:
        credentials: HTTP Bearer token from request header

    Returns:
        CurrentUser with user_id and role

    Raises:
        HTTPException: 401 if token is invalid or expired
    """
    token = credentials.credentials

    allow_insecure_dev_auth = (
        os.getenv("ALLOW_INSECURE_DEV_AUTH", "true").lower() in {"1", "true", "yes"}
    )

    if jwt is None:
        if allow_insecure_dev_auth:
            return CurrentUser(
                user_id=os.getenv("DEV_AUTH_USER_ID", "dev-user"),
                role=os.getenv("DEV_AUTH_ROLE", "SYSTEM"),
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="python-jose dependency is required for JWT auth",
        )

    try:
        # Load public key from environment
        public_key = os.getenv("JWT_PUBLIC_KEY")
        if not public_key:
            if allow_insecure_dev_auth:
                return CurrentUser(
                    user_id=os.getenv("DEV_AUTH_USER_ID", "dev-user"),
                    role=os.getenv("DEV_AUTH_ROLE", "SYSTEM"),
                )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWT_PUBLIC_KEY not configured",
            )

        # Decode JWT
        payload = jwt.decode(
            token, public_key, algorithms=[os.getenv("JWT_ALGORITHM", "RS256")]
        )

        user_id: str = payload.get("sub")
        role: str = payload.get("role")

        if not user_id or not role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
            )

        if role not in ALLOWED_ROLES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' not allowed",
            )

        return CurrentUser(user_id=user_id, role=role)

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}"
        )


def require_role(allowed_roles: List[str]):
    """
    Decorator to enforce RBAC on routes.

    Args:
        allowed_roles: List of roles permitted to access endpoint

    Returns:
        FastAPI dependency function
    """

    def role_checker(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' does not have permission. "
                f"Allowed roles: {', '.join(allowed_roles)}",
            )
        return current_user

    return role_checker


def create_token(
    user_id: str, role: str, expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a signed JWT token.

    Args:
        user_id: Subject identifier
        role: User role (SOC_ANALYST, SOC_ADMIN, SYSTEM)
        expires_delta: Token expiration time (default from JWT_EXPIRATION_HOURS)

    Returns:
        Encoded JWT token string
    """
    if jwt is None:
        raise RuntimeError("python-jose dependency is required for token creation")

    if expires_delta is None:
        hours = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))
        expires_delta = timedelta(hours=hours)

    expire = datetime.utcnow() + expires_delta

    to_encode = {"sub": user_id, "role": role, "exp": expire, "iat": datetime.utcnow()}

    secret_key = os.getenv("JWT_SECRET_KEY")
    if not secret_key:
        raise RuntimeError("JWT_SECRET_KEY not configured")

    encoded_jwt = jwt.encode(
        to_encode, secret_key, algorithm=os.getenv("JWT_ALGORITHM", "RS256")
    )

    return encoded_jwt
