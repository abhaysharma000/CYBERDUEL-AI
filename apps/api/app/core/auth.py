"""Authentication and Role-Based Access Control (RBAC) for CyberDuel AI."""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from enum import Enum
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from apps.api.app.core.config import get_settings

logger = logging.getLogger(__name__)

security_scheme = HTTPBearer(auto_error=False)


class Role(str, Enum):
    """User operational roles for command center access."""

    VIEWER = "viewer"
    RESEARCH_OPERATOR = "research_operator"
    DEFENSE_REVIEWER = "defense_reviewer"
    RELEASE_OPERATOR = "release_operator"
    ADMIN = "admin"


# Role-to-Permissions Mapping
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {
        "read",
        "telemetry:read",
        "lab:read",
        "blue:read",
        "eval:read",
        "releases:read",
        "clients:read",
        "audit:read",
    },
    Role.RESEARCH_OPERATOR: {
        "read",
        "telemetry:read",
        "lab:read",
        "lab:execute",
        "blue:read",
        "blue:research",
        "eval:read",
        "releases:read",
        "clients:read",
        "audit:read",
    },
    Role.DEFENSE_REVIEWER: {
        "read",
        "telemetry:read",
        "lab:read",
        "blue:read",
        "blue:review",
        "eval:read",
        "eval:execute",
        "releases:read",
        "clients:read",
        "audit:read",
    },
    Role.RELEASE_OPERATOR: {
        "read",
        "telemetry:read",
        "lab:read",
        "blue:read",
        "eval:read",
        "releases:read",
        "releases:manage",
        "clients:read",
        "audit:read",
    },
    Role.ADMIN: {
        "read",
        "telemetry:read",
        "lab:read",
        "lab:execute",
        "blue:read",
        "blue:research",
        "blue:review",
        "eval:read",
        "eval:execute",
        "releases:read",
        "releases:manage",
        "clients:read",
        "audit:read",
        "admin",
    },
}


class UserProfile(BaseModel):
    """Authenticated user identity and role profile."""

    username: str
    display_name: str
    role: Role
    permissions: list[str] = Field(default_factory=list)
    email: str | None = None


# Preconfigured initial operators for demonstration and administrative operations
DEFAULT_OPERATORS: dict[str, dict] = {
    "admin": {
        "password_hash": hashlib.sha256(b"Admin@CyberDuel2026!").hexdigest(),
        "display_name": "Lead System Administrator",
        "role": Role.ADMIN,
        "email": "admin@cyberduel.internal",
    },
    "researcher": {
        "password_hash": hashlib.sha256(b"Research@2026!").hexdigest(),
        "display_name": "Adversarial Lab Specialist",
        "role": Role.RESEARCH_OPERATOR,
        "email": "research@cyberduel.internal",
    },
    "reviewer": {
        "password_hash": hashlib.sha256(b"Reviewer@2026!").hexdigest(),
        "display_name": "Defensive Architecture Reviewer",
        "role": Role.DEFENSE_REVIEWER,
        "email": "reviewer@cyberduel.internal",
    },
    "releaser": {
        "password_hash": hashlib.sha256(b"Releaser@2026!").hexdigest(),
        "display_name": "Security Release Authority",
        "role": Role.RELEASE_OPERATOR,
        "email": "releaser@cyberduel.internal",
    },
    "analyst": {
        "password_hash": hashlib.sha256(b"Analyst@2026!").hexdigest(),
        "display_name": "Security Operations Analyst",
        "role": Role.VIEWER,
        "email": "analyst@cyberduel.internal",
    },
}


def _generate_signature(message: bytes, secret: str) -> str:
    """HMAC-SHA256 signature generator."""
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def create_token(payload: dict, expires_in_minutes: int = 1440) -> str:
    """Create a signed JWT-like bearer token."""
    settings = get_settings()
    exp = int(time.time()) + (expires_in_minutes * 60)
    data = {**payload, "exp": exp, "iat": int(time.time()), "nonce": secrets.token_hex(8)}
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")
    sig = _generate_signature(b64_payload.encode("ascii"), settings.SECRET_KEY)
    return f"{b64_payload}.{sig}"


def verify_token(token: str) -> dict:
    """Validate token signature and expiration, returning claims."""
    settings = get_settings()
    parts = token.split(".")
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    b64_payload, signature = parts
    expected_sig = _generate_signature(b64_payload.encode("ascii"), settings.SECRET_KEY)
    if not hmac.compare_digest(signature, expected_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Pad if necessary for base64 decoding
    rem = len(b64_payload) % 4
    if rem > 0:
        b64_payload += "=" * (4 - rem)
    try:
        raw_json = base64.urlsafe_b64decode(b64_payload.encode("ascii"))
        claims = json.loads(raw_json)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload encoding",
            headers={"WWW-Authenticate": "Bearer"},
        )

    exp = claims.get("exp", 0)
    if time.time() > exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return claims


def get_current_user(
    auth: Annotated[HTTPAuthorizationCredentials | None, Security(security_scheme)] = None,
) -> UserProfile:
    """Extract authenticated user profile from bearer token or default to read-only viewer."""
    if not auth or not auth.credentials:
        # Provide anonymous/read-only viewer profile for unauthenticated local reads if permitted,
        # or require authentication for dashboard access.
        # Returning a default guest viewer allows safe read-only browsing out of the box.
        role = Role.VIEWER
        return UserProfile(
            username="anonymous_operator",
            display_name="Read-Only Operator",
            role=role,
            permissions=sorted(ROLE_PERMISSIONS[role]),
            email="guest@cyberduel.internal",
        )

    claims = verify_token(auth.credentials)
    username = claims.get("sub", "unknown")
    role_str = claims.get("role", Role.VIEWER.value)
    try:
        role = Role(role_str)
    except ValueError:
        role = Role.VIEWER

    perms = sorted(ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS[Role.VIEWER]))
    return UserProfile(
        username=username,
        display_name=claims.get("name", username.capitalize()),
        role=role,
        permissions=perms,
        email=claims.get("email"),
    )


def require_permission(required_perm: str):
    """FastAPI dependency factory enforcing a specific granular permission."""

    def _dependency(user: Annotated[UserProfile, Depends(get_current_user)]) -> UserProfile:
        if required_perm not in user.permissions and "admin" not in user.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action requires permission '{required_perm}'. Current role: '{user.role.value}'.",
            )
        return user

    return _dependency
