"""Authentication endpoints for CyberDuel AI Command Center."""

import hashlib
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.auth import (
    DEFAULT_OPERATORS,
    ROLE_PERMISSIONS,
    Role,
    UserProfile,
    create_token,
    get_current_user,
)
from apps.api.app.core.config import Settings, get_settings
from apps.api.app.db.session import get_db_session
from apps.api.app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


class LoginRequest(BaseModel):
    """Credentials or quick demo login request."""

    username: str = Field(..., description="Operator username")
    password: str = Field(default="", description="Operator password")


class LoginResponse(BaseModel):
    """Successful login session response."""

    token: str
    token_type: str = "Bearer"
    expires_in_seconds: int = 86400
    user: UserProfile


class OperatorOption(BaseModel):
    """Preconfigured operator account for quick demo login."""

    username: str
    display_name: str
    role: Role
    description: str


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    """Authenticate an operator and issue an authorized session token."""
    client_ip = request.client.host if request.client else "unknown"
    username = payload.username.strip().lower()

    if username not in DEFAULT_OPERATORS:
        try:
            await AuditService.record_event(
                session=session,
                actor=username,
                action="auth.login",
                target_type="auth",
                outcome="denied",
                reason="Invalid username",
                client_ip=client_ip,
            )
        except Exception as e:
            logger.warning("Audit record failed during failed login: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid operator credentials",
        )

    op_info = DEFAULT_OPERATORS[username]

    provided_hash = hashlib.sha256(payload.password.encode()).hexdigest()

    if settings.is_production:
        # In production: strictly require non-empty password and exact hash match
        if not payload.password or provided_hash != op_info["password_hash"]:
            try:
                await AuditService.record_event(
                    session=session,
                    actor=username,
                    action="auth.login",
                    target_type="auth",
                    outcome="denied",
                    reason="Invalid credentials in production mode",
                    client_ip=client_ip,
                )
            except Exception as e:
                logger.warning("Audit record failed during failed login: %s", e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid operator credentials",
            )
    else:
        # In dev/demo mode, if password is empty or matches known demo credentials, allow login
        if payload.password and provided_hash != op_info["password_hash"]:
            if payload.password != "demo" and payload.password != username:
                try:
                    await AuditService.record_event(
                        session=session,
                        actor=username,
                        action="auth.login",
                        target_type="auth",
                        outcome="denied",
                        reason="Invalid password",
                        client_ip=client_ip,
                    )
                except Exception as e:
                    logger.warning("Audit record failed during failed login: %s", e)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid operator credentials",
                )

    role = op_info["role"]
    claims = {
        "sub": username,
        "name": op_info["display_name"],
        "role": role.value,
        "email": op_info["email"],
    }
    token = create_token(claims)

    user = UserProfile(
        username=username,
        display_name=op_info["display_name"],
        role=role,
        permissions=sorted(ROLE_PERMISSIONS[role]),
        email=op_info["email"],
    )

    try:
        await AuditService.record_event(
            session=session,
            actor=username,
            action="auth.login",
            target_type="auth",
            outcome="success",
            metadata={"role": role.value},
            client_ip=client_ip,
        )
    except Exception as e:
        logger.warning("Audit record failed during successful login: %s", e)

    return LoginResponse(
        token=token,
        user=user,
    )


@router.get("/me", response_model=UserProfile)
async def get_current_profile(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Retrieve identity and active RBAC permissions for the calling operator."""
    return user


@router.post("/logout")
async def logout(
    request: Request,
    user: UserProfile = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Acknowledge session termination and record audit log."""
    client_ip = request.client.host if request.client else "unknown"
    try:
        await AuditService.record_event(
            session=session,
            actor=user.username,
            action="auth.logout",
            target_type="auth",
            outcome="success",
            client_ip=client_ip,
        )
    except Exception as e:
        logger.warning("Audit record failed during logout: %s", e)
    return {"status": "logged_out", "username": user.username}


@router.get("/operators", response_model=list[OperatorOption])
async def list_demo_operators() -> list[OperatorOption]:
    """List preconfigured operator accounts for quick switching in dashboard."""
    descriptions = {
        "admin": "Full system, research, defense review, and cryptographic release authority.",
        "researcher": "Can execute Red AI scenario suites and research tasks.",
        "reviewer": "Can review failure groups and approve/reject Blue AI defense proposals.",
        "releaser": "Can verify release eligibility, stage rollouts, and trigger rollbacks.",
        "analyst": "Read-only access across telemetry, intelligence, and system status.",
    }
    return [
        OperatorOption(
            username=uname,
            display_name=info["display_name"],
            role=info["role"],
            description=descriptions.get(uname, "Standard operator"),
        )
        for uname, info in DEFAULT_OPERATORS.items()
    ]
