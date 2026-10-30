"""Defensive policy export endpoint for edge clients."""

from cyberduel_policy_engine.exporter import LocalProtectionPolicyBundle
from fastapi import APIRouter, Depends

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.services.policy_service import PolicyService

router = APIRouter(prefix="/policy", tags=["Policy Engine"])


@router.get(
    "/export",
    response_model=LocalProtectionPolicyBundle,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Export Local Protection Policy Bundle",
    description=(
        "Retrieves a versioned, machine-readable defensive policy package containing domain hashes, "
        "declarative regex rules, and an integrity digest for local edge protection."
    ),
)
async def export_local_policy() -> LocalProtectionPolicyBundle:
    return PolicyService.export_active_policy()
