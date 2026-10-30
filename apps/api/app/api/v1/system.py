"""System status and capability inspection endpoints."""

from datetime import UTC, datetime

from cyberduel_contracts.system import SystemStatusResponse
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.db.session import get_db_session

router = APIRouter(prefix="/system", tags=["System"])


@router.get(
    "/status",
    response_model=SystemStatusResponse,
    summary="Get Operational System Status",
    description="Reports system operational status, active AI runtime provider mode, and enabled capabilities.",
)
async def get_system_status(
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_db_session),
) -> SystemStatusResponse:
    capabilities = [
        "threat_classification",
        "privacy_preserving_telemetry",
        "declarative_policy_distribution",
        "sandboxed_laboratory_scenarios",
    ]
    if settings.LAB_WORKER_ENABLED:
        capabilities.append("adversarial_lab_worker")

    db_ok = True
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    return SystemStatusResponse(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        status="operational" if db_ok else "degraded",
        ai_provider_mode=settings.AI_PROVIDER_TYPE,
        active_capabilities=capabilities,
        database_connected=db_ok,
        active_workers=2,
        timestamp=datetime.now(UTC),
    )
