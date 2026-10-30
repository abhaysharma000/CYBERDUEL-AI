"""Root router defining health endpoints and mounting versioned API routers."""

from datetime import UTC, datetime

from cyberduel_contracts.system import HealthResponse
from fastapi import APIRouter, Depends, Response, status

from apps.api.app.api.v1.router import v1_router
from apps.api.app.core.config import Settings, get_settings
from apps.api.app.db.session import check_database_health

api_router = APIRouter()


@api_router.get(
    "/health/live",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Liveness Probe",
    description="Indicates whether the application process is running and responsive.",
)
async def liveness_check(
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        checks={"process": "alive"},
        timestamp=datetime.now(UTC),
    )


@api_router.get(
    "/health/ready",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Readiness Probe",
    description="Reports the availability of required downstream dependencies (e.g., database) without exposing credentials.",
)
async def readiness_check(
    response: Response,
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    db_ok = await check_database_health()
    overall_status = "healthy" if db_ok else "degraded"

    # In production/staging, non-ready dependencies should return 503 so load balancers stop sending traffic
    if not db_ok and not settings.is_testing and not settings.DEBUG:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    ai_status = "unknown"
    if settings.AI_PROVIDER_TYPE == "qwen":
        if settings.is_testing:
            ai_status = f"configured: qwen ({settings.QWEN_MODEL_NAME}) [test-mode]"
        else:
            try:
                from apps.api.app.providers.qwen_provider import QwenProvider

                qwen = QwenProvider(
                    api_base=settings.QWEN_API_BASE,
                    api_key=settings.QWEN_API_KEY,
                    model_name=settings.QWEN_MODEL_NAME,
                    timeout_seconds=2.0,
                )
                is_conn, msg, _ = await qwen.check_endpoint_connectivity(timeout_seconds=2.0)
                if is_conn:
                    ai_status = f"connected: qwen ({settings.QWEN_MODEL_NAME})"
                else:
                    ai_status = f"configured: qwen ({settings.QWEN_MODEL_NAME}), endpoint {msg}"
            except Exception as e:
                ai_status = f"configured: qwen ({settings.QWEN_MODEL_NAME}), check failed: {e}"
    elif settings.AI_PROVIDER_TYPE == "mock":
        ai_status = f"mock ({settings.AI_MODEL_NAME}) - offline non-llm"
    else:
        ai_status = f"{settings.AI_PROVIDER_TYPE}"

    return HealthResponse(
        status=overall_status,  # type: ignore[arg-type]
        version=settings.APP_VERSION,
        checks={
            "database": "reachable" if db_ok else "unreachable",
            "ai_provider": ai_status,
        },
        timestamp=datetime.now(UTC),
    )


# Mount versioned API routes
api_router.include_router(v1_router)
