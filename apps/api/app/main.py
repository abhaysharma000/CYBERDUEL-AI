"""CyberDuel AI Backend Core Application Entrypoint."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.app.api.router import api_router
from apps.api.app.core.config import get_settings
from apps.api.app.core.logging import logger, setup_logging
from apps.api.app.core.middleware import (
    RequestBodySizeLimitMiddleware,
    RequestCorrelationIdMiddleware,
    register_exception_handlers,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager handling application startup and shutdown hooks."""
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL, json_format=settings.LOG_JSON)
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} "
        f"[env={settings.ENVIRONMENT}, ai_provider={settings.AI_PROVIDER_TYPE}]"
    )
    try:
        if settings.ENVIRONMENT != "test":
            from apps.api.app.db.init_db import ensure_schema_initialized

            await ensure_schema_initialized()
    except Exception as e:
        logger.warning(f"Database auto-init notice: {e}")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "CyberDuel AI: Continuously improving defensive cybersecurity platform "
            "with cloud research laboratory, browser extension, and mobile integration."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # 1. Request Body Size Limit Middleware
    app.add_middleware(
        RequestBodySizeLimitMiddleware,
        max_bytes=settings.MAX_REQUEST_BODY_BYTES,
    )

    # 2. Correlation ID Middleware
    app.add_middleware(RequestCorrelationIdMiddleware)

    # 3. Restrictive CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Process-Time-Ms"],
    )

    # 4. Centralized Exception Handlers
    register_exception_handlers(app, is_debug=settings.DEBUG)

    # 5. Mount Core Routers
    app.include_router(api_router)

    return app


app = create_app()
