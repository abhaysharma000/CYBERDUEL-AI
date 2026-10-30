"""Schemas for system operational status, service health checks, and standardized error responses."""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Liveness and readiness check schema."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ...,
        description="Overall service health classification",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    version: Annotated[str, Field(min_length=1, max_length=32)]
    checks: dict[str, str] = Field(
        default_factory=dict,
        description="Subsystem status mappings (e.g. database: healthy, redis: healthy)",
    )


class SystemStatusResponse(BaseModel):
    """Detailed operational capability and operational configuration status."""

    model_config = ConfigDict(extra="forbid")

    app_name: Annotated[str, Field(min_length=1, max_length=64)]
    version: Annotated[str, Field(min_length=1, max_length=32)]
    environment: Annotated[str, Field(min_length=2, max_length=32)]
    status: Literal["operational", "maintenance", "degraded"] = "operational"
    ai_provider_mode: Annotated[
        str,
        Field(description="Current AI runtime adapter: e.g. 'mock', 'local', 'openai'"),
    ]
    active_capabilities: list[str] = Field(
        default_factory=list,
        description="List of enabled platform features and services",
    )
    database_connected: bool = Field(
        default=True,
        description="Whether primary database is reachable and accepting transactions",
    )
    active_workers: int = Field(
        default=2,
        description="Count of active lab/evaluator background worker processes",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )


class ErrorDetail(BaseModel):
    """Granular error indicator."""

    model_config = ConfigDict(extra="forbid")

    code: Annotated[str, Field(min_length=2, max_length=64)]
    message: Annotated[str, Field(min_length=2, max_length=512)]
    field: Annotated[str | None, Field(default=None, max_length=128)] = None


class StandardErrorResponse(BaseModel):
    """Canonical error payload returned across all API endpoints."""

    model_config = ConfigDict(extra="forbid")

    request_id: Annotated[
        str,
        Field(min_length=8, max_length=64, description="Correlation identifier for tracing"),
    ]
    error_code: Annotated[str, Field(min_length=2, max_length=64)]
    message: Annotated[str, Field(min_length=2, max_length=512)]
    details: list[ErrorDetail] = Field(default_factory=list)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    extra: dict[str, Any] = Field(default_factory=dict)
