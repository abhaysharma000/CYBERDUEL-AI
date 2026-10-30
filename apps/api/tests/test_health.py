"""Tests for API health endpoints (liveness & readiness probes)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_liveness_probe_returns_healthy(async_client: AsyncClient) -> None:
    response = await async_client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert data["checks"]["process"] == "alive"
    assert "X-Request-ID" in response.headers
    assert "X-Process-Time-Ms" in response.headers


@pytest.mark.asyncio
async def test_readiness_probe_returns_healthy(async_client: AsyncClient) -> None:
    response = await async_client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "database" in data["checks"]
    assert "ai_provider" in data["checks"]
    # Ensure sensitive credentials or passwords are NOT leaked in health response
    raw_text = response.text.lower()
    assert "password" not in raw_text
    assert "secret" not in raw_text


@pytest.mark.asyncio
async def test_readiness_probe_handles_db_failure(
    async_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def mock_failing_db() -> bool:
        return False

    monkeypatch.setattr("apps.api.app.api.router.check_database_health", mock_failing_db)

    response = await async_client.get("/health/ready")
    data = response.json()
    assert data["status"] == "degraded"
    assert data["checks"]["database"] == "unreachable"
