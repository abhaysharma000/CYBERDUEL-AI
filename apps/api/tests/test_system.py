"""Tests for system status and operational capability inspection."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_system_status_endpoint(async_client: AsyncClient) -> None:
    response = await async_client.get("/api/v1/system/status")
    assert response.status_code == 200
    data = response.json()

    assert data["app_name"] == "CyberDuel AI"
    assert data["status"] == "operational"
    assert data["environment"] == "test"
    assert data["ai_provider_mode"] == "mock"
    assert isinstance(data["active_capabilities"], list)
    assert "threat_classification" in data["active_capabilities"]
    assert "declarative_policy_distribution" in data["active_capabilities"]

    # Verify tracking headers
    assert "X-Request-ID" in response.headers
    assert response.headers["X-Request-ID"].startswith("cd-")
