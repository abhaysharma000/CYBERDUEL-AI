"""Tests for centralized exception handlers and information leakage prevention."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_404_not_found_returns_standard_error(async_client: AsyncClient) -> None:
    response = await async_client.get("/api/v1/nonexistent/endpoint")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "HTTP_404"
    assert "request_id" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_422_validation_error_structure(async_client: AsyncClient) -> None:
    # Send malformed payload to evaluate endpoint
    response = await async_client.post(
        "/api/v1/analysis/evaluate",
        json={"invalid_field": 123},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error_code"] == "VALIDATION_FAILED"
    assert len(data["details"]) > 0
    assert "request_id" in data


@pytest.mark.asyncio
async def test_413_payload_too_large(async_client: AsyncClient) -> None:
    # Attempt to post a body exceeding default MAX_REQUEST_BODY_BYTES (1 MB)
    huge_len = 1_200_000
    response = await async_client.post(
        "/api/v1/telemetry/observations",
        content="x",
        headers={"Content-Length": str(huge_len), "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    data = response.json()
    assert data["error_code"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.asyncio
async def test_information_leakage_prevented_on_internal_error(
    async_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Trigger an unexpected exception
    async def mock_crashing_evaluate(*args: object, **kwargs: object) -> None:
        raise RuntimeError(
            "Sensitive internal database connection error: user=admin pass=supersecret"
        )

    monkeypatch.setattr(
        "apps.api.app.providers.mock_provider.DeterministicMockProvider.classify_resource",
        mock_crashing_evaluate,
    )

    response = await async_client.post(
        "/api/v1/analysis/evaluate",
        json={
            "normalized_identifier": "a" * 64,
            "resource_url": "https://example.com",
            "resource_type": "url",
        },
    )
    assert response.status_code == 500
    data = response.json()
    assert data["error_code"] == "INTERNAL_SERVER_ERROR"
    # Ensure sensitive credentials and raw trace are obscured in non-debug mode
    assert "supersecret" not in response.text
    assert "admin" not in response.text
    assert data["message"] == "An unexpected internal server error occurred."
