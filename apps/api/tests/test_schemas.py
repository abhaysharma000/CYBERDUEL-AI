"""Tests for API routes handling analysis, telemetry, and updates."""

from uuid import uuid4

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_evaluate_resource_malicious(async_client: AsyncClient) -> None:
    payload = {
        "normalized_identifier": "phish-hash-" + "1" * 53,
        "resource_url": "https://secure-login.phish-account.com",
        "resource_type": "url",
        "client_id": "client-101",
    }
    response = await async_client.post("/api/v1/analysis/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "block"
    assert data["threat_score"] >= 0.8
    assert len(data["evidence"]) >= 1
    assert data["provenance"] == "model_inference"


@pytest.mark.asyncio
async def test_evaluate_resource_benign(async_client: AsyncClient) -> None:
    payload = {
        "normalized_identifier": "benign-hash-" + "2" * 52,
        "resource_url": "https://legitimate-site.org",
        "resource_type": "url",
    }
    response = await async_client.post("/api/v1/analysis/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["threat_score"] < 0.2


@pytest.mark.asyncio
async def test_ingest_telemetry_observation(async_client: AsyncClient) -> None:
    payload = {
        "observation_id": str(uuid4()),
        "source": "browser_extension",
        "normalized_target": "norm-target-" + "3" * 52,
        "local_action_taken": "warn",
        "engine_version": "0.1.0",
        "policy_version": "2026.10.1",
        "telemetry_summary": {"has_homoglyphs": True},
    }
    response = await async_client.post("/api/v1/telemetry/observations", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted_for_triage"
    assert "receipt_id" in data


@pytest.mark.asyncio
async def test_check_for_updates_available(async_client: AsyncClient) -> None:
    payload = {
        "client_id": "client-uuid-test",
        "client_type": "browser_extension",
        "current_policy_version": "2026.09.1",  # older version
        "engine_version": "0.1.0",
        "platform": "Chrome-130",
    }
    response = await async_client.post("/api/v1/updates/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["update_available"] is True
    assert data["target_version"] == "2026.10.1"
    assert data["rules_digest"] is not None


@pytest.mark.asyncio
async def test_check_for_updates_up_to_date(async_client: AsyncClient) -> None:
    payload = {
        "client_id": "client-uuid-test",
        "client_type": "browser_extension",
        "current_policy_version": "2026.10.1",  # current version
        "engine_version": "0.1.0",
        "platform": "Chrome-130",
    }
    response = await async_client.post("/api/v1/updates/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["update_available"] is False


@pytest.mark.asyncio
async def test_acknowledge_update(async_client: AsyncClient) -> None:
    payload = {
        "acknowledgement_id": str(uuid4()),
        "client_id": "client-uuid-test",
        "policy_version": "2026.10.1",
        "status": "applied",
        "error_message": None,
    }
    response = await async_client.post("/api/v1/updates/ack", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "recorded"
