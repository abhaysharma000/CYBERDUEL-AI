"""End-to-end integration smoke test for CyberDuel AI."""

from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.main import create_app


@pytest.mark.asyncio
async def test_full_platform_smoke_flow(async_client: AsyncClient) -> None:
    """Smoke test exercising the core integration cycle of the platform."""
    client = async_client
    # Step 1: Liveness Probe
    res_live = await client.get("/health/live")
    assert res_live.status_code == 200
    assert res_live.json()["status"] == "healthy"

    # Step 2: Readiness Probe
    res_ready = await client.get("/health/ready")
    assert res_ready.status_code == 200

    # Step 3: System Status & Capability Discovery
    res_status = await client.get("/api/v1/system/status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] == "operational"
    assert res_status.json()["ai_provider_mode"] == "mock"

    # Step 4: Evaluate Suspicious Threat
    eval_payload = {
        "normalized_identifier": "smoke-test-hash-" + "9" * 48,
        "resource_url": "https://secure-login.suspicious-phish.net",
        "resource_type": "url",
        "client_id": "client-smoke-01",
    }
    res_eval = await client.post("/api/v1/analysis/evaluate", json=eval_payload)
    assert res_eval.status_code == 200
    verdict = res_eval.json()
    assert verdict["decision"] in ["warn", "block"]
    assert verdict["threat_score"] > 0.4

    # Step 5: Submit Telemetry Report
    telemetry_payload = {
        "observation_id": str(uuid4()),
        "source": "browser_extension",
        "normalized_target": "smoke-test-hash-" + "9" * 48,
        "local_action_taken": "block",
        "engine_version": "0.1.0",
        "policy_version": "2026.10.1",
        "telemetry_summary": {"phish_score": 0.95},
    }
    res_telem = await client.post("/api/v1/telemetry/observations", json=telemetry_payload)
    assert res_telem.status_code == 202

    # Step 6: Query Policy Updates
    update_payload = {
        "client_id": "client-smoke-01",
        "client_type": "browser_extension",
        "current_policy_version": "2026.09.1",
        "engine_version": "0.1.0",
        "platform": "SmokePlatform-1.0",
    }
    res_update = await client.post("/api/v1/updates/check", json=update_payload)
    assert res_update.status_code == 200
    assert res_update.json()["update_available"] is True

    # Step 7: Acknowledge Update Application
    ack_payload = {
        "acknowledgement_id": str(uuid4()),
        "client_id": "client-smoke-01",
        "policy_version": "2026.10.1",
        "status": "applied",
        "error_message": None,
    }
    res_ack = await client.post("/api/v1/updates/ack", json=ack_payload)
    assert res_ack.status_code == 200
    assert res_ack.json()["status"] == "recorded"
