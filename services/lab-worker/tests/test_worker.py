"""Tests for safe laboratory worker isolation and execution."""

from uuid import uuid4

import pytest

from services.lab_worker.app.config import LabWorkerSettings
from services.lab_worker.app.worker import SafeLabWorker


@pytest.mark.asyncio
async def test_lab_worker_safety_verification() -> None:
    worker = SafeLabWorker()
    assert not worker.is_running


@pytest.mark.asyncio
async def test_lab_worker_blocks_external_network_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "services.lab_worker.app.worker.worker_settings",
        LabWorkerSettings(ALLOW_EXTERNAL_NETWORK=True),
    )
    with pytest.raises(RuntimeError, match="SAFETY VIOLATION"):
        SafeLabWorker()


@pytest.mark.asyncio
async def test_lab_worker_process_synthetic_scenario() -> None:
    worker = SafeLabWorker()
    scenario_id = uuid4()
    result = await worker.process_synthetic_scenario(
        scenario_id=scenario_id,
        scenario_type="phishing_lure",
        payload_params={"homograph_domain": "ex-ample.com"},
    )
    assert result["scenario_id"] == str(scenario_id)
    assert result["status"] == "completed"
    assert result["safety_flags"]["live_binary_execution"] is False
    assert result["safety_flags"]["sandboxed"] is True
