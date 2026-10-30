"""Tests for the Research Laboratory REST API endpoints (/api/v1/lab)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_lab_status_endpoint(async_client: AsyncClient) -> None:
    """Verify /api/v1/lab/status returns health, sandbox flags, and supported families."""
    response = await async_client.get("/api/v1/lab/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["sandboxed"] is True
    assert data["external_network_blocked"] is True
    assert len(data["supported_families"]) >= 12
    assert "homograph_mimicry" in data["supported_families"]


@pytest.mark.asyncio
async def test_lab_scenarios_generate_endpoint(async_client: AsyncClient) -> None:
    """Verify /api/v1/lab/scenarios/generate returns a batch of validated ScenarioContracts."""
    payload = {
        "goal": "Test API generation",
        "count": 10,
        "seed": 42,
        "mutation_depth": 1,
    }
    response = await async_client.post("/api/v1/lab/scenarios/generate", json=payload)
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) == 10
    for s in scenarios:
        assert "scenario_id" in s
        assert "raw_url" in s["input_fixture"]
        assert s["safety_classification"] == "harmless_synthetic"


@pytest.mark.asyncio
async def test_lab_scenarios_list_endpoint(async_client: AsyncClient) -> None:
    """Verify /api/v1/lab/scenarios lists cataloged scenarios."""
    response = await async_client.get("/api/v1/lab/scenarios?limit=15")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 15


@pytest.mark.asyncio
async def test_lab_experiment_lifecycle_endpoints(async_client: AsyncClient) -> None:
    """Verify creating, querying, and inspecting results of an experiment via the API."""
    exp_payload = {
        "experiment_name": "API Integration Experiment",
        "goal": "Verify full API lifecycle",
        "scenario_count": 8,
        "seed": 42,
        "mutation_depth": 1,
    }
    create_res = await async_client.post("/api/v1/lab/experiments", json=exp_payload)
    assert create_res.status_code == 201
    exp_data = create_res.json()
    exp_id = exp_data["experiment_id"]
    assert exp_data["status"] == "completed"
    assert exp_data["executed_count"] == 8

    # Fetch experiment by ID
    get_res = await async_client.get(f"/api/v1/lab/experiments/{exp_id}")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["experiment_id"] == exp_id
    assert get_data["status"] == "completed"
    assert "accuracy" in get_data["metrics"]

    # Fetch experiment scenario execution results
    res_list = await async_client.get(f"/api/v1/lab/experiments/{exp_id}/results")
    assert res_list.status_code == 200
    results_data = res_list.json()
    assert len(results_data) == 8
    for r in results_data:
        assert "actual_decision" in r
        assert "actual_threat_score" in r


@pytest.mark.asyncio
async def test_lab_metrics_endpoint(async_client: AsyncClient) -> None:
    """Verify /api/v1/lab/metrics returns aggregated laboratory evaluation metrics."""
    response = await async_client.get("/api/v1/lab/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "overall_accuracy" in data
    assert "overall_tpr" in data
    assert "overall_fpr" in data
