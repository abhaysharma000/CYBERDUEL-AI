"""REST API integration tests for Independent Evaluation and Self-Improvement Controller."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.lab import FailureFindingRecord, LabExperimentRecord
from apps.api.app.models.policies import CandidateDefenseRecord


@pytest.mark.asyncio
async def test_api_list_and_get_benchmarks(async_client: AsyncClient) -> None:
    """Verify listing and retrieving benchmark manifests via API."""
    response = await async_client.get("/api/v1/evaluations/benchmarks")
    assert response.status_code == 200
    manifests = response.json()
    assert isinstance(manifests, list)
    assert len(manifests) >= 1
    golden = next(m for m in manifests if m["manifest_id"] == "benchmark-golden-v1")
    assert golden["scenario_count"] == 25

    # Get specific manifest
    resp_single = await async_client.get("/api/v1/evaluations/benchmarks/benchmark-golden-v1")
    assert resp_single.status_code == 200
    data = resp_single.json()
    assert data["manifest_id"] == "benchmark-golden-v1"
    assert "benign_control" in data["split_counts"]


@pytest.mark.asyncio
async def test_api_submit_and_get_evaluation(
    async_client: AsyncClient,
    test_db_session: AsyncSession,
) -> None:
    """Verify submitting a candidate defense for independent evaluation and reading reports."""
    # 1. Create candidate defense in DB
    candidate = CandidateDefenseRecord(
        version="0.3.0-api-test-candidate",
        author_agent="BlueAI-Test",
        description="Candidate defense for API testing",
        rule_spec={
            "rules": [
                {
                    "rule_id": "rule-api-punycode",
                    "rule_version": "1.0.0",
                    "description": "Block punycode domain spoofing",
                    "purpose": "Mitigate homograph attacks",
                    "target_family": "homograph_mimicry",
                    "predicates": [
                        {
                            "field": "is_punycode",
                            "operator": "eq",
                            "value": True,
                        }
                    ],
                    "action": "block",
                    "weight": 0.90,
                }
            ]
        },
        status="candidate",
    )
    test_db_session.add(candidate)
    await test_db_session.commit()
    await test_db_session.refresh(candidate)

    # 2. Submit evaluation request
    payload = {
        "candidate_id": str(candidate.id),
        "benchmark_manifest_version": "benchmark-golden-v1",
        "requested_by": "TestSuite",
    }
    submit_resp = await async_client.post("/api/v1/evaluations", json=payload)
    assert submit_resp.status_code == 201
    report = submit_resp.json()
    assert report["candidate_version"] == "0.3.0-api-test-candidate"
    assert "verdict" in report
    request_id = report["request_id"]

    # 3. List evaluations
    list_resp = await async_client.get("/api/v1/evaluations")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1

    # 4. Get evaluation summary by request_id
    get_resp = await async_client.get(f"/api/v1/evaluations/{request_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["request_id"] == request_id

    # 5. Get full evaluation report
    report_resp = await async_client.get(f"/api/v1/evaluations/{request_id}/report")
    assert report_resp.status_code == 200
    assert report_resp.json()["report_digest"] != ""

    # 6. Get metrics breakdown
    metrics_resp = await async_client.get(f"/api/v1/evaluations/{request_id}/metrics")
    assert metrics_resp.status_code == 200
    m_data = metrics_resp.json()
    assert "candidate_metrics" in m_data
    assert "operational_metrics" in m_data


@pytest.mark.asyncio
async def test_api_improvement_cycle_endpoints(
    async_client: AsyncClient,
    test_db_session: AsyncSession,
) -> None:
    """Verify autonomous improvement cycle execution, history, and status APIs."""
    # Seed experiment and open finding
    experiment = LabExperimentRecord(
        name="adversarial_api_test",
        goal="Test cycle endpoint",
        status="completed",
    )
    test_db_session.add(experiment)
    await test_db_session.flush()

    finding = FailureFindingRecord(
        experiment_id=experiment.id,
        failure_category="evasion",
        discrepancy_type="false_negative",
        hypothesis="Detector missed suspicious homograph mimicked domain",
        affected_scenarios_count=3,
        representative_scenario_ids=[],
        suggested_remedy="Deploy declarative rule",
        severity="high",
        status="open",
    )
    test_db_session.add(finding)
    await test_db_session.commit()

    # 1. Start improvement cycle
    cycle_payload = {
        "trigger_reason": "api_integration_test",
        "max_candidates_per_cycle": 1,
        "cycle_timeout_seconds": 30.0,
    }
    start_resp = await async_client.post("/api/v1/improvement/cycles", json=cycle_payload)
    assert start_resp.status_code == 201
    cycle = start_resp.json()
    assert cycle["cycle_number"] >= 1
    assert "status" in cycle
    cycle_id = cycle["cycle_id"]

    # 2. List improvement cycles
    list_cycles_resp = await async_client.get("/api/v1/improvement/cycles")
    assert list_cycles_resp.status_code == 200
    assert len(list_cycles_resp.json()) >= 1

    # 3. Get single cycle details with checkpoints
    detail_resp = await async_client.get(f"/api/v1/improvement/cycles/{cycle_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["cycle_id"] == cycle_id
    assert len(detail["checkpoints"]) > 0

    # 4. Get trend report
    trend_resp = await async_client.get("/api/v1/improvement/history")
    assert trend_resp.status_code == 200
    trend = trend_resp.json()
    assert trend["total_cycles"] >= 1

    # 5. Get controller status
    status_resp = await async_client.get("/api/v1/improvement/status")
    assert status_resp.status_code == 200
    st = status_resp.json()
    assert "active_cycles_count" in st
    assert st["latest_cycle_number"] >= 1
