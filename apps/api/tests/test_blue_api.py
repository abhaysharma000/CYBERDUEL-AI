"""Tests for Blue AI Defense Engine REST API endpoints (/api/v1/blue/*)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_blue_status_endpoint(async_client: AsyncClient) -> None:
    """Verify /api/v1/blue/status returns ready status and operational metrics."""
    response = await async_client.get("/api/v1/blue/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "active_research_tasks" in data
    assert "total_candidates_built" in data
    assert "candidate_acceptance_rate" in data
    assert "declarative_rule" in data["available_proposal_types"]


@pytest.mark.asyncio
async def test_blue_research_initiation_and_fetch(async_client: AsyncClient) -> None:
    """Verify initiating a research task via handoff payload and retrieving it by task_id."""
    s1_id = str(uuid4())
    payload = {
        "handoff_package": {
            "handoff_id": str(uuid4()),
            "experiment_id": str(uuid4()),
            "detector_version": "1.0.0",
            "policy_version": "1.0.0",
            "total_failures": 1,
            "findings": [
                {
                    "finding_id": str(uuid4()),
                    "experiment_id": str(uuid4()),
                    "failure_category": "homoglyph_spoofing",
                    "discrepancy_type": "false_negative",
                    "hypothesis": "Detector missed IDN punycode",
                    "affected_scenarios_count": 5,
                    "representative_scenario_ids": [s1_id],
                    "suggested_remedy": "Add declarative rule on is_punycode",
                    "severity": "critical",
                }
            ],
            "representative_scenarios": [
                {
                    "scenario_id": s1_id,
                    "scenario_family": "homograph_mimicry",
                    "scenario_name": "IDN-Phish-Test",
                    "description": "Punycode spoof",
                    "expected_class": "malicious",
                    "expected_decision": "block",
                    "difficulty": "intermediate",
                    "tags": ["homoglyph"],
                    "seed": 1,
                    "generator_version": "1.0",
                    "input_fixture": {"raw_url": "https://xn--pypal-4ve.com/signin?verify=account"},
                    "expected_evidence": ["homoglyph"],
                    "provenance": {},
                    "safety_classification": "harmless_synthetic",
                }
            ],
            "reproduction_config": {},
            "suggested_investigation_questions": [],
        }
    }

    # 1. Initiate Research
    init_res = await async_client.post("/api/v1/blue/research", json=payload)
    assert init_res.status_code == 201
    init_data = init_res.json()
    assert "task_id" in init_data
    task_id = init_data["task_id"]
    assert init_data["findings_count"] == 1
    assert "homoglyph_spoofing" in init_data["top_priority"]

    # 2. Fetch Research Task
    get_res = await async_client.get(f"/api/v1/blue/research/{task_id}")
    assert get_res.status_code == 200
    task_data = get_res.json()
    assert task_data["task_id"] == task_id
    assert task_data["status"] == "active"

    # 3. List Failure Groups
    fg_res = await async_client.get("/api/v1/blue/failure-groups")
    assert fg_res.status_code == 200
    fg_data = fg_res.json()
    assert len(fg_data) >= 1
    assert any(g["failure_category"] == "homoglyph_spoofing" for g in fg_data)

    # 4. Generate Candidate Defense from Task
    cand_payload = {
        "task_id": task_id,
        "failure_category": "homoglyph_spoofing",
        "proposal_type": "declarative_rule",
        "auto_sandbox": True,
    }
    cand_res = await async_client.post("/api/v1/blue/candidates", json=cand_payload)
    assert cand_res.status_code == 201
    cand_data = cand_res.json()
    assert "candidate" in cand_data
    cand_id = cand_data["candidate"]["defense_id"]
    assert "hypothesis" in cand_data
    assert "proposal" in cand_data
    assert cand_data["comparison"] is not None
    assert cand_data["comparison"]["new_regressions"] == 0

    # 5. Fetch Candidate Defense by ID
    get_cand_res = await async_client.get(f"/api/v1/blue/candidates/{cand_id}")
    assert get_cand_res.status_code == 200
    assert get_cand_res.json()["defense_id"] == cand_id

    # 6. Fetch Candidate Sandbox Comparison Report
    comp_res = await async_client.get(f"/api/v1/blue/candidates/{cand_id}/comparison")
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["candidate_id"] == cand_id
    assert comp_data["new_regressions"] == 0

    # 7. Evaluate Candidate Defense via Independent Evaluator
    eval_res = await async_client.post(
        f"/api/v1/blue/candidates/{cand_id}/evaluate",
        json={"suite_id": "curated-golden-v1"},
    )
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert "evaluation" in eval_data
    assert eval_data["evaluation"]["verdict"] in {"pass", "fail"}
    assert "feedback" in eval_data

    # 8. Check Candidate History Audit Trail
    hist_res = await async_client.get("/api/v1/blue/history")
    assert hist_res.status_code == 200
    hist_data = hist_res.json()
    assert len(hist_data) >= 1
    assert any(h["candidate_id"] == cand_id for h in hist_data)
