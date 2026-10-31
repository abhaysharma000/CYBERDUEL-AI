"""Comprehensive test suite for CyberDuel Guardian supervisory agent.

Validates:
1. Live agent monitoring and truthful status reporting.
2. Supervised research-to-defense mission orchestration.
3. Comparative decision reasoning and user protection recommendations.
4. The 9-stage 'CyberDuel Live Defense Challenge' executing the complete autonomous loop.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from uuid import uuid4

from apps.api.app.main import app
from apps.api.app.services.blue_ai import CandidateDefenseBuilder
from apps.api.app.services.guardian.decision_engine import GuardianDecisionEngine
from apps.api.app.services.guardian.monitor import GuardianAgentMonitor
from apps.api.app.services.guardian.supervisor import CyberDuelGuardian
from cyberduel_contracts.enums import Decision, EvaluationVerdict, ProposalType, ThreatSeverity
from cyberduel_contracts.evaluation import ConfusionMatrix, EvaluationReport, ImprovementMetrics
from cyberduel_contracts.guardian import (
    GuardianDecisionOutcome,
    GuardianMissionRequest,
    GuardianState,
)
from cyberduel_contracts.policy import (
    CandidateDefense,
    DeclarativeRuleModel,
    DefenseProposal,
    RulePredicateModel,
)


@pytest.mark.asyncio
async def test_guardian_status_endpoint(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/guardian/status returns structured telemetry across all agents."""
    resp = await async_client.get("/api/v1/guardian/status")
    assert resp.status_code == 200
    data = resp.json()

    assert data["guardian_name"] == "CyberDuel Guardian"
    assert "state" in data
    assert "agent_health" in data
    assert "red_ai" in data["agent_health"]
    assert "blue_ai" in data["agent_health"]
    assert "evaluator" in data["agent_health"]
    assert data["agent_health"]["evaluator"]["details"]["uses_llm"] is False
    assert data["agent_health"]["evaluator"]["details"]["acceptance_criteria"] == "zero_regressions_required"
    assert "qwen_status" in data
    assert "active_policy_version" in data


@pytest.mark.asyncio
async def test_guardian_decision_engine_reasoning() -> None:
    """Verify GuardianDecisionEngine correctly prioritizes candidates with zero regressions."""
    rule = DeclarativeRuleModel(
        rule_id="RULE-HOMO-01",
        description="Block Paypal IDN homoglyphs",
        author="BlueAI",
        purpose="Block Paypal homoglyph evasion",
        target_family="homograph_mimicry",
        feature_names=["is_punycode", "brand_token_detected"],
        severity=ThreatSeverity.CRITICAL,
        action=Decision.BLOCK,
        predicates=[
            RulePredicateModel(field="is_punycode", operator="eq", value=1),
            RulePredicateModel(field="brand_token_detected", operator="eq", value=1),
        ],
    )
    proposal = DefenseProposal(
        hypothesis_id=uuid4(),
        proposal_type=ProposalType.DECLARATIVE_RULE,
        title="Test Proposal",
        rationale="Test Rationale",
        declarative_rule=rule,
    )
    candidate = CandidateDefenseBuilder.assemble_candidate([proposal])

    metrics_pass = ConfusionMatrix(tp=95, fp=0, tn=100, fn=5)

    report_pass = EvaluationReport(
        request_id="00000000-0000-0000-0000-000000000001",
        candidate_id="00000000-0000-0000-0000-000000000002",
        candidate_version="1.2.0",
        baseline_version="1.1.0",
        benchmark_manifest_version="1.0.0",
        verdict=EvaluationVerdict.PASS,
        verdict_rationale="Passed all criteria",
        baseline_metrics=ConfusionMatrix(tp=80, fp=0, tn=100, fn=20),
        candidate_metrics=metrics_pass,
        improvement_metrics=ImprovementMetrics(new_regressions=0),
        acceptance_reasons=["zero_regressions", "recall_threshold"],
        rejection_reasons=[],
    )

    explanation = GuardianDecisionEngine.evaluate_candidate_for_release(
        candidate=candidate,
        report=report_pass,
        baseline_version="1.1.0",
    )

    assert explanation.release_recommendation == "promote"
    assert explanation.threat_priority == "critical"
    assert explanation.evaluator_verdict == "pass"
    assert "Zero false positives" in explanation.false_positive_concerns
    assert explanation.confidence > 0.95

    # Test user-centric outcome resolution
    outcome, msg = GuardianDecisionEngine.resolve_user_decision(
        threat_score=0.85, matched_rule_id="RULE-HOMO-01"
    )
    assert outcome == GuardianDecisionOutcome.BLOCK
    assert "RULE-HOMO-01" in msg

    outcome_allow, _ = GuardianDecisionEngine.resolve_user_decision(threat_score=0.10)
    assert outcome_allow == GuardianDecisionOutcome.ALLOW


@pytest.mark.asyncio
async def test_guardian_live_defense_challenge_e2e(async_client: AsyncClient) -> None:
    """Verify the 9-stage 'CyberDuel Live Defense Challenge' runs and completes with verified protection."""
    resp = await async_client.post("/api/v1/guardian/challenge")
    assert resp.status_code == 201
    data = resp.json()

    assert data["mission_name"] == "CyberDuel Live Defense Challenge"
    assert data["state"] == "released"
    assert data["initial_threat_url"] is not None
    assert data["initial_decision"] == "warn"
    assert data["final_decision"] == "block"
    assert data["benign_control_decision"] == "allow"
    assert data["policy_version"] is not None
    assert data["decision_explanation"] is not None
    assert data["decision_explanation"]["release_recommendation"] == "promote"
    assert len(data["timeline"]) >= 7

    # Verify activity endpoint returns the recorded events
    act_resp = await async_client.get("/api/v1/guardian/activity?limit=10")
    assert act_resp.status_code == 200
    events = act_resp.json()
    assert len(events) >= 1
    assert any("Stage" in e["message"] for e in events)
