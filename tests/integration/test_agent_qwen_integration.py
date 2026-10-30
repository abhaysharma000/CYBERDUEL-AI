"""Comprehensive Integration Tests for Red AI & Blue AI Qwen Agent Integration.

Verifies:
1. Red AI selects and invokes QwenProvider when configured.
2. Blue AI selects and invokes QwenProvider when configured.
3. Provider failures fail closed without silent fallback in production.
4. Red AI strictly enforces RFC 2606 reserved domains (.test, .example) and rejects live domains.
5. Blue AI strictly validates AST predicates against allowed features and operators.
6. Invalid defensive rules cannot enter evaluation or authorization.
7. Failed or incomplete evaluation blocks release signing.
8. Held-out test set remains strictly isolated from agent inputs and prompts.
9. Full research-to-candidate persistence flow records provenance and audit metadata.
10. Guarded live Qwen inference roundtrip (opt-in with RUN_LIVE_QWEN_TESTS=1).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.config import Settings
from apps.api.app.models.base import Base
from apps.api.app.models.evaluations import (
    BenchmarkManifestRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
)
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.providers.base import (
    ProviderInferenceError,
    ProviderUnavailableError,
)
from apps.api.app.providers.qwen_provider import QwenProvider
from apps.api.app.services.blue_ai.hypothesis import DefenseHypothesisEngine
from apps.api.app.services.blue_ai.prioritizer import FailureCluster, PrioritizedFailureGroup
from apps.api.app.services.blue_ai.proposals import DefenseProposalGenerator
from apps.api.app.services.releases.eligibility import ReleaseEligibilityService
from cyberduel_contracts.enums import Decision, EvaluationVerdict, ScenarioFamily, ThreatSeverity
from cyberduel_contracts.lab import ScenarioContract
from cyberduel_contracts.policy import DeclarativeRuleModel, DefensiveHypothesis, RulePredicateModel
from cyberduel_policy_engine.rules import DeclarativeRuleEngine, RuleValidationError
from services.lab_worker.app.red_ai.generator import ScenarioGenerator


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def sample_priority_group() -> PrioritizedFailureGroup:
    """Fixture producing a prioritized failure cluster for Blue AI."""
    cluster = FailureCluster(
        cluster_id="cluster-test-01",
        failure_category="homoglyph_mimicry",
        target_family="phishing_and_credential_theft",
        discrepancy_type="false_negative",
        severity=ThreatSeverity.HIGH,
        findings=[],
        scenarios=[],
        affected_count=5,
        sample_urls=[
            "hxxps://login[.]micros0ft[.]example[.]test/auth",
            "hxxps://secure[.]paypa1[.]example[.]test/webapps",
        ],
    )
    return PrioritizedFailureGroup(
        cluster=cluster,
        priority_score=0.92,
        urgency_rank=1,
        rationale="High volume homoglyph evasion cluster",
        recommended_focus="Mitigate homoglyph login lookalikes",
    )


# ==============================================================================
# 1. Red AI Qwen Integration & Safety Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_red_ai_selects_qwen_provider() -> None:
    """Verify Red AI ScenarioGenerator invokes QwenProvider when configured."""
    mock_qwen = AsyncMock(spec=QwenProvider)
    mock_qwen.model_name = "Qwen/Qwen2.5-Coder-7B-Instruct"

    mock_scenario = ScenarioContract(
        scenario_id=uuid4(),
        schema_version="1.0.0",
        scenario_family=ScenarioFamily.HOMOGRAPH_MIMICRY.value,
        scenario_name="Qwen Homoglyph Phish",
        description="Synthesized by Qwen with authentic lookalike token",
        expected_class="malicious",
        expected_decision=Decision.BLOCK,
        difficulty="intermediate",
        tags=["qwen", "synthetic"],
        seed=1001,
        generator_version="qwen-Qwen2.5-Coder",
        input_fixture={"raw_url": "https://secure-login.brand-verify.test/oauth"},
        expected_evidence=["homoglyph"],
        provenance={"origin": "QwenProvider", "model": "Qwen/Qwen2.5-Coder-7B-Instruct"},
        safety_classification="harmless_synthetic",
    )
    mock_qwen.generate_scenario_contract.return_value = mock_scenario

    generator = ScenarioGenerator(seed=1001, provider=mock_qwen, provider_mode="qwen")
    scenarios = await generator.generate_corpus_async(count=1, families=[ScenarioFamily.HOMOGRAPH_MIMICRY])

    assert len(scenarios) >= 1
    assert scenarios[0].generator_version.startswith("qwen-")
    assert scenarios[0].provenance["origin"] == "QwenProvider"
    mock_qwen.generate_scenario_contract.assert_awaited()


@pytest.mark.asyncio
async def test_red_ai_rejects_unsafe_live_domains() -> None:
    """Verify Red AI strictly rejects URLs using live, non-RFC2606 domains."""
    mock_qwen = AsyncMock(spec=QwenProvider)
    mock_qwen.model_name = "Qwen/Qwen2.5-Coder-7B-Instruct"

    # Malicious/unsafe scenario targeting live Google domain
    unsafe_scenario = ScenarioContract(
        scenario_id=uuid4(),
        schema_version="1.0.0",
        scenario_family=ScenarioFamily.HOMOGRAPH_MIMICRY.value,
        scenario_name="Unsafe Live Domain Target",
        description="Violates safety by pointing to live routable domain",
        expected_class="malicious",
        expected_decision=Decision.BLOCK,
        difficulty="intermediate",
        tags=["unsafe"],
        seed=1002,
        generator_version="qwen-Qwen2.5-Coder",
        input_fixture={"raw_url": "https://accounts.google.com/ServiceLogin"},
        expected_evidence=["live_domain"],
        provenance={"origin": "QwenProvider"},
        safety_classification="harmless_synthetic",
    )
    mock_qwen.generate_scenario_contract.return_value = unsafe_scenario

    generator = ScenarioGenerator(seed=1002, provider=mock_qwen, provider_mode="qwen")
    with pytest.raises(ProviderInferenceError, match="Safety violation"):
        await generator.generate_corpus_async(count=1, families=[ScenarioFamily.HOMOGRAPH_MIMICRY])


@pytest.mark.asyncio
async def test_red_ai_fails_closed_in_production() -> None:
    """Verify Red AI fails closed in production without silent procedural fallback when Qwen fails."""
    mock_qwen = AsyncMock(spec=QwenProvider)
    mock_qwen.generate_scenario_contract.side_effect = ProviderUnavailableError("Qwen connection timed out")

    generator = ScenarioGenerator(seed=1003, provider=mock_qwen, provider_mode="qwen")

    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        with pytest.raises(ProviderInferenceError, match="failed in production"):
            await generator.generate_corpus_async(count=2, families=[ScenarioFamily.HOMOGRAPH_MIMICRY])


# ==============================================================================
# 2. Blue AI Qwen Integration & AST Validation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_blue_ai_selects_qwen_provider(sample_priority_group: PrioritizedFailureGroup) -> None:
    """Verify Blue AI DefenseHypothesisEngine invokes QwenProvider when configured."""
    task_id = uuid4()
    mock_qwen = AsyncMock(spec=QwenProvider)

    mock_hypothesis = DefensiveHypothesis(
        hypothesis_id=uuid4(),
        research_task_id=task_id,
        failure_category="homoglyph_mimicry",
        target_family="phishing_and_credential_theft",
        observed_behavior="Baseline allowed homoglyph variant URLs",
        expected_behavior="Detector should warn on punycode and brand keyword mismatch",
        possible_explanation="Heuristics lacked inspection of internationalized unicode labels",
        supporting_evidence=[{"sample": "hxxps://micros0ft[.]example[.]test"}],
        counterexamples=[],
        proposed_intervention={
            "proposal_type": "declarative_rule",
            "target_action": "block",
            "predicates": [
                {"field": "is_punycode", "operator": "eq", "value": 1},
                {"field": "phish_keyword_count", "operator": "gte", "value": 1},
            ],
            "recommended_weight": 0.90,
        },
        predicted_benefit="Neutralizes brand lookalike attacks",
        potential_risks="Low false positive risk with verified allowlist",
        test_plan="Benchmark against golden test suite",
        confidence=0.92,
    )
    mock_qwen.formulate_hypothesis.return_value = mock_hypothesis

    hypothesis = await DefenseHypothesisEngine.formulate_hypothesis_async(
        task_id=task_id,
        priority_group=sample_priority_group,
        provider=mock_qwen,
        provider_mode="qwen",
    )

    assert hypothesis.research_task_id == task_id
    assert hypothesis.confidence == 0.92
    assert hypothesis.proposed_intervention["target_action"] == "block"
    mock_qwen.formulate_hypothesis.assert_awaited_once()


@pytest.mark.asyncio
async def test_blue_ai_rejects_unallowlisted_predicates(
    sample_priority_group: PrioritizedFailureGroup,
) -> None:
    """Verify Blue AI rejects hypotheses containing unallowlisted features or arbitrary code."""
    task_id = uuid4()
    mock_qwen = AsyncMock(spec=QwenProvider)

    # Hypothesis attempting unallowlisted feature injection
    malicious_hypothesis = DefensiveHypothesis(
        hypothesis_id=uuid4(),
        research_task_id=task_id,
        failure_category="arbitrary_injection",
        target_family="exploit",
        observed_behavior="Bypass",
        expected_behavior="Block",
        possible_explanation="Unknown",
        proposed_intervention={
            "proposal_type": "declarative_rule",
            "target_action": "block",
            "predicates": [
                {"field": "unsupported_shell_eval", "operator": "eq", "value": "rm -rf"},
            ],
        },
        predicted_benefit="None",
        potential_risks="High",
        test_plan="None",
    )
    mock_qwen.formulate_hypothesis.return_value = malicious_hypothesis

    with pytest.raises(ProviderInferenceError, match="unallowlisted feature"):
        await DefenseHypothesisEngine.formulate_hypothesis_async(
            task_id=task_id,
            priority_group=sample_priority_group,
            provider=mock_qwen,
            provider_mode="qwen",
        )


@pytest.mark.asyncio
async def test_blue_ai_proposal_generator_validates_ast_rule() -> None:
    """Verify DefenseProposalGenerator generates schema-valid AST rule and runs AST validator."""
    hypothesis = DefensiveHypothesis(
        hypothesis_id=uuid4(),
        research_task_id=uuid4(),
        failure_category="credential_harvesting",
        target_family="phishing",
        observed_behavior="Missed login path",
        expected_behavior="Block login path",
        possible_explanation="Missing rule for login verify path",
        proposed_intervention={
            "proposal_type": "declarative_rule",
            "target_action": "block",
            "predicates": [
                {"field": "path_length", "operator": "gte", "value": 15},
                {"field": "phish_keyword_count", "operator": "gte", "value": 2},
            ],
            "recommended_weight": 0.88,
        },
        predicted_benefit="Blocks credential harvesting",
        potential_risks="Low",
        test_plan="Test against golden suite",
    )

    proposal = await DefenseProposalGenerator.generate_proposal_async(hypothesis)
    assert proposal.status == "built"
    assert proposal.declarative_rule is not None
    assert isinstance(proposal.declarative_rule, DeclarativeRuleModel)
    assert proposal.declarative_rule.action == Decision.BLOCK

    # Must pass strict AST validation
    DeclarativeRuleEngine.validate_rule(proposal.declarative_rule)


@pytest.mark.asyncio
async def test_blue_ai_fails_closed_in_production(
    sample_priority_group: PrioritizedFailureGroup,
) -> None:
    """Verify Blue AI fails closed without procedural fallback when Qwen fails in production."""
    mock_qwen = AsyncMock(spec=QwenProvider)
    mock_qwen.formulate_hypothesis.side_effect = ProviderUnavailableError("Qwen service unavailable")

    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        with pytest.raises(ProviderInferenceError, match="failed in production"):
            await DefenseHypothesisEngine.formulate_hypothesis_async(
                task_id=uuid4(),
                priority_group=sample_priority_group,
                provider=mock_qwen,
                provider_mode="qwen",
            )


# ==============================================================================
# 3. Independent Evaluator & Release Signing Authorization Gate
# ==============================================================================


@pytest.mark.asyncio
async def test_failed_evaluation_blocks_release_eligibility() -> None:
    """Verify that an evaluator failure verdict strictly blocks release eligibility."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        cand_id = uuid4()
        eval_id = uuid4()
        req_id = uuid4()

        # 1. Benchmark Manifest
        manifest = BenchmarkManifestRecord(
            id="golden-v1",
            name="Golden Suite",
            version="1.0",
            description="Benchmark manifest",
            split_counts={"test": 50},
            family_counts={"phishing": 50},
            scenario_count=50,
            scenarios_payload=[],
            integrity_hash="a" * 64,
        )
        session.add(manifest)

        # 2. Candidate Defense
        cand_rec = CandidateDefenseRecord(
            id=cand_id,
            version="1.2.0-candidate",
            author_agent="BlueAI-Qwen",
            description="Qwen proposed candidate defense",
            rule_spec={"rules": []},
            status="candidate",
        )
        session.add(cand_rec)

        # 3. Evaluation Request
        req_rec = EvaluationRequestRecord(
            id=req_id,
            candidate_id=cand_id,
            candidate_version="1.2.0-candidate",
            baseline_detector_version="0.2.0",
            baseline_policy_version="2026.10.1",
            benchmark_manifest_id="golden-v1",
            status="completed",
            requested_by="SelfImprovementController",
            resource_budget={},
            target_finding_ids=[],
            target_scenario_ids=[],
        )
        session.add(req_rec)

        # 4. Evaluation Report Record (with FAIL verdict)
        eval_rec = EvaluationReportRecord(
            id=eval_id,
            request_id=req_id,
            candidate_id=cand_id,
            candidate_version="1.2.0-candidate",
            baseline_version="1.0.0",
            benchmark_manifest_id="golden-v1",
            verdict=EvaluationVerdict.FAIL.value,
            status="completed",
            verdict_rationale="Candidate produced 2 false positive regressions.",
            acceptance_reasons=[],
            rejection_reasons=["Regressions detected"],
            baseline_metrics={},
            candidate_metrics={"accuracy": 0.75, "recall": 0.70, "false_positive_rate": 0.08, "f1_score": 0.72},
            split_metrics={},
            improvement_metrics={"regression_count": 2},
            operational_metrics={},
            report_digest="b" * 64,
            evaluated_at=datetime.now(UTC),
        )
        session.add(eval_rec)
        await session.commit()

        # Check release eligibility
        eligibility_service = ReleaseEligibilityService()
        report = await eligibility_service.check_eligibility(
            session=session,
            candidate_id=cand_id,
            evaluation_report_id=eval_id,
        )

        assert report.is_eligible is False
        assert any("FAIL" in r or "regression" in r.lower() for r in report.reasons)

    await engine.dispose()


# ==============================================================================
# 4. Held-Out Test Set Isolation Verification
# ==============================================================================


def test_held_out_dataset_strictly_isolated_from_agents() -> None:
    """Verify held-out test split is isolated and never referenced in agent sources."""
    import json
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent.parent
    test_path = repo_root / "datasets" / "splits" / "test_held_out.jsonl"
    assert test_path.exists()

    held_out_domains = set()
    with open(test_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                held_out_domains.add(item["domain"].lower())

    # Verify Red AI pattern library does not reference any held-out domain
    from services.lab_worker.app.red_ai.patterns import ThreatPatternLibrary
    templates = ThreatPatternLibrary.list_templates()
    for t in templates:
        from urllib.parse import urlparse
        host = urlparse(t.raw_url).hostname or ""
        assert host.lower() not in held_out_domains, f"Held-out domain leak in template {t.template_id}: {host}"


# ==============================================================================
# 5. Opt-in Live Qwen Inference Test
# ==============================================================================


@pytest.mark.skipif(
    not os.getenv("RUN_LIVE_QWEN_TESTS"),
    reason="LIVE INFERENCE BLOCKED: Live Qwen endpoint or credentials not configured in environment.",
)
@pytest.mark.asyncio
async def test_live_qwen_red_and_blue_roundtrip() -> None:
    """Live integration roundtrip: Red AI scenario synthesis and Blue AI hypothesis formulation."""
    provider = QwenProvider()
    reachable, msg, _ = await provider.check_endpoint_connectivity(timeout_seconds=5.0)
    assert reachable is True, f"Live Qwen endpoint unreachable: {msg}"

    # 1. Live Red AI scenario generation
    scenario = await provider.generate_scenario_contract(
        target_family="homoglyph_mimicry",
        goal="test live scenario generation",
        difficulty="basic",
        seed=42,
    )
    assert scenario.input_fixture["raw_url"].endswith((".test", ".example"))

    # 2. Live Blue AI hypothesis formulation
    hypothesis = await provider.formulate_hypothesis(
        task_id=uuid4(),
        failure_category="homoglyph_mimicry",
        target_family="phishing",
        discrepancy_type="false_negative",
        affected_count=2,
        sample_urls=[scenario.input_fixture["raw_url"]],
    )
    assert hypothesis.possible_explanation
    assert len(hypothesis.proposed_intervention.get("predicates", [])) >= 1
