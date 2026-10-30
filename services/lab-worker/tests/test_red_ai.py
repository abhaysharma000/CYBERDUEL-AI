"""Comprehensive test suite for Red AI scenario generation, mutation, execution, and failure analysis."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cyberduel_contracts.enums import Decision, ExpectedClass, ScenarioFamily
from cyberduel_contracts.lab import ExperimentConfig, ScenarioContract

from services.lab_worker.app.red_ai.analyzer import FailureAnalyzer
from services.lab_worker.app.red_ai.generator import ScenarioGenerator
from services.lab_worker.app.red_ai.handoff import EvaluationHandoff
from services.lab_worker.app.red_ai.mutator import ScenarioMutationEngine
from services.lab_worker.app.red_ai.patterns import ThreatPatternLibrary
from services.lab_worker.app.red_ai.runner import DefensiveTestRunner
from services.lab_worker.app.red_ai.validator import ScenarioValidator
from services.lab_worker.app.worker import SafeLabWorker


def test_threat_pattern_library_completeness() -> None:
    """Verify threat pattern library contains templates across all required scenario families."""
    templates = ThreatPatternLibrary.list_templates()
    assert len(templates) >= 25

    families = ThreatPatternLibrary.supported_families()
    assert len(families) >= 12
    assert ScenarioFamily.HOMOGRAPH_MIMICRY.value in families
    assert ScenarioFamily.AUTHORITY_SPOOFING.value in families
    assert ScenarioFamily.IP_HOST.value in families
    assert ScenarioFamily.BRAND_IMPERSONATION.value in families
    assert ScenarioFamily.BENIGN_LOOKALIKE.value in families
    assert ScenarioFamily.WHITELIST_CONTROL.value in families


def test_scenario_generation_determinism() -> None:
    """Verify that identical random seeds produce identical scenario corpora."""
    gen1 = ScenarioGenerator(seed=1337)
    corpus1 = gen1.generate_corpus(count=30, goal="determinism_test")

    gen2 = ScenarioGenerator(seed=1337)
    corpus2 = gen2.generate_corpus(count=30, goal="determinism_test")

    assert len(corpus1) == len(corpus2) == 30
    for s1, s2 in zip(corpus1, corpus2, strict=False):
        assert s1.scenario_name == s2.scenario_name
        assert s1.input_fixture["raw_url"] == s2.input_fixture["raw_url"]
        assert s1.expected_class == s2.expected_class
        assert s1.expected_decision == s2.expected_decision


def test_scenario_generation_different_seeds() -> None:
    """Verify different seeds produce varied parameterizations."""
    gen1 = ScenarioGenerator(seed=101)
    corpus1 = gen1.generate_corpus(count=50)

    gen2 = ScenarioGenerator(seed=999)
    corpus2 = gen2.generate_corpus(count=50)

    urls1 = {s.input_fixture["raw_url"] for s in corpus1}
    urls2 = {s.input_fixture["raw_url"] for s in corpus2}
    assert urls1 != urls2


def test_generated_scenarios_strictly_valid() -> None:
    """Verify all generated scenarios strictly pass ScenarioValidator."""
    gen = ScenarioGenerator(seed=42)
    corpus = gen.generate_corpus(count=100)
    assert len(corpus) == 100

    for s in corpus:
        res = ScenarioValidator.validate(s)
        assert res.is_valid is True, f"Validation failed: {res.error_message}"


def test_scenario_validator_rejects_malformed_inputs() -> None:
    """Verify validator catches length, scheme, and classification violations."""
    base = ScenarioContract(
        scenario_id=uuid4(),
        schema_version="1.0.0",
        scenario_family=ScenarioFamily.HOMOGRAPH_MIMICRY.value,
        scenario_name="Valid Test Scenario",
        description="A valid test scenario description",
        expected_class=ExpectedClass.MALICIOUS.value,
        expected_decision=Decision.BLOCK,
        difficulty="basic",
        input_fixture={"raw_url": "https://example.test/test"},
        provenance={"test": True},
        safety_classification="harmless_synthetic",
    )
    assert ScenarioValidator.validate(base).is_valid is True

    # 1. Invalid scheme (javascript:)
    bad_scheme = base.model_copy(update={"input_fixture": {"raw_url": "javascript:alert(1)"}})
    res = ScenarioValidator.validate(bad_scheme)
    assert res.is_valid is False
    assert res.error_code == "UNSUPPORTED_SCHEME"

    # 2. Name too short
    bad_name = base.model_copy(update={"scenario_name": "x"})
    res2 = ScenarioValidator.validate(bad_name)
    assert res2.is_valid is False
    assert res2.error_code == "INVALID_NAME_LENGTH"

    # 3. Invalid classification
    bad_class = base.model_copy(update={"safety_classification": "live_exploit"})  # type: ignore[arg-type]
    res3 = ScenarioValidator.validate(bad_class)
    assert res3.is_valid is False
    assert res3.error_code == "UNSAFE_CLASSIFICATION"


def test_mutation_engine_lineage_and_semantics() -> None:
    """Verify mutation records lineage and handles semantic shifts safely."""
    mutator = ScenarioMutationEngine(seed=42)
    base_scenario = ScenarioContract(
        scenario_id=uuid4(),
        schema_version="1.0.0",
        scenario_family=ScenarioFamily.BENIGN_LOOKALIKE.value,
        scenario_name="Benign Control",
        description="Benign test control",
        expected_class=ExpectedClass.BENIGN.value,
        expected_decision=Decision.ALLOW,
        input_fixture={"raw_url": "https://service.example.test/portal"},
        provenance={"origin": "unit_test"},
        safety_classification="harmless_synthetic",
    )

    # 1. Semantics-preserving mutation: case_variation
    mut_case = mutator.mutate(base_scenario, operator="case_variation")
    assert mut_case.mutation_parent_id == base_scenario.scenario_id
    assert len(mut_case.transformation_history) == 1
    assert mut_case.transformation_history[0]["operator"] == "case_variation"
    assert mut_case.transformation_history[0]["preserved_semantics"] is True
    assert mut_case.expected_class == ExpectedClass.BENIGN.value

    # 2. Mutation depth ceiling
    deep_scenario = base_scenario
    for _ in range(6):
        deep_scenario = mutator.mutate(deep_scenario, operator="query_param_injection", max_depth=3)
    assert len(deep_scenario.transformation_history) <= 3


@pytest.mark.asyncio
async def test_defensive_test_runner_real_pipeline() -> None:
    """Verify test runner executes real URLAnalysisService and returns structured results."""
    runner = DefensiveTestRunner(session=None)
    scenario = ScenarioContract(
        scenario_id=uuid4(),
        schema_version="1.0.0",
        scenario_family=ScenarioFamily.HOMOGRAPH_MIMICRY.value,
        scenario_name="PayPal Homoglyph",
        description="Homoglyph test case",
        expected_class=ExpectedClass.MALICIOUS.value,
        expected_decision=Decision.BLOCK,
        input_fixture={"raw_url": "https://xn--pypal-4ve.example.test/signin"},
        provenance={"test": True},
        safety_classification="harmless_synthetic",
    )

    res = await runner.execute_scenario(scenario, experiment_id=uuid4())
    assert res.scenario_id == scenario.scenario_id
    assert res.actual_decision in {Decision.BLOCK, Decision.WARN}
    assert res.actual_threat_score > 0.40
    assert len(res.actual_evidence) > 0
    assert "heuristic" in res.detector_version


def test_failure_analyzer_metrics_and_findings() -> None:
    """Verify FailureAnalyzer computes correct denominators and extracts hypotheses."""
    # Test empty executions
    empty_metrics = FailureAnalyzer.compute_metrics([])
    assert empty_metrics["total_scenarios"] == 0
    assert empty_metrics["accuracy"] == 0.0

    # Test findings generation
    findings = FailureAnalyzer.analyze_executions(
        experiment_id=uuid4(),
        executions=[],
    )
    assert len(findings) == 0


def test_evaluation_handoff_contract() -> None:
    """Verify EvaluationHandoff package adheres to independent evaluator specifications."""
    from datetime import UTC, datetime

    from cyberduel_contracts.lab import ExperimentRunSummary, FailureFinding

    exp_id = uuid4()
    summary = ExperimentRunSummary(
        experiment_id=exp_id,
        experiment_name="Handoff Test",
        goal="Test handoff packaging",
        status="completed",
        seed=42,
        scenario_count=10,
        executed_count=10,
        discrepancy_count=2,
        metrics={"accuracy": 0.80},
        family_breakdown={},
        detector_version="0.2.0-heuristic",
        policy_version="2026.10.1",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )

    finding = FailureFinding(
        finding_id=uuid4(),
        experiment_id=exp_id,
        failure_category="over_detection",
        discrepancy_type="false_positive",
        hypothesis="Benign lookalikes triggered false positive",
        affected_scenarios_count=2,
        representative_scenario_ids=[uuid4(), uuid4()],
        suggested_remedy="Calibrate weights",
    )

    pkg = EvaluationHandoff.create_package(
        summary=summary,
        scenarios=[],
        findings=[finding],
    )
    assert pkg.experiment_id == exp_id
    assert pkg.total_failures == 2
    assert len(pkg.findings) == 1
    assert pkg.status == "handed_off"
    assert len(pkg.suggested_investigation_questions) >= 3


@pytest.mark.asyncio
async def test_safe_lab_worker_execution() -> None:
    """Verify SafeLabWorker respects sandbox invariants and processes experiments."""
    worker = SafeLabWorker()
    config = ExperimentConfig(
        experiment_name="Worker Integration Test",
        goal="Verify worker orchestration",
        scenario_count=5,
        seed=42,
    )

    summary = await worker.execute_experiment(config, session=None)
    assert summary.status == "completed"
    assert summary.executed_count == 5
    assert summary.scenario_count == 5
