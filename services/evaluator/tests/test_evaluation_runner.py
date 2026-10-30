"""Comprehensive tests for the Independent Evaluation Engine, Benchmark Registry, and Metrics."""

import pytest
from cyberduel_contracts.enums import (
    DatasetSplitType,
    Decision,
    EvaluationStatus,
    EvaluationVerdict,
    ExpectedClass,
)
from cyberduel_contracts.evaluation import (
    AcceptancePolicyConfig,
    BenchmarkManifest,
    BenchmarkScenarioItem,
    ConfusionMatrix,
    EvaluationRequest,
    ImprovementMetrics,
    OperationalMetrics,
)
from cyberduel_contracts.policy import CandidateDefense, DeclarativeRuleModel, RulePredicateModel

from services.evaluator.app.acceptance import AcceptancePolicyEngine
from services.evaluator.app.benchmarks import BenchmarkRegistry
from services.evaluator.app.metrics import MetricsEngine
from services.evaluator.app.runner import EvaluationRunner


def test_confusion_matrix_properties() -> None:
    """Verify exact mathematical computations of confusion matrix and edge cases."""
    cm = ConfusionMatrix(tp=80, fp=5, tn=95, fn=20)
    assert cm.total == 200
    assert cm.precision == round(80 / 85, 4)
    assert cm.recall == round(80 / 100, 4)
    assert cm.accuracy == round(175 / 200, 4)
    assert cm.false_positive_rate == round(5 / 100, 4)
    assert cm.false_negative_rate == round(20 / 100, 4)
    assert cm.f1 > 0.85

    # Zero denominator edge case
    empty_cm = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0)
    assert empty_cm.total == 0
    assert empty_cm.precision == 0.0
    assert empty_cm.recall == 0.0
    assert empty_cm.f1 == 0.0
    assert empty_cm.accuracy == 0.0


def test_metrics_engine_classification() -> None:
    """Verify MetricsEngine correctly maps threat and benign scenarios to TP, FP, TN, FN."""
    records = [
        # True Positive: Malicious blocked
        {"actual_decision": Decision.BLOCK, "expected_class": ExpectedClass.MALICIOUS},
        # True Positive: Suspicious warned
        {"actual_decision": Decision.WARN, "expected_class": ExpectedClass.SUSPICIOUS},
        # False Negative: Malicious allowed
        {"actual_decision": Decision.ALLOW, "expected_class": ExpectedClass.MALICIOUS},
        # True Negative: Benign allowed
        {"actual_decision": Decision.ALLOW, "expected_class": ExpectedClass.BENIGN},
        # False Positive: Benign blocked
        {"actual_decision": Decision.BLOCK, "expected_class": ExpectedClass.BENIGN},
    ]
    cm = MetricsEngine.compute_confusion_matrix(records)
    assert cm.tp == 2
    assert cm.fn == 1
    assert cm.tn == 1
    assert cm.fp == 1
    assert cm.total == 5


def test_operational_metrics_p95_computation() -> None:
    """Verify latency percentiles and error metrics computation."""
    durations = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    op = MetricsEngine.compute_operational_metrics(durations, error_count=1, timeout_count=0)
    assert op.mean_latency_ms == 5.5
    assert op.max_latency_ms == 10.0
    assert op.p95_latency_ms == 10.0
    assert op.error_count == 1


def test_benchmark_registry_defaults_and_integrity() -> None:
    """Verify standard golden benchmark loads with valid integrity hash and counts."""
    reg = BenchmarkRegistry()
    manifest = reg.get_manifest("benchmark-golden-v1")
    assert manifest is not None
    assert manifest.scenario_count == 25
    assert len(manifest.integrity_hash) == 64
    assert DatasetSplitType.HELD_OUT.value in manifest.split_counts
    assert DatasetSplitType.REGRESSION.value in manifest.split_counts
    assert DatasetSplitType.DEVELOPMENT.value in manifest.split_counts


def test_benchmark_split_isolation_passes_golden() -> None:
    """Golden benchmark manifest must pass group and split isolation with zero violations."""
    reg = BenchmarkRegistry()
    manifest = reg.get_manifest("benchmark-golden-v1")
    assert manifest is not None
    is_valid, violations = reg.validate_split_isolation(manifest)
    assert is_valid is True
    assert len(violations) == 0


def test_benchmark_split_isolation_detects_url_leakage() -> None:
    """Detect duplicate URL leakage across distinct benchmark splits."""
    reg = BenchmarkRegistry()
    scenarios = [
        BenchmarkScenarioItem(
            url="https://leaked-target.com/login",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            scenario_family="brand_impersonation",
            split=DatasetSplitType.DEVELOPMENT,
            group_id="group_a",
        ),
        BenchmarkScenarioItem(
            url="https://leaked-target.com/login",  # Exact duplicate in held-out
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            scenario_family="brand_impersonation",
            split=DatasetSplitType.HELD_OUT,
            group_id="group_b",
        ),
    ]
    manifest = BenchmarkManifest(
        manifest_id="test-leaked-urls",
        name="Leakage Test Suite",
        version="1.0.0",
        description="Suite with duplicate URLs",
        scenario_count=2,
        scenarios=scenarios,
    )
    is_valid, violations = reg.validate_split_isolation(manifest)
    assert is_valid is False
    assert any("URL leakage" in v for v in violations)


def test_benchmark_split_isolation_detects_group_leakage() -> None:
    """Detect group/lineage domain leakage between training and held-out evaluation."""
    reg = BenchmarkRegistry()
    scenarios = [
        BenchmarkScenarioItem(
            url="https://campaign-alpha.com/login1",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            scenario_family="brand_impersonation",
            split=DatasetSplitType.DEVELOPMENT,
            group_id="group_campaign_alpha",
        ),
        BenchmarkScenarioItem(
            url="https://campaign-alpha.com/login2",  # Different URL, same group in held-out
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            scenario_family="brand_impersonation",
            split=DatasetSplitType.HELD_OUT,
            group_id="group_campaign_alpha",
        ),
    ]
    manifest = BenchmarkManifest(
        manifest_id="test-group-leakage",
        name="Group Leakage Test Suite",
        version="1.0.0",
        description="Suite with shared group_id across train and eval",
        scenario_count=2,
        scenarios=scenarios,
    )
    is_valid, violations = reg.validate_split_isolation(manifest)
    assert is_valid is False
    assert any("Group/lineage leakage" in v for v in violations)


def test_acceptance_policy_enforcement() -> None:
    """Verify AcceptancePolicyEngine gates (regressions, FPR, minimum detection rate)."""
    candidate = CandidateDefense(
        version="0.2.1-candidate",
        author_agent="BlueAI",
        description="Test defense",
        rule_spec={"rules": [{"rule_id": "r1"}]},
    )
    policy = AcceptancePolicyConfig(
        max_allowed_fpr=0.05,
        max_allowed_regressions=0,
        min_detection_rate=0.70,
    )

    # Case A: Passes all gates
    verdict, status, _, _, rejections = AcceptancePolicyEngine.evaluate(
        candidate=candidate,
        candidate_metrics=ConfusionMatrix(tp=90, fp=2, tn=98, fn=10),
        baseline_metrics=ConfusionMatrix(tp=70, fp=5, tn=95, fn=30),
        split_metrics={DatasetSplitType.HELD_OUT.value: ConfusionMatrix(tp=10, fp=0, tn=10, fn=0)},
        improvement_metrics=ImprovementMetrics(
            original_failures_resolved=5,
            original_failures_total=5,
            resolution_rate=1.0,
            new_regressions=0,
            new_false_positives=0,
        ),
        operational_metrics=OperationalMetrics(mean_latency_ms=1.2),
        policy=policy,
    )
    assert verdict == EvaluationVerdict.PASS
    assert status == EvaluationStatus.ACCEPTED
    assert len(rejections) == 0

    # Case B: Rejects due to regressions
    verdict_reg, status_reg, _, _, rejections_reg = AcceptancePolicyEngine.evaluate(
        candidate=candidate,
        candidate_metrics=ConfusionMatrix(tp=90, fp=2, tn=98, fn=10),
        baseline_metrics=ConfusionMatrix(tp=70, fp=5, tn=95, fn=30),
        split_metrics={},
        improvement_metrics=ImprovementMetrics(
            new_regressions=2,  # > 0 allowed
            original_failures_resolved=5,
            original_failures_total=5,
        ),
        operational_metrics=OperationalMetrics(mean_latency_ms=1.2),
        policy=policy,
    )
    assert verdict_reg == EvaluationVerdict.FAIL
    assert status_reg == EvaluationStatus.REJECTED
    assert any("regressions" in r for r in rejections_reg)

    # Case C: Rejects due to high FPR
    verdict_fpr, _, _, _, rejections_fpr = AcceptancePolicyEngine.evaluate(
        candidate=candidate,
        candidate_metrics=ConfusionMatrix(tp=90, fp=20, tn=80, fn=10),  # FPR = 20%
        baseline_metrics=ConfusionMatrix(tp=70, fp=5, tn=95, fn=30),
        split_metrics={},
        improvement_metrics=ImprovementMetrics(new_regressions=0),
        operational_metrics=OperationalMetrics(mean_latency_ms=1.2),
        policy=policy,
    )
    assert verdict_fpr == EvaluationVerdict.FAIL
    assert any("FPR" in r for r in rejections_fpr)


@pytest.mark.asyncio
async def test_evaluation_runner_real_execution() -> None:
    """Verify EvaluationRunner executes real CandidateDetectorSandbox on benchmark suite."""
    reg = BenchmarkRegistry()
    runner = EvaluationRunner(benchmark_registry=reg)

    rule = DeclarativeRuleModel(
        rule_id="rule-test-ip-port",
        rule_version="1.0.0",
        description="Flag direct suspicious IP and port accesses",
        purpose="Mitigate raw IP evasion",
        target_family="ip_host",
        predicates=[
            RulePredicateModel(
                field="is_ip_literal",
                operator="eq",
                value=True,
            )
        ],
        action=Decision.BLOCK,
        weight=0.95,
    )
    candidate = CandidateDefense(
        version="0.3.0-runner-test",
        author_agent="BlueAI-Test",
        description="Declarative rule blocking IP literal hosts",
        rule_spec={"rules": [rule.model_dump(mode="json")]},
    )

    request = EvaluationRequest(
        candidate_id=candidate.defense_id,
        candidate_version=candidate.version,
        benchmark_manifest_version="benchmark-golden-v1",
        acceptance_policy=AcceptancePolicyConfig(
            max_allowed_fpr=0.05,
            max_allowed_regressions=0,
            min_detection_rate=0.50,
        ),
    )

    report = await runner.run_evaluation(request=request, candidate=candidate)

    assert report.candidate_version == "0.3.0-runner-test"
    assert report.candidate_metrics.total == 25
    assert report.candidate_metrics.tp > 0
    assert report.candidate_metrics.tn > 0
    assert report.operational_metrics.mean_latency_ms >= 0.0
    assert len(report.report_digest) == 64
    assert len(report.split_metrics) > 0
    assert DatasetSplitType.HELD_OUT.value in report.split_metrics
