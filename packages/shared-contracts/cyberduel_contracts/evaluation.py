"""Schemas for independent evaluation runs, benchmarks, regression testing, and self-improvement."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field

from cyberduel_contracts.enums import (
    CycleStatus,
    DatasetSplitType,
    Decision,
    EvaluationStatus,
    EvaluationVerdict,
    ExpectedClass,
)


class ConfusionMatrix(BaseModel):
    """Rigorous confusion matrix and performance statistics for security evaluation."""

    model_config = ConfigDict(extra="ignore")

    tp: int = Field(default=0, ge=0, description="True Positives (Threat correctly flagged)")
    fp: int = Field(default=0, ge=0, description="False Positives (Benign incorrectly flagged)")
    tn: int = Field(default=0, ge=0, description="True Negatives (Benign correctly allowed)")
    fn: int = Field(default=0, ge=0, description="False Negatives (Threat missed / allowed)")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> int:
        """Total evaluated scenarios."""
        return self.tp + self.fp + self.tn + self.fn

    @computed_field  # type: ignore[prop-decorator]
    @property
    def precision(self) -> float:
        """Proportion of flagged items that were genuine threats."""
        denom = self.tp + self.fp
        return round(self.tp / denom, 4) if denom > 0 else 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recall(self) -> float:
        """Proportion of actual threats correctly flagged (Detection Rate)."""
        denom = self.tp + self.fn
        return round(self.tp / denom, 4) if denom > 0 else 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p = self.precision
        r = self.recall
        denom = p + r
        return round(2 * (p * r) / denom, 4) if denom > 0 else 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def false_positive_rate(self) -> float:
        """Proportion of benign items incorrectly flagged (FP / (FP + TN))."""
        denom = self.fp + self.tn
        return round(self.fp / denom, 4) if denom > 0 else 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def false_negative_rate(self) -> float:
        """Proportion of threats missed (FN / (FN + TP))."""
        denom = self.fn + self.tp
        return round(self.fn / denom, 4) if denom > 0 else 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def accuracy(self) -> float:
        """Overall classification accuracy ((TP + TN) / Total)."""
        denom = self.total
        return round((self.tp + self.tn) / denom, 4) if denom > 0 else 0.0


class OperationalMetrics(BaseModel):
    """Operational latency, efficiency, and resource impact metrics."""

    model_config = ConfigDict(extra="forbid")

    total_duration_ms: float = Field(default=0.0, ge=0.0)
    mean_latency_ms: float = Field(default=0.0, ge=0.0)
    p95_latency_ms: float = Field(default=0.0, ge=0.0)
    max_latency_ms: float = Field(default=0.0, ge=0.0)
    error_count: int = Field(default=0, ge=0)
    timeout_count: int = Field(default=0, ge=0)


class ImprovementMetrics(BaseModel):
    """Deltas and progress tracking relative to baseline detector."""

    model_config = ConfigDict(extra="forbid")

    original_failures_resolved: int = Field(default=0, ge=0)
    original_failures_total: int = Field(default=0, ge=0)
    resolution_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    new_regressions: int = Field(default=0, ge=0)
    new_false_positives: int = Field(default=0, ge=0)
    delta_f1: float = Field(default=0.0)
    delta_recall: float = Field(default=0.0)
    delta_fpr: float = Field(default=0.0)
    family_breakdown: dict[str, dict[str, Any]] = Field(default_factory=dict)


class BenchmarkScenarioItem(BaseModel):
    """Individual scenario record within a verified benchmark manifest."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: UUID = Field(default_factory=uuid4)
    url: str = Field(min_length=1)
    expected_class: ExpectedClass
    expected_decision: Decision
    scenario_family: str
    split: DatasetSplitType
    group_id: str = Field(
        description="Lineage or domain grouping preventing trivial copies across splits"
    )
    difficulty: str = Field(default="intermediate")
    tags: list[str] = Field(default_factory=list)


class BenchmarkManifest(BaseModel):
    """Manifest describing a standardized, leakage-resistant benchmark dataset."""

    model_config = ConfigDict(extra="forbid")

    manifest_id: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=2, max_length=128)
    version: str = Field(min_length=1, max_length=32)
    description: str = Field(min_length=5, max_length=1024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    split_counts: dict[str, int] = Field(default_factory=dict)
    family_counts: dict[str, int] = Field(default_factory=dict)
    scenario_count: int = Field(default=0, ge=0)
    scenarios: list[BenchmarkScenarioItem] = Field(default_factory=list)
    integrity_hash: str = Field(default="", description="SHA-256 of canonical scenarios payload")


class AcceptancePolicyConfig(BaseModel):
    """Configurable acceptance criteria rules for candidate defense approval."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(default="default-acceptance-v1")
    name: str = Field(default="Standard Defensive Acceptance Policy")
    version: str = Field(default="1.0.0")
    max_allowed_fpr: float = Field(default=0.05, ge=0.0, le=1.0)
    max_allowed_regressions: int = Field(default=0, ge=0)
    min_failures_resolved: int = Field(default=1, ge=0)
    min_held_out_f1: float = Field(default=0.70, ge=0.0, le=1.0)
    min_detection_rate: float = Field(default=0.60, ge=0.0, le=1.0)
    max_latency_overhead_ms: float = Field(default=25.0, ge=0.0)
    max_error_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    require_digest_verification: bool = Field(default=True)
    require_allowlist_validation: bool = Field(default=True)


class EvaluationRequest(BaseModel):
    """Formal audit request submitted to the Independent Evaluation Engine."""

    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID = Field(..., description="CandidateDefense reference")
    candidate_version: str = Field(min_length=1)
    baseline_detector_version: str = Field(default="0.2.0-heuristic-intel")
    baseline_policy_version: str = Field(default="2026.10.1")
    benchmark_manifest_version: str = Field(default="benchmark-golden-v1")
    protocol_version: str = Field(default="1.0.0")
    acceptance_policy: AcceptancePolicyConfig = Field(default_factory=AcceptancePolicyConfig)
    target_finding_ids: list[UUID] = Field(default_factory=list)
    target_scenario_ids: list[UUID] = Field(default_factory=list)
    resource_budget_seconds: float = Field(default=60.0, ge=1.0)
    requested_by: str = Field(default="SelfImprovementController")
    status: EvaluationStatus = Field(default=EvaluationStatus.QUEUED)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvaluationReport(BaseModel):
    """Full independent audit report detailing candidate defense performance."""

    model_config = ConfigDict(extra="forbid")

    report_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    candidate_id: UUID
    candidate_version: str
    baseline_version: str
    benchmark_manifest_version: str
    verdict: EvaluationVerdict
    status: EvaluationStatus = Field(default=EvaluationStatus.COMPLETED)
    verdict_rationale: str
    acceptance_reasons: list[str] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)
    baseline_metrics: ConfusionMatrix
    candidate_metrics: ConfusionMatrix
    split_metrics: dict[str, ConfusionMatrix] = Field(default_factory=dict)
    improvement_metrics: ImprovementMetrics = Field(default_factory=ImprovementMetrics)
    operational_metrics: OperationalMetrics = Field(default_factory=OperationalMetrics)
    report_digest: str = Field(default="", description="Cryptographic SHA-256 of audit metrics")
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvaluationResult(BaseModel):
    """Backward-compatible audit summary record for candidate defense efficacy."""

    model_config = ConfigDict(extra="forbid")

    evaluation_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this evaluation verdict",
    )
    candidate_defense_id: UUID = Field(
        ...,
        description="Reference to the candidate defense under benchmark testing",
    )
    scenario_suite_id: Annotated[
        str,
        Field(
            min_length=2, max_length=64, description="Identifier of the scenario test suite used"
        ),
    ]
    total_scenarios: Annotated[
        int,
        Field(ge=1, description="Total number of scenarios in the benchmark suite"),
    ]
    passed_scenarios: Annotated[
        int,
        Field(ge=0, description="Number of scenarios correctly categorized"),
    ]
    detection_rate: Annotated[
        float,
        Field(ge=0.0, le=1.0, description="Proportion of true malicious threats detected (Recall)"),
    ]
    false_positive_rate: Annotated[
        float,
        Field(ge=0.0, le=1.0, description="Proportion of benign items erroneously flagged"),
    ]
    regression_count: Annotated[
        int,
        Field(ge=0, description="Known benign benchmarks broken by this candidate"),
    ] = 0
    resource_overhead_ms: Annotated[
        float,
        Field(ge=0.0, description="Average evaluation latency impact per inspection"),
    ] = 0.0
    verdict: EvaluationVerdict = Field(
        ...,
        description="Independent verdict: pass, fail, or inconclusive",
    )
    verdict_rationale: Annotated[
        str,
        Field(
            min_length=5,
            max_length=2048,
            description="Justification for promotion or rejection of candidate defense",
        ),
    ]
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )


class CycleCheckpoint(BaseModel):
    """Step checkpoint in an autonomous self-improvement cycle."""

    model_config = ConfigDict(extra="forbid")

    checkpoint_id: UUID = Field(default_factory=uuid4)
    cycle_id: UUID
    step_number: int = Field(ge=1, le=10)
    step_name: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ImprovementCycleConfig(BaseModel):
    """Configuration and guardrail parameters for an autonomous improvement cycle."""

    model_config = ConfigDict(extra="forbid")

    cycle_id: UUID = Field(default_factory=uuid4)
    max_candidates_per_cycle: int = Field(default=5, ge=1, le=20)
    max_evaluations: int = Field(default=10, ge=1, le=50)
    max_scenarios_per_eval: int = Field(default=100, ge=10, le=1000)
    cycle_timeout_seconds: float = Field(default=120.0, ge=10.0, le=600.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    benchmark_manifest_version: str = Field(default="benchmark-golden-v1")
    acceptance_policy: AcceptancePolicyConfig = Field(default_factory=AcceptancePolicyConfig)
    target_failure_categories: list[str] = Field(default_factory=list)


class ImprovementCycleSummary(BaseModel):
    """Summary of execution and outcomes of an autonomous self-improvement cycle."""

    model_config = ConfigDict(extra="forbid")

    cycle_id: UUID
    cycle_number: int = Field(default=1, ge=1)
    status: CycleStatus = Field(default=CycleStatus.CREATED)
    trigger_reason: str = Field(default="scheduled_research")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float = Field(default=0.0, ge=0.0)
    findings_selected: int = Field(default=0, ge=0)
    hypotheses_formulated: int = Field(default=0, ge=0)
    candidates_generated: int = Field(default=0, ge=0)
    candidates_evaluated: int = Field(default=0, ge=0)
    accepted_candidate_id: UUID | None = None
    accepted_candidate_version: str | None = None
    terminal_reason: str = Field(default="")
    budget_used_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    checkpoints: list[CycleCheckpoint] = Field(default_factory=list)


class ImprovementTrendReport(BaseModel):
    """Longitudinal metrics tracking progress across self-improvement cycles."""

    model_config = ConfigDict(extra="forbid")

    total_cycles: int = Field(default=0, ge=0)
    successful_cycles: int = Field(default=0, ge=0)
    total_candidates_evaluated: int = Field(default=0, ge=0)
    total_candidates_accepted: int = Field(default=0, ge=0)
    cumulative_failures_resolved: int = Field(default=0, ge=0)
    mean_cycle_duration_seconds: float = Field(default=0.0, ge=0.0)
    cycle_history: list[ImprovementCycleSummary] = Field(default_factory=list)
