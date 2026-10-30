"""Schemas for laboratory threat scenarios, synthetic attacks, and agent run metrics."""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from cyberduel_contracts.enums import AgentRole, Decision, ScenarioStatus


class LaboratoryScenario(BaseModel):
    """Synthetic, controlled security challenge created for evaluation inside the research lab."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the synthetic scenario",
    )
    title: Annotated[
        str,
        Field(min_length=3, max_length=128, description="Descriptive scenario name"),
    ]
    scenario_type: Annotated[
        str,
        Field(
            min_length=3,
            max_length=64,
            description="Category: e.g. homograph_attack, prompt_injection, deceptive_subdomain",
        ),
    ]
    synthetic_payload: dict[str, Any] = Field(
        ...,
        description="Controlled, harmless synthetic payload parameters (no live exploits)",
    )
    expected_decision: Decision = Field(
        ...,
        description="The ground-truth decision a flawless defense should produce",
    )
    difficulty: Literal["basic", "intermediate", "advanced", "adversarial"] = "intermediate"
    created_by_agent: Annotated[
        str,
        Field(min_length=2, max_length=64, description="Agent identity, e.g. 'RedAI-v1'"),
    ]
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of scenario formulation",
    )


class AgentRunSummary(BaseModel):
    """Outcome and metric summary of an adversarial scenario trial."""

    model_config = ConfigDict(extra="forbid")

    run_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this scenario run",
    )
    scenario_id: UUID = Field(
        ...,
        description="Reference to the executed laboratory scenario",
    )
    agent_role: AgentRole = Field(
        ...,
        description="Role of the participating agent: red_ai, blue_ai, or evaluator",
    )
    agent_version: Annotated[
        str,
        Field(min_length=1, max_length=32, description="Version string of the executing agent"),
    ]
    status: ScenarioStatus = Field(
        default=ScenarioStatus.PENDING,
        description="Operational status of the scenario run",
    )
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    end_time: datetime | None = None
    metrics: dict[str, float] = Field(
        default_factory=dict,
        description="Performance indicators (e.g. latency_ms, evasion_rate, confidence)",
    )
    findings_summary: Annotated[
        str,
        Field(
            default="",
            max_length=2048,
            description="Concise summary of weaknesses discovered or defenses verified",
        ),
    ]


class TransformationRecord(BaseModel):
    """Immutable audit record of a safe mutation applied to a parent scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operator: Annotated[str, Field(min_length=2, max_length=64)]
    parameters: dict[str, Any] = Field(default_factory=dict)
    preserved_semantics: bool = True
    relabel_required: bool = False
    applied_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScenarioContract(BaseModel):
    """Canonical typed contract for a laboratory threat scenario or benign control."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: UUID = Field(default_factory=uuid4)
    schema_version: Annotated[str, Field(max_length=16)] = "1.0.0"
    scenario_family: str = Field(
        description="Scenario family classification e.g. homograph_mimicry, benign_lookalike"
    )
    scenario_name: Annotated[str, Field(min_length=3, max_length=128)]
    description: Annotated[str, Field(max_length=512)]
    expected_class: str = Field(
        description="Ground truth expectation: benign, malicious, suspicious, or uncertain"
    )
    expected_decision: Decision = Field(
        description="Expected defensive decision under active baseline policy"
    )
    difficulty: Literal["basic", "intermediate", "advanced", "adversarial"] = "intermediate"
    tags: list[str] = Field(default_factory=list)
    seed: int = 42
    generator_version: Annotated[str, Field(default="red-generator-1.0.0", max_length=32)]
    mutation_parent_id: UUID | None = None
    transformation_history: list[dict[str, Any]] = Field(default_factory=list)
    input_fixture: dict[str, Any] = Field(
        ...,
        description="Input parameters including raw_url, headers, and protocol parameters",
    )
    expected_evidence: list[str] = Field(
        default_factory=list,
        description="Expected indicator/heuristic categories e.g. ['homoglyph', 'authority_spoof']",
    )
    provenance: dict[str, Any] = Field(
        default_factory=dict,
        description="Origin metadata, rationale, and synthetic generation lineage",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    safety_classification: Literal["harmless_synthetic"] = "harmless_synthetic"


class ScenarioGenerationRequest(BaseModel):
    """Request payload to generate a synthetic scenario corpus."""

    model_config = ConfigDict(extra="forbid")

    goal: Annotated[str, Field(default="general_exploration", min_length=2, max_length=128)]
    count: Annotated[int, Field(default=100, ge=1, le=1000)]
    families: list[str] | None = None
    mutation_depth: Annotated[int, Field(default=1, ge=0, le=5)]
    seed: int = 42
    generator_version: str = "red-generator-1.0.0"


class ExperimentConfig(BaseModel):
    """Specification for an adversarial evaluation experiment run."""

    model_config = ConfigDict(extra="forbid")

    experiment_name: Annotated[str, Field(min_length=3, max_length=128)]
    goal: Annotated[str, Field(min_length=2, max_length=256)]
    scenario_count: Annotated[int, Field(default=100, ge=1, le=1000)]
    seed: int = 42
    selected_families: list[str] = Field(default_factory=list)
    mutation_depth: Annotated[int, Field(default=1, ge=0, le=5)]
    fail_on_first_error: bool = False
    timeout_seconds: Annotated[int, Field(default=300, ge=10, le=1800)]
    created_by: str = "RedAI-Agent"


class ScenarioExecutionResult(BaseModel):
    """Observation recorded when testing a single scenario against the defensive engine."""

    model_config = ConfigDict(extra="forbid")

    execution_id: UUID = Field(default_factory=uuid4)
    experiment_id: UUID
    scenario_id: UUID
    scenario_name: str
    scenario_family: str
    raw_url: str
    expected_class: str
    expected_decision: Decision
    actual_decision: Decision
    actual_threat_score: float
    actual_evidence: list[dict[str, Any]] = Field(default_factory=list)
    detector_version: str
    policy_version: str
    is_discrepancy: bool
    discrepancy_type: str
    duration_ms: float = 0.0
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FailureFinding(BaseModel):
    """Structured analytical hypothesis regarding a cluster of detection discrepancies."""

    model_config = ConfigDict(extra="forbid")

    finding_id: UUID = Field(default_factory=uuid4)
    experiment_id: UUID
    failure_category: str
    discrepancy_type: str
    hypothesis: Annotated[str, Field(max_length=1024)]
    affected_scenarios_count: int
    representative_scenario_ids: list[UUID] = Field(default_factory=list)
    suggested_remedy: Annotated[str, Field(default="", max_length=1024)]
    severity: Literal["low", "medium", "high", "critical"] = "medium"


class ExperimentRunSummary(BaseModel):
    """Comprehensive report summarizing an executed research laboratory experiment."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: UUID
    experiment_name: str
    goal: str
    status: str
    seed: int
    scenario_count: int
    executed_count: int
    discrepancy_count: int
    metrics: dict[str, Any] = Field(default_factory=dict)
    family_breakdown: dict[str, dict[str, Any]] = Field(default_factory=dict)
    detector_version: str
    policy_version: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings: list[FailureFinding] = Field(default_factory=list)


class EvaluationHandoffPackage(BaseModel):
    """Versioned package transmitted to the Independent Evaluator and future Blue AI."""

    model_config = ConfigDict(extra="forbid")

    handoff_id: UUID = Field(default_factory=uuid4)
    experiment_id: UUID
    candidate_id: UUID = Field(default_factory=uuid4)
    detector_version: str
    policy_version: str
    total_failures: int
    findings: list[FailureFinding] = Field(default_factory=list)
    representative_scenarios: list[ScenarioContract] = Field(default_factory=list)
    ground_truth_confidence: float = 0.95
    reproduction_config: dict[str, Any] = Field(default_factory=dict)
    suggested_investigation_questions: list[str] = Field(default_factory=list)
    status: Literal["handed_off", "acknowledged", "in_investigation", "resolved"] = "handed_off"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LabStatusResponse(BaseModel):
    """Operational status and capabilities discovery for the research laboratory."""

    model_config = ConfigDict(extra="forbid")

    status: str
    active_experiments: int
    completed_experiments: int
    total_scenarios_cataloged: int
    sandboxed: bool = True
    external_network_blocked: bool = True
    worker_version: str
    supported_families: list[str] = Field(default_factory=list)


class LabMetricsResponse(BaseModel):
    """Aggregated detection and failure metrics across laboratory experiments."""

    model_config = ConfigDict(extra="forbid")

    total_scenarios_generated: int
    total_scenarios_executed: int
    total_experiments_run: int
    overall_accuracy: float
    overall_tpr: float
    overall_fpr: float
    decision_distribution: dict[str, int] = Field(default_factory=dict)
    discrepancy_distribution: dict[str, int] = Field(default_factory=dict)
    failure_category_distribution: dict[str, int] = Field(default_factory=dict)
