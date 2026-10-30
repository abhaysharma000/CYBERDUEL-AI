"""Schemas for candidate defenses, policy releases, and cryptographic distribution manifests."""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from cyberduel_contracts.enums import (
    Decision,
    DefenseStatus,
    EvaluationVerdict,
    HypothesisStatus,
    ProposalType,
    ReleaseStatus,
    ThreatSeverity,
)


class CandidateDefense(BaseModel):
    """A proposed set of detection rules, weights, or signatures formulated by Blue AI."""

    model_config = ConfigDict(extra="forbid")

    defense_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this candidate defense proposal",
    )
    version: Annotated[
        str,
        Field(
            min_length=3,
            max_length=32,
            description="Semantic version string, e.g. '0.2.1-candidate'",
        ),
    ]
    author_agent: Annotated[
        str,
        Field(
            min_length=2,
            max_length=64,
            description="Identifier of proposing agent, e.g. 'BlueAI-v1'",
        ),
    ]
    description: Annotated[
        str,
        Field(
            min_length=5,
            max_length=1024,
            description="Detailed hypothesis and summary of defense changes",
        ),
    ]
    rule_spec: dict[str, Any] = Field(
        ...,
        description="Declarative rule specifications (regex, heuristics, thresholds, indicators)",
    )
    status: DefenseStatus = Field(
        default=DefenseStatus.CANDIDATE,
        description="Current lifecycle status of the candidate defense",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )


class PolicyReleaseManifest(BaseModel):
    """Cryptographically signed release package distributed to production edge clients."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    release_id: UUID = Field(
        default_factory=uuid4,
        description="Unique publication ID for this release",
    )
    policy_version: Annotated[
        str,
        Field(
            min_length=3, max_length=32, description="Canonical published version, e.g. '2026.10.1'"
        ),
    ]
    min_client_version: Annotated[
        str,
        Field(
            min_length=3,
            max_length=32,
            description="Minimum edge client version compatible with this policy",
        ),
    ]
    rules_digest: Annotated[
        str,
        Field(
            min_length=64,
            max_length=64,
            pattern=r"^[a-fA-F0-9]{64}$",
            description="SHA-256 hash of the compiled declarative policy payload",
        ),
    ]
    publisher_key_id: Annotated[
        str,
        Field(
            min_length=4,
            max_length=64,
            description="Key ID of the authorized release-signing authority",
        ),
    ]
    signature: Annotated[
        str,
        Field(
            min_length=16,
            max_length=1024,
            description="Cryptographic signature over the release payload and digest",
        ),
    ]
    published_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    expires_at: datetime = Field(
        ...,
        description="Timestamp after which clients must consider this release stale",
    )
    status: ReleaseStatus = Field(
        default=ReleaseStatus.PUBLISHED,
        description="Lifecycle status of this release (staged, published, or revoked)",
    )
    rules_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Declarative rules, compiled bloom filters, or regex sets (no executable code)",
    )


class RulePredicateModel(BaseModel):
    """Atomic evaluable predicate on an allowlisted URL or threat feature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: Annotated[str, Field(min_length=2, max_length=64)]
    operator: Literal["eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "matches_regex"]
    value: Any


class DeclarativeRuleModel(BaseModel):
    """Schema for a declarative defensive rule formulated by Blue AI."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: Annotated[str, Field(min_length=3, max_length=64)]
    rule_version: Annotated[str, Field(max_length=32)] = "1.0.0"
    description: Annotated[str, Field(max_length=512)]
    author: Annotated[str, Field(max_length=64)] = "BlueAI-DefenseEngine"
    purpose: Annotated[str, Field(max_length=256)]
    target_family: Annotated[str, Field(max_length=64)]
    feature_names: list[str] = Field(default_factory=list)
    predicates: list[RulePredicateModel] = Field(..., min_length=1, max_length=10)
    logical_operator: Literal["AND", "OR"] = "AND"
    action: Decision = Decision.WARN
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    weight: Annotated[float, Field(ge=0.0, le=1.0)] = 0.70
    false_positive_risk: Literal["low", "medium", "high"] = "low"
    source_hypothesis_id: UUID | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DefensiveHypothesis(BaseModel):
    """Structured hypothesis explaining a detection gap and proposing corrective action."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: UUID = Field(default_factory=uuid4)
    research_task_id: UUID
    failure_category: str
    target_family: str
    observed_behavior: Annotated[str, Field(max_length=512)]
    expected_behavior: Annotated[str, Field(max_length=512)]
    possible_explanation: Annotated[str, Field(max_length=1024)]
    supporting_evidence: list[dict[str, Any]] = Field(default_factory=list)
    counterexamples: list[dict[str, Any]] = Field(default_factory=list)
    proposed_intervention: dict[str, Any] = Field(default_factory=dict)
    predicted_benefit: Annotated[str, Field(max_length=512)]
    potential_risks: Annotated[str, Field(max_length=512)]
    test_plan: Annotated[str, Field(max_length=512)]
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.85
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DefenseProposal(BaseModel):
    """Concrete candidate change package generated by Blue AI."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID
    proposal_type: ProposalType
    title: Annotated[str, Field(min_length=3, max_length=128)]
    rationale: Annotated[str, Field(max_length=1024)]
    declarative_rule: DeclarativeRuleModel | None = None
    tuning_spec: dict[str, Any] | None = None
    status: Literal["draft", "built", "evaluated", "rejected"] = "draft"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BaselineComparisonReport(BaseModel):
    """Detailed comparison between baseline and candidate detector performance."""

    model_config = ConfigDict(extra="forbid")

    comparison_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    candidate_version: str
    baseline_version: str
    total_scenarios_evaluated: int
    baseline_accuracy: float
    candidate_accuracy: float
    baseline_recall: float
    candidate_recall: float
    baseline_fpr: float
    candidate_fpr: float
    baseline_f1: float
    candidate_f1: float
    original_failures_resolved: int
    new_regressions: int
    new_false_positives: int
    family_breakdown: dict[str, dict[str, Any]] = Field(default_factory=dict)
    trade_off_analysis: str
    preliminary_verdict: Literal["promoted_for_evaluation", "rejected_regressive", "inconclusive"]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CandidateFeedback(BaseModel):
    """Outcome feedback received from independent evaluation."""

    model_config = ConfigDict(extra="forbid")

    feedback_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    evaluator_verdict: EvaluationVerdict
    evaluator_rationale: str
    detection_rate: float
    false_positive_rate: float
    regression_count: int
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BlueStatusResponse(BaseModel):
    """Operational status and research capabilities of Blue AI."""

    model_config = ConfigDict(extra="forbid")

    status: str
    active_research_tasks: int
    total_candidates_built: int
    accepted_candidates: int
    rejected_candidates: int
    candidate_acceptance_rate: float
    available_proposal_types: list[str] = Field(default_factory=list)
