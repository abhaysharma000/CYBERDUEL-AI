"""Domain models for laboratory scenario executions, simulations, and benchmark evaluations."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from apps.api.app.models.policies import CandidateDefenseRecord


class LaboratoryScenarioRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Execution log of a synthetic threat scenario run within the isolated research laboratory."""

    __tablename__ = "lab_scenario_runs"

    title: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    scenario_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    synthetic_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        doc="Harmless synthetic payload specs (never live exploits)",
    )
    expected_decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    difficulty: Mapped[str] = mapped_column(
        String(32),
        default="intermediate",
        nullable=False,
    )
    created_by_agent: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Agent identity (e.g. RedAI-v1)",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
        index=True,
    )
    execution_metrics: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    findings_summary: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class EvaluationRunRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Benchmark evaluation of a candidate defense version against regression suites."""

    __tablename__ = "evaluation_runs"

    candidate_defense_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scenario_suite_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    total_scenarios: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    passed_scenarios: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    detection_rate: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    false_positive_rate: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    regression_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    resource_overhead_ms: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="pass, fail, or inconclusive",
    )
    verdict_rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    candidate_defense: Mapped["CandidateDefenseRecord"] = relationship(  # type: ignore[name-defined]
        back_populates="evaluations",
        lazy="selectin",
    )

    __table_args__ = (Index("ix_eval_runs_suite_verdict", "scenario_suite_id", "verdict"),)


class LabExperimentRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Persistent tracking of a Red AI adversarial experiment run."""

    __tablename__ = "lab_experiments"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    goal: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False, index=True)
    seed: Mapped[int] = mapped_column(Integer, default=42, nullable=False)
    scenario_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    discrepancy_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    summary_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    detector_version: Mapped[str] = mapped_column(
        String(64), default="0.2.0-heuristic-intel", nullable=False
    )
    policy_version: Mapped[str] = mapped_column(String(64), default="2026.10.1", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    scenarios: Mapped[list["ScenarioRecord"]] = relationship(
        back_populates="experiment",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    executions: Mapped[list["ScenarioExecutionRecord"]] = relationship(
        back_populates="experiment",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["FailureFindingRecord"]] = relationship(
        back_populates="experiment",
        lazy="selectin",
        cascade="all, delete-orphan",
    )


class ScenarioRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Canonical persistent threat scenario definition or benign control."""

    __tablename__ = "scenarios"

    experiment_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("lab_experiments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scenario_family: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scenario_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    expected_class: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    expected_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(32), default="intermediate", nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    seed: Mapped[int] = mapped_column(Integer, default=42, nullable=False)
    generator_version: Mapped[str] = mapped_column(
        String(64), default="red-generator-1.0.0", nullable=False
    )
    mutation_parent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    transformation_history: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    input_fixture: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expected_evidence: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    safety_classification: Mapped[str] = mapped_column(
        String(32), default="harmless_synthetic", nullable=False
    )

    experiment: Mapped[LabExperimentRecord | None] = relationship(
        back_populates="scenarios",
        lazy="selectin",
    )
    executions: Mapped[list["ScenarioExecutionRecord"]] = relationship(
        back_populates="scenario",
        lazy="selectin",
        cascade="all, delete-orphan",
    )


class ScenarioExecutionRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Individual execution result of a scenario run against the defensive engine."""

    __tablename__ = "scenario_executions"

    experiment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("lab_experiments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scenario_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scenarios.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_url: Mapped[str] = mapped_column(Text, nullable=False)
    expected_class: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    actual_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    actual_threat_score: Mapped[float] = mapped_column(Float, nullable=False)
    actual_evidence: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    detector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    is_discrepancy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    discrepancy_type: Mapped[str] = mapped_column(
        String(64), default="none", nullable=False, index=True
    )
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    experiment: Mapped[LabExperimentRecord] = relationship(
        back_populates="executions",
        lazy="selectin",
    )
    scenario: Mapped[ScenarioRecord] = relationship(
        back_populates="executions",
        lazy="selectin",
    )


class FailureFindingRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Structured analytical finding generated from a cluster of experiment discrepancies."""

    __tablename__ = "failure_findings"

    experiment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("lab_experiments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    failure_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    discrepancy_type: Mapped[str] = mapped_column(String(64), nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    affected_scenarios_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    representative_scenario_ids: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    suggested_remedy: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)

    experiment: Mapped[LabExperimentRecord] = relationship(
        back_populates="findings",
        lazy="selectin",
    )
