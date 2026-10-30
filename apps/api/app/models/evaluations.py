"""Domain models for independent evaluation engine and autonomous self-improvement cycles."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class EvaluationProtocolRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Formal audit protocol specification governing candidate defense verification."""

    __tablename__ = "evaluation_protocols"

    protocol_name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metrics_required: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    split_spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    pass_fail_thresholds: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class BenchmarkManifestRecord(Base, TimestampMixin):
    """Standardized benchmark manifest defining test scenarios and split distributions."""

    __tablename__ = "benchmark_manifests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    split_counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    family_counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    scenario_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scenarios_payload: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    requests: Mapped[list["EvaluationRequestRecord"]] = relationship(
        back_populates="benchmark_manifest",
        lazy="selectin",
    )


class AcceptancePolicyRecord(Base, TimestampMixin):
    """Configurable acceptance gates for candidate defense promotion."""

    __tablename__ = "acceptance_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    criteria_spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class EvaluationRequestRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Audit request queued for or completed by the Independent Evaluation Engine."""

    __tablename__ = "evaluation_requests"

    candidate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_version: Mapped[str] = mapped_column(String(32), nullable=False)
    baseline_detector_version: Mapped[str] = mapped_column(
        String(64), default="0.2.0-heuristic-intel", nullable=False
    )
    baseline_policy_version: Mapped[str] = mapped_column(
        String(64), default="2026.10.1", nullable=False
    )
    benchmark_manifest_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("benchmark_manifests.id"),
        nullable=False,
        index=True,
    )
    acceptance_policy_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("acceptance_policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(
        String(64), default="SelfImprovementController", nullable=False
    )
    resource_budget: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    target_finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    target_scenario_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    benchmark_manifest: Mapped[BenchmarkManifestRecord] = relationship(
        back_populates="requests",
        lazy="selectin",
    )
    report: Mapped["EvaluationReportRecord | None"] = relationship(
        back_populates="request",
        lazy="selectin",
        uselist=False,
        cascade="all, delete-orphan",
    )


class EvaluationReportRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Comprehensive independent audit report verifying candidate performance against benchmarks."""

    __tablename__ = "evaluation_reports"

    request_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evaluation_requests.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_version: Mapped[str] = mapped_column(String(32), nullable=False)
    baseline_version: Mapped[str] = mapped_column(String(64), nullable=False)
    benchmark_manifest_id: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    verdict_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    acceptance_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    rejection_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    baseline_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    candidate_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    split_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    improvement_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    operational_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    request: Mapped[EvaluationRequestRecord] = relationship(
        back_populates="report",
        lazy="selectin",
    )


class ImprovementCycleRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Execution tracking of an autonomous, bounded self-improvement loop cycle."""

    __tablename__ = "improvement_cycles"

    cycle_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False, index=True)
    trigger_reason: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    selected_findings: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    candidates_evaluated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    accepted_candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="SET NULL"),
        nullable=True,
    )
    accepted_candidate_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    terminal_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    checkpoints: Mapped[list["CycleCheckpointRecord"]] = relationship(
        back_populates="cycle",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CycleCheckpointRecord.step_number",
    )
    feedbacks: Mapped[list["CycleFeedbackRecord"]] = relationship(
        back_populates="cycle",
        lazy="selectin",
        cascade="all, delete-orphan",
    )


class CycleCheckpointRecord(Base, UUIDPrimaryKeyMixin):
    """Step-by-step checkpoint record within an autonomous improvement cycle."""

    __tablename__ = "cycle_checkpoints"

    cycle_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("improvement_cycles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    step_name: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    cycle: Mapped[ImprovementCycleRecord] = relationship(
        back_populates="checkpoints",
        lazy="selectin",
    )

    __table_args__ = (Index("ix_cycle_step", "cycle_id", "step_number"),)


class CycleFeedbackRecord(Base, UUIDPrimaryKeyMixin):
    """Structured learning feedback tying audit findings back to future cycles."""

    __tablename__ = "cycle_feedbacks"

    cycle_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("improvement_cycles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    feedback_type: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    lessons_learned: Mapped[str] = mapped_column(Text, nullable=False)
    feature_weights: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    cycle: Mapped[ImprovementCycleRecord] = relationship(
        back_populates="feedbacks",
        lazy="selectin",
    )
