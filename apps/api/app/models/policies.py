"""Domain models for defensive candidate policies and cryptographically signed releases."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
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
    from apps.api.app.models.devices import UpdateDeliveryRecord
    from apps.api.app.models.lab import EvaluationRunRecord


class CandidateDefenseRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Candidate defensive rules and heuristics formulated by Blue AI."""

    __tablename__ = "candidate_defenses"

    version: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        index=True,
    )
    author_agent: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Identifier of generating agent, e.g. BlueAI-v1",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    rule_spec: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        doc="Declarative detection rules and signatures (no executable code)",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="candidate",
        nullable=False,
        index=True,
        doc="candidate, evaluating, approved, rejected, deprecated",
    )

    evaluations: Mapped[list["EvaluationRunRecord"]] = relationship(  # type: ignore[name-defined]
        back_populates="candidate_defense",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    comparisons: Mapped[list["SandboxComparisonRecord"]] = relationship(
        back_populates="candidate_defense",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    feedbacks: Mapped[list["CandidateFeedbackRecord"]] = relationship(
        back_populates="candidate_defense",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class PolicyReleaseRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Approved, signed defensive policy package authorized for edge distribution."""

    __tablename__ = "policy_releases"

    policy_version: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        index=True,
    )
    min_client_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    rules_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="SHA-256 hash of compiled rule specification",
    )
    publisher_key_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    signature: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Detached cryptographic signature verifying origin and tamper-resistance",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="published",
        nullable=False,
        index=True,
        doc="staged, published, or revoked",
    )
    rules_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    deliveries: Mapped[list["UpdateDeliveryRecord"]] = relationship(  # type: ignore[name-defined]
        back_populates="policy_release",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (Index("ix_policy_releases_ver_status", "policy_version", "status"),)


class ResearchTaskRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Investigation task instantiated by Blue AI to analyze Red AI failures or telemetry."""

    __tablename__ = "research_tasks"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    experiment_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True, index=True
    )
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    hypotheses: Mapped[list["DefenseHypothesisRecord"]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class DefenseHypothesisRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Structured hypothesis explaining a detection gap and proposing defensive intervention."""

    __tablename__ = "defense_hypotheses"

    research_task_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("research_tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    failure_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_family: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hypothesis_text: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="proposed", nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.85, nullable=False)
    evidence_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    intervention_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    task: Mapped[ResearchTaskRecord] = relationship(
        back_populates="hypotheses",
        lazy="selectin",
    )
    proposals: Mapped[list["DefenseProposalRecord"]] = relationship(
        back_populates="hypothesis",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class DefenseProposalRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Concrete candidate defensive change generated from a hypothesis."""

    __tablename__ = "defense_proposals"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("defense_hypotheses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    proposal_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False, index=True)

    hypothesis: Mapped[DefenseHypothesisRecord] = relationship(
        back_populates="proposals",
        lazy="selectin",
    )


class SandboxComparisonRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Side-by-side performance audit record of a candidate defense versus the baseline."""

    __tablename__ = "sandbox_comparisons"

    candidate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_version: Mapped[str] = mapped_column(String(32), nullable=False)
    baseline_version: Mapped[str] = mapped_column(String(32), nullable=False)
    total_scenarios: Mapped[int] = mapped_column(Integer, nullable=False)
    original_failures_resolved: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_regressions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_false_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    baseline_accuracy: Mapped[float] = mapped_column(Float, nullable=False)
    candidate_accuracy: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_recall: Mapped[float] = mapped_column(Float, nullable=False)
    candidate_recall: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_fpr: Mapped[float] = mapped_column(Float, nullable=False)
    candidate_fpr: Mapped[float] = mapped_column(Float, nullable=False)
    preliminary_verdict: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    report_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    candidate_defense: Mapped[CandidateDefenseRecord] = relationship(
        back_populates="comparisons",
        lazy="selectin",
    )


class CandidateFeedbackRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Historical feedback received from independent evaluator audit."""

    __tablename__ = "candidate_feedbacks"

    candidate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evaluator_verdict: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    evaluator_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    detection_rate: Mapped[float] = mapped_column(Float, nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(Float, nullable=False)
    regression_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    candidate_defense: Mapped[CandidateDefenseRecord] = relationship(
        back_populates="feedbacks",
        lazy="selectin",
    )
