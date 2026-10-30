"""Add research_tasks, defense_hypotheses, defense_proposals, sandbox_comparisons, and candidate_feedbacks tables.

Revision ID: 0004_blue_defense_engine
Revises: 0003_lab_experiments
Create Date: 2026-10-29 00:35:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_blue_defense_engine"
down_revision: str | None = "0003_lab_experiments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. research_tasks
    op.create_table(
        "research_tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("experiment_id", sa.Uuid(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_research_tasks_status", "research_tasks", ["status"])
    op.create_index("ix_research_tasks_experiment_id", "research_tasks", ["experiment_id"])

    # 2. defense_hypotheses
    op.create_table(
        "defense_hypotheses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("research_task_id", sa.Uuid(), nullable=False),
        sa.Column("failure_category", sa.String(length=64), nullable=False),
        sa.Column("target_family", sa.String(length=64), nullable=False),
        sa.Column("hypothesis_text", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_payload", sa.JSON(), nullable=False),
        sa.Column("intervention_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["research_task_id"], ["research_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_defense_hypotheses_research_task_id", "defense_hypotheses", ["research_task_id"]
    )
    op.create_index(
        "ix_defense_hypotheses_failure_category", "defense_hypotheses", ["failure_category"]
    )
    op.create_index("ix_defense_hypotheses_target_family", "defense_hypotheses", ["target_family"])
    op.create_index("ix_defense_hypotheses_status", "defense_hypotheses", ["status"])

    # 3. defense_proposals
    op.create_table(
        "defense_proposals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hypothesis_id", sa.Uuid(), nullable=False),
        sa.Column("proposal_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=128), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["defense_hypotheses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_defense_proposals_hypothesis_id", "defense_proposals", ["hypothesis_id"])
    op.create_index("ix_defense_proposals_proposal_type", "defense_proposals", ["proposal_type"])
    op.create_index("ix_defense_proposals_status", "defense_proposals", ["status"])

    # 4. sandbox_comparisons
    op.create_table(
        "sandbox_comparisons",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_version", sa.String(length=32), nullable=False),
        sa.Column("baseline_version", sa.String(length=32), nullable=False),
        sa.Column("total_scenarios", sa.Integer(), nullable=False),
        sa.Column("original_failures_resolved", sa.Integer(), nullable=False),
        sa.Column("new_regressions", sa.Integer(), nullable=False),
        sa.Column("new_false_positives", sa.Integer(), nullable=False),
        sa.Column("baseline_accuracy", sa.Float(), nullable=False),
        sa.Column("candidate_accuracy", sa.Float(), nullable=False),
        sa.Column("baseline_recall", sa.Float(), nullable=False),
        sa.Column("candidate_recall", sa.Float(), nullable=False),
        sa.Column("baseline_fpr", sa.Float(), nullable=False),
        sa.Column("candidate_fpr", sa.Float(), nullable=False),
        sa.Column("preliminary_verdict", sa.String(length=32), nullable=False),
        sa.Column("report_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate_defenses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sandbox_comparisons_candidate_id", "sandbox_comparisons", ["candidate_id"])
    op.create_index(
        "ix_sandbox_comparisons_preliminary_verdict", "sandbox_comparisons", ["preliminary_verdict"]
    )

    # 5. candidate_feedbacks
    op.create_table(
        "candidate_feedbacks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("evaluator_verdict", sa.String(length=32), nullable=False),
        sa.Column("evaluator_rationale", sa.Text(), nullable=False),
        sa.Column("detection_rate", sa.Float(), nullable=False),
        sa.Column("false_positive_rate", sa.Float(), nullable=False),
        sa.Column("regression_count", sa.Integer(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate_defenses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_candidate_feedbacks_candidate_id", "candidate_feedbacks", ["candidate_id"])
    op.create_index(
        "ix_candidate_feedbacks_evaluator_verdict", "candidate_feedbacks", ["evaluator_verdict"]
    )


def downgrade() -> None:
    op.drop_table("candidate_feedbacks")
    op.drop_table("sandbox_comparisons")
    op.drop_table("defense_proposals")
    op.drop_table("defense_hypotheses")
    op.drop_table("research_tasks")
