"""Add evaluation_protocols, benchmark_manifests, acceptance_policies, evaluation_requests, evaluation_reports, improvement_cycles, cycle_checkpoints, and cycle_feedbacks tables.

Revision ID: 0005_evaluation_controller
Revises: 0004_blue_defense_engine
Create Date: 2026-10-29 11:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_evaluation_controller"
down_revision: str | None = "0004_blue_defense_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. evaluation_protocols
    op.create_table(
        "evaluation_protocols",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("protocol_name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("metrics_required", sa.JSON(), nullable=False),
        sa.Column("split_spec", sa.JSON(), nullable=False),
        sa.Column("pass_fail_thresholds", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evaluation_protocols_version", "evaluation_protocols", ["version"])

    # 2. benchmark_manifests
    op.create_table(
        "benchmark_manifests",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("split_counts", sa.JSON(), nullable=False),
        sa.Column("family_counts", sa.JSON(), nullable=False),
        sa.Column("scenario_count", sa.Integer(), nullable=False),
        sa.Column("scenarios_payload", sa.JSON(), nullable=False),
        sa.Column("integrity_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_benchmark_manifests_version", "benchmark_manifests", ["version"])

    # 3. acceptance_policies
    op.create_table(
        "acceptance_policies",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("criteria_spec", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # 4. evaluation_requests
    op.create_table(
        "evaluation_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_version", sa.String(length=32), nullable=False),
        sa.Column("baseline_detector_version", sa.String(length=64), nullable=False),
        sa.Column("baseline_policy_version", sa.String(length=64), nullable=False),
        sa.Column("benchmark_manifest_id", sa.String(length=64), nullable=False),
        sa.Column("acceptance_policy_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("resource_budget", sa.JSON(), nullable=False),
        sa.Column("target_finding_ids", sa.JSON(), nullable=False),
        sa.Column("target_scenario_ids", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate_defenses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["benchmark_manifest_id"], ["benchmark_manifests.id"]),
        sa.ForeignKeyConstraint(
            ["acceptance_policy_id"], ["acceptance_policies.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evaluation_requests_candidate_id", "evaluation_requests", ["candidate_id"])
    op.create_index("ix_evaluation_requests_status", "evaluation_requests", ["status"])
    op.create_index(
        "ix_evaluation_requests_benchmark_manifest_id",
        "evaluation_requests",
        ["benchmark_manifest_id"],
    )

    # 5. evaluation_reports
    op.create_table(
        "evaluation_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_version", sa.String(length=32), nullable=False),
        sa.Column("baseline_version", sa.String(length=64), nullable=False),
        sa.Column("benchmark_manifest_id", sa.String(length=64), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("verdict_rationale", sa.Text(), nullable=False),
        sa.Column("acceptance_reasons", sa.JSON(), nullable=False),
        sa.Column("rejection_reasons", sa.JSON(), nullable=False),
        sa.Column("baseline_metrics", sa.JSON(), nullable=False),
        sa.Column("candidate_metrics", sa.JSON(), nullable=False),
        sa.Column("split_metrics", sa.JSON(), nullable=False),
        sa.Column("improvement_metrics", sa.JSON(), nullable=False),
        sa.Column("operational_metrics", sa.JSON(), nullable=False),
        sa.Column("report_digest", sa.String(length=64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["request_id"], ["evaluation_requests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate_defenses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    op.create_index("ix_evaluation_reports_request_id", "evaluation_reports", ["request_id"])
    op.create_index("ix_evaluation_reports_candidate_id", "evaluation_reports", ["candidate_id"])
    op.create_index("ix_evaluation_reports_verdict", "evaluation_reports", ["verdict"])
    op.create_index("ix_evaluation_reports_status", "evaluation_reports", ["status"])

    # 6. improvement_cycles
    op.create_table(
        "improvement_cycles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cycle_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("trigger_reason", sa.String(length=128), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("selected_findings", sa.JSON(), nullable=False),
        sa.Column("candidates_evaluated", sa.Integer(), nullable=False),
        sa.Column("accepted_candidate_id", sa.Uuid(), nullable=True),
        sa.Column("accepted_candidate_version", sa.String(length=32), nullable=True),
        sa.Column("summary_metrics", sa.JSON(), nullable=False),
        sa.Column("terminal_reason", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["accepted_candidate_id"], ["candidate_defenses.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_improvement_cycles_cycle_number", "improvement_cycles", ["cycle_number"])
    op.create_index("ix_improvement_cycles_status", "improvement_cycles", ["status"])

    # 7. cycle_checkpoints
    op.create_table(
        "cycle_checkpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cycle_id", sa.Uuid(), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("step_name", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["cycle_id"], ["improvement_cycles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cycle_step", "cycle_checkpoints", ["cycle_id", "step_number"])

    # 8. cycle_feedbacks
    op.create_table(
        "cycle_feedbacks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cycle_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("feedback_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("lessons_learned", sa.Text(), nullable=False),
        sa.Column("feature_weights", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["cycle_id"], ["improvement_cycles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate_defenses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cycle_feedbacks_cycle_id", "cycle_feedbacks", ["cycle_id"])
    op.create_index("ix_cycle_feedbacks_candidate_id", "cycle_feedbacks", ["candidate_id"])
    op.create_index("ix_cycle_feedbacks_outcome", "cycle_feedbacks", ["outcome"])


def downgrade() -> None:
    op.drop_table("cycle_feedbacks")
    op.drop_table("cycle_checkpoints")
    op.drop_table("improvement_cycles")
    op.drop_table("evaluation_reports")
    op.drop_table("evaluation_requests")
    op.drop_table("acceptance_policies")
    op.drop_table("benchmark_manifests")
    op.drop_table("evaluation_protocols")
