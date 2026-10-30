"""Add lab_experiments, scenarios, scenario_executions, and failure_findings tables.

Revision ID: 0003_lab_experiments
Revises: 0002_threat_indicators
Create Date: 2026-10-28 23:45:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_lab_experiments"
down_revision: str | None = "0002_threat_indicators"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. lab_experiments
    op.create_table(
        "lab_experiments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("goal", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("scenario_count", sa.Integer(), nullable=False),
        sa.Column("completed_count", sa.Integer(), nullable=False),
        sa.Column("discrepancy_count", sa.Integer(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("summary_metrics", sa.JSON(), nullable=False),
        sa.Column("detector_version", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_lab_experiments_status", "lab_experiments", ["status"])
    op.create_index("ix_lab_experiments_created_at", "lab_experiments", ["created_at"])

    # 2. scenarios
    op.create_table(
        "scenarios",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("experiment_id", sa.Uuid(), nullable=True),
        sa.Column("scenario_family", sa.String(length=64), nullable=False),
        sa.Column("scenario_name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("expected_class", sa.String(length=32), nullable=False),
        sa.Column("expected_decision", sa.String(length=32), nullable=False),
        sa.Column("difficulty", sa.String(length=32), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("generator_version", sa.String(length=64), nullable=False),
        sa.Column("mutation_parent_id", sa.Uuid(), nullable=True),
        sa.Column("transformation_history", sa.JSON(), nullable=False),
        sa.Column("input_fixture", sa.JSON(), nullable=False),
        sa.Column("expected_evidence", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("safety_classification", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["experiment_id"], ["lab_experiments.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scenarios_experiment_id", "scenarios", ["experiment_id"])
    op.create_index("ix_scenarios_scenario_family", "scenarios", ["scenario_family"])
    op.create_index("ix_scenarios_expected_class", "scenarios", ["expected_class"])

    # 3. scenario_executions
    op.create_table(
        "scenario_executions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("experiment_id", sa.Uuid(), nullable=False),
        sa.Column("scenario_id", sa.Uuid(), nullable=False),
        sa.Column("raw_url", sa.Text(), nullable=False),
        sa.Column("expected_class", sa.String(length=32), nullable=False),
        sa.Column("expected_decision", sa.String(length=32), nullable=False),
        sa.Column("actual_decision", sa.String(length=32), nullable=False),
        sa.Column("actual_threat_score", sa.Float(), nullable=False),
        sa.Column("actual_evidence", sa.JSON(), nullable=False),
        sa.Column("detector_version", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("is_discrepancy", sa.Boolean(), nullable=False),
        sa.Column("discrepancy_type", sa.String(length=64), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["experiment_id"], ["lab_experiments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scenario_id"], ["scenarios.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_scenario_executions_experiment_id", "scenario_executions", ["experiment_id"]
    )
    op.create_index("ix_scenario_executions_scenario_id", "scenario_executions", ["scenario_id"])
    op.create_index(
        "ix_scenario_executions_is_discrepancy", "scenario_executions", ["is_discrepancy"]
    )
    op.create_index(
        "ix_scenario_executions_discrepancy_type", "scenario_executions", ["discrepancy_type"]
    )

    # 4. failure_findings
    op.create_table(
        "failure_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("experiment_id", sa.Uuid(), nullable=False),
        sa.Column("failure_category", sa.String(length=64), nullable=False),
        sa.Column("discrepancy_type", sa.String(length=64), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("affected_scenarios_count", sa.Integer(), nullable=False),
        sa.Column("representative_scenario_ids", sa.JSON(), nullable=False),
        sa.Column("suggested_remedy", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["experiment_id"], ["lab_experiments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_failure_findings_experiment_id", "failure_findings", ["experiment_id"])
    op.create_index(
        "ix_failure_findings_failure_category", "failure_findings", ["failure_category"]
    )


def downgrade() -> None:
    op.drop_table("failure_findings")
    op.drop_table("scenario_executions")
    op.drop_table("scenarios")
    op.drop_table("lab_experiments")
