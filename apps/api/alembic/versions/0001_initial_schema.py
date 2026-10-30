"""Initial database migration establishing CyberDuel AI foundational schema.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-10-28 22:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Threat Observations
    op.create_table(
        "threat_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("normalized_target", sa.String(length=256), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("local_action_taken", sa.String(length=32), nullable=True),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("telemetry_payload", sa.JSON(), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_observations_created_at", "threat_observations", ["created_at"])
    op.create_index(
        "ix_threat_observations_normalized_target", "threat_observations", ["normalized_target"]
    )
    op.create_index("ix_threat_observations_source", "threat_observations", ["source"])
    op.create_index(
        "ix_threat_observations_verification_status", "threat_observations", ["verification_status"]
    )
    op.create_index(
        "ix_threat_obs_target_status",
        "threat_observations",
        ["normalized_target", "verification_status"],
    )

    # 2. Threat Analyses
    op.create_table(
        "threat_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("normalized_identifier", sa.String(length=256), nullable=False),
        sa.Column("threat_score", sa.Float(), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("provenance", sa.String(length=64), nullable=False),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("evidence_payload", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_analyses_created_at", "threat_analyses", ["created_at"])
    op.create_index("ix_threat_analyses_decision", "threat_analyses", ["decision"])
    op.create_index("ix_threat_analyses_expires_at", "threat_analyses", ["expires_at"])
    op.create_index(
        "ix_threat_analyses_normalized_identifier", "threat_analyses", ["normalized_identifier"]
    )
    op.create_index(
        "ix_threat_analyses_lookup", "threat_analyses", ["normalized_identifier", "decision"]
    )

    # 3. Detection Outcomes
    op.create_table(
        "detection_outcomes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.String(length=128), nullable=True),
        sa.Column("client_action_taken", sa.String(length=32), nullable=False),
        sa.Column("outcome_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["threat_analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_detection_outcomes_analysis_id", "detection_outcomes", ["analysis_id"])
    op.create_index("ix_detection_outcomes_client_id", "detection_outcomes", ["client_id"])
    op.create_index("ix_detection_outcomes_created_at", "detection_outcomes", ["created_at"])

    # 4. Lab Scenario Runs
    op.create_table(
        "lab_scenario_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=128), nullable=False),
        sa.Column("scenario_type", sa.String(length=64), nullable=False),
        sa.Column("synthetic_payload", sa.JSON(), nullable=False),
        sa.Column("expected_decision", sa.String(length=32), nullable=False),
        sa.Column("difficulty", sa.String(length=32), nullable=False),
        sa.Column("created_by_agent", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("execution_metrics", sa.JSON(), nullable=False),
        sa.Column("findings_summary", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_lab_scenario_runs_created_at", "lab_scenario_runs", ["created_at"])
    op.create_index("ix_lab_scenario_runs_scenario_type", "lab_scenario_runs", ["scenario_type"])
    op.create_index("ix_lab_scenario_runs_status", "lab_scenario_runs", ["status"])

    # 5. Candidate Defenses
    op.create_table(
        "candidate_defenses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("author_agent", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("rule_spec", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_candidate_defenses_created_at", "candidate_defenses", ["created_at"])
    op.create_index("ix_candidate_defenses_status", "candidate_defenses", ["status"])
    op.create_index("ix_candidate_defenses_version", "candidate_defenses", ["version"], unique=True)

    # 6. Evaluation Runs
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_defense_id", sa.Uuid(), nullable=False),
        sa.Column("scenario_suite_id", sa.String(length=64), nullable=False),
        sa.Column("total_scenarios", sa.Integer(), nullable=False),
        sa.Column("passed_scenarios", sa.Integer(), nullable=False),
        sa.Column("detection_rate", sa.Float(), nullable=False),
        sa.Column("false_positive_rate", sa.Float(), nullable=False),
        sa.Column("regression_count", sa.Integer(), nullable=False),
        sa.Column("resource_overhead_ms", sa.Float(), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("verdict_rationale", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_defense_id"], ["candidate_defenses.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_evaluation_runs_candidate_defense_id", "evaluation_runs", ["candidate_defense_id"]
    )
    op.create_index("ix_evaluation_runs_created_at", "evaluation_runs", ["created_at"])
    op.create_index(
        "ix_evaluation_runs_scenario_suite_id", "evaluation_runs", ["scenario_suite_id"]
    )
    op.create_index("ix_evaluation_runs_verdict", "evaluation_runs", ["verdict"])
    op.create_index(
        "ix_eval_runs_suite_verdict", "evaluation_runs", ["scenario_suite_id", "verdict"]
    )

    # 7. Policy Releases
    op.create_table(
        "policy_releases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("min_client_version", sa.String(length=32), nullable=False),
        sa.Column("rules_digest", sa.String(length=64), nullable=False),
        sa.Column("publisher_key_id", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("rules_payload", sa.JSON(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_releases_created_at", "policy_releases", ["created_at"])
    op.create_index("ix_policy_releases_expires_at", "policy_releases", ["expires_at"])
    op.create_index(
        "ix_policy_releases_policy_version", "policy_releases", ["policy_version"], unique=True
    )
    op.create_index("ix_policy_releases_status", "policy_releases", ["status"])
    op.create_index(
        "ix_policy_releases_ver_status", "policy_releases", ["policy_version", "status"]
    )

    # 8. Device Registrations
    op.create_table(
        "device_registrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.String(length=128), nullable=False),
        sa.Column("client_type", sa.String(length=64), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("current_policy_version", sa.String(length=32), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_device_registrations_client_id", "device_registrations", ["client_id"], unique=True
    )
    op.create_index("ix_device_registrations_client_type", "device_registrations", ["client_type"])
    op.create_index("ix_device_registrations_created_at", "device_registrations", ["created_at"])

    # 9. Update Deliveries
    op.create_table(
        "update_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("policy_release_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device_registrations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_release_id"], ["policy_releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_update_deliveries_created_at", "update_deliveries", ["created_at"])
    op.create_index("ix_update_deliveries_device_id", "update_deliveries", ["device_id"])
    op.create_index(
        "ix_update_deliveries_policy_release_id", "update_deliveries", ["policy_release_id"]
    )
    op.create_index("ix_update_deliveries_status", "update_deliveries", ["status"])

    # 10. Feedback Submissions
    op.create_table(
        "feedback_submissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("feedback_type", sa.String(length=32), nullable=False),
        sa.Column("normalized_identifier", sa.String(length=256), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=True),
        sa.Column("user_notes", sa.Text(), nullable=True),
        sa.Column("triage_status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["threat_analyses.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_feedback_submissions_analysis_id", "feedback_submissions", ["analysis_id"])
    op.create_index("ix_feedback_submissions_created_at", "feedback_submissions", ["created_at"])
    op.create_index(
        "ix_feedback_submissions_feedback_type", "feedback_submissions", ["feedback_type"]
    )
    op.create_index(
        "ix_feedback_submissions_normalized_identifier",
        "feedback_submissions",
        ["normalized_identifier"],
    )
    op.create_index(
        "ix_feedback_submissions_triage_status", "feedback_submissions", ["triage_status"]
    )
    op.create_index(
        "ix_feedback_type_status", "feedback_submissions", ["feedback_type", "triage_status"]
    )


def downgrade() -> None:
    op.drop_table("feedback_submissions")
    op.drop_table("update_deliveries")
    op.drop_table("device_registrations")
    op.drop_table("policy_releases")
    op.drop_table("evaluation_runs")
    op.drop_table("candidate_defenses")
    op.drop_table("lab_scenario_runs")
    op.drop_table("detection_outcomes")
    op.drop_table("threat_analyses")
    op.drop_table("threat_observations")
