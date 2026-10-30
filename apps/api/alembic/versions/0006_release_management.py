"""Add signing_keys, releases, release_authorizations, rollout_states, client_devices, and client_acknowledgements tables.

Revision ID: 0006_release_management
Revises: 0005_evaluation_controller
Create Date: 2026-10-29 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_release_management"
down_revision: str | None = "0005_evaluation_controller"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. signing_keys
    op.create_table(
        "signing_keys",
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False, server_default="ed25519"),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key_id"),
    )
    op.create_index("ix_signing_keys_status", "signing_keys", ["status"])

    # 2. releases
    op.create_table(
        "releases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False, server_default="stable"),
        sa.Column("candidate_id", sa.Uuid(), nullable=True),
        sa.Column("evaluation_report_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="draft"),
        sa.Column(
            "min_client_version", sa.String(length=32), nullable=False, server_default="0.1.0"
        ),
        sa.Column("max_client_version", sa.String(length=32), nullable=True),
        sa.Column(
            "min_engine_version", sa.String(length=32), nullable=False, server_default="1.0.0"
        ),
        sa.Column("supported_platforms", sa.JSON(), nullable=False),
        sa.Column("artifact_path", sa.String(length=512), nullable=False),
        sa.Column("artifact_digest", sa.String(length=64), nullable=False),
        sa.Column("artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("publisher_key_id", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("manifest_payload", sa.JSON(), nullable=False),
        sa.Column("bundle_payload", sa.JSON(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_mandatory", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_rollback", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("rollback_target_version", sa.String(length=32), nullable=True),
        sa.Column("release_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate_defenses.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["evaluation_report_id"], ["evaluation_reports.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["publisher_key_id"], ["signing_keys.key_id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_version"),
        sa.UniqueConstraint("sequence_number"),
    )
    op.create_index("ix_releases_policy_version", "releases", ["policy_version"])
    op.create_index("ix_releases_sequence_number", "releases", ["sequence_number"])
    op.create_index("ix_releases_channel", "releases", ["channel"])
    op.create_index("ix_releases_status", "releases", ["status"])
    op.create_index("ix_releases_artifact_digest", "releases", ["artifact_digest"])
    op.create_index("ix_releases_publisher_key_id", "releases", ["publisher_key_id"])
    op.create_index("ix_releases_expires_at", "releases", ["expires_at"])
    op.create_index("ix_releases_published_at", "releases", ["published_at"])
    op.create_index("ix_releases_channel_seq", "releases", ["channel", "sequence_number"])
    op.create_index("ix_releases_status_channel", "releases", ["status", "channel"])

    # 3. release_authorizations
    op.create_table(
        "release_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("release_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("evaluation_report_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("target_channel", sa.String(length=32), nullable=False),
        sa.Column("authorized_by", sa.String(length=128), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_authorizations_release_id", "release_authorizations", ["release_id"]
    )
    op.create_index(
        "ix_release_authorizations_candidate_id", "release_authorizations", ["candidate_id"]
    )

    # 4. rollout_states
    op.create_table(
        "rollout_states",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("release_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False, server_default="internal"),
        sa.Column("rollout_percentage", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("is_paused", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("total_targeted_clients", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("successful_installs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_installs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rollback_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_rate", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("stage_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("release_id"),
    )
    op.create_index("ix_rollout_states_channel", "rollout_states", ["channel"])
    op.create_index("ix_rollout_states_stage", "rollout_states", ["stage"])

    # 5. client_devices
    op.create_table(
        "client_devices",
        sa.Column("client_id", sa.String(length=128), nullable=False),
        sa.Column("client_type", sa.String(length=32), nullable=False),
        sa.Column("current_policy_version", sa.String(length=32), nullable=False),
        sa.Column("current_sequence_number", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False, server_default="stable"),
        sa.Column("cohort_bucket", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("client_id"),
    )
    op.create_index("ix_client_devices_client_type", "client_devices", ["client_type"])
    op.create_index("ix_client_devices_channel", "client_devices", ["channel"])
    op.create_index("ix_client_devices_cohort_bucket", "client_devices", ["cohort_bucket"])

    # 6. client_acknowledgements
    op.create_table(
        "client_acknowledgements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.String(length=128), nullable=False),
        sa.Column("release_id", sa.Uuid(), nullable=True),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["client_devices.client_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_client_acknowledgements_client_id", "client_acknowledgements", ["client_id"]
    )
    op.create_index(
        "ix_client_acknowledgements_policy_version", "client_acknowledgements", ["policy_version"]
    )
    op.create_index("ix_client_acknowledgements_status", "client_acknowledgements", ["status"])


def downgrade() -> None:
    op.drop_table("client_acknowledgements")
    op.drop_table("client_devices")
    op.drop_table("rollout_states")
    op.drop_table("release_authorizations")
    op.drop_table("releases")
    op.drop_table("signing_keys")
