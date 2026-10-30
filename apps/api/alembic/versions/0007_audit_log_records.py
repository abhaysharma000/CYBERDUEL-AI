"""Add audit_log_records table for immutable security audit logging.

Revision ID: 0007_audit_log_records
Revises: 0006_release_management
Create Date: 2026-10-29 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_audit_log_records"
down_revision: str | None = "0006_release_management"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log_records",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), unique=True, nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False, server_default="success"),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_log_records_event_id", "audit_log_records", ["event_id"])
    op.create_index("ix_audit_log_records_actor", "audit_log_records", ["actor"])
    op.create_index("ix_audit_log_records_action", "audit_log_records", ["action"])
    op.create_index("ix_audit_log_records_target_type", "audit_log_records", ["target_type"])
    op.create_index("ix_audit_log_records_target_id", "audit_log_records", ["target_id"])
    op.create_index("ix_audit_log_records_correlation_id", "audit_log_records", ["correlation_id"])
    op.create_index("ix_audit_actor_created", "audit_log_records", ["actor", "created_at"])
    op.create_index("ix_audit_action_created", "audit_log_records", ["action", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_action_created", table_name="audit_log_records")
    op.drop_index("ix_audit_actor_created", table_name="audit_log_records")
    op.drop_index("ix_audit_log_records_correlation_id", table_name="audit_log_records")
    op.drop_index("ix_audit_log_records_target_id", table_name="audit_log_records")
    op.drop_index("ix_audit_log_records_target_type", table_name="audit_log_records")
    op.drop_index("ix_audit_log_records_action", table_name="audit_log_records")
    op.drop_index("ix_audit_log_records_actor", table_name="audit_log_records")
    op.drop_index("ix_audit_log_records_event_id", table_name="audit_log_records")
    op.drop_table("audit_log_records")
