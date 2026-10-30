"""Add threat_indicators table for local intelligence lookups.

Revision ID: 0002_threat_indicators
Revises: 0001_initial_schema
Create Date: 2026-10-28 23:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_threat_indicators"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("normalized_value", sa.String(length=512), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_version", sa.String(length=32), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False),
        sa.Column("metadata_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_indicators_classification", "threat_indicators", ["classification"])
    op.create_index("ix_threat_indicators_created_at", "threat_indicators", ["created_at"])
    op.create_index("ix_threat_indicators_expires_at", "threat_indicators", ["expires_at"])
    op.create_index("ix_threat_indicators_indicator_type", "threat_indicators", ["indicator_type"])
    op.create_index(
        "ix_threat_indicators_normalized_value", "threat_indicators", ["normalized_value"]
    )
    op.create_index("ix_threat_indicators_value_hash", "threat_indicators", ["value_hash"])
    op.create_index(
        "ix_threat_indicators_verification_status", "threat_indicators", ["verification_status"]
    )
    op.create_index(
        "ix_threat_indicators_hash_status",
        "threat_indicators",
        ["value_hash", "verification_status"],
    )
    op.create_index(
        "ix_threat_indicators_type_val", "threat_indicators", ["indicator_type", "normalized_value"]
    )


def downgrade() -> None:
    op.drop_table("threat_indicators")
