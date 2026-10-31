"""phase 4.2 event correlation

Revision ID: f42a00000001
Revises: ed8244c03365
Create Date: 2026-10-31 20:00:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "f42a00000001"
down_revision: str | Sequence[str] | None = "ed8244c03365"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "event_correlations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_name", sa.String(length=200), nullable=False),
        sa.Column("rule_description", sa.Text(), nullable=True),
        sa.Column("correlation_type", sa.String(length=64), nullable=False),
        sa.Column(
            "confidence",
            sa.Enum("high", "medium", "low", name="correlation_confidence", native_enum=False, length=16),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("matching_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("time_relationship", sa.Text(), nullable=True),
        sa.Column("timestamp_uncertainty", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("suggested", "dismissed", name="correlation_status", native_enum=False, length=16),
            nullable=False,
        ),
        sa.Column("parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by", sa.String(length=255), nullable=True),
        sa.Column("dismissal_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_event_correlations_investigation", "event_correlations", ["investigation_id"], unique=False)
    op.create_index("ix_event_correlations_status", "event_correlations", ["status"], unique=False)
    op.create_index("ix_event_correlations_rule", "event_correlations", ["rule_id"], unique=False)

    op.create_table(
        "event_correlation_members",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["correlation_id"], ["event_correlations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["parsed_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("correlation_id", "event_id", name="uq_event_correlation_members_corr_event"),
    )
    op.create_index("ix_event_correlation_members_event", "event_correlation_members", ["event_id"], unique=False)
    op.create_index("ix_event_correlation_members_correlation", "event_correlation_members", ["correlation_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_event_correlation_members_correlation", table_name="event_correlation_members")
    op.drop_index("ix_event_correlation_members_event", table_name="event_correlation_members")
    op.drop_table("event_correlation_members")
    op.drop_index("ix_event_correlations_rule", table_name="event_correlations")
    op.drop_index("ix_event_correlations_status", table_name="event_correlations")
    op.drop_index("ix_event_correlations_investigation", table_name="event_correlations")
    op.drop_table("event_correlations")