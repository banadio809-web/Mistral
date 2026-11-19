"""Bug finder baseline: plugin, scan and finding tables.

Revision ID: bugfinder_baseline_01
Revises:
Create Date: 2026-02-13

"""
from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision: str = "bugfinder_baseline_01"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = ["bugfinder"]
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "bugfinder_plugin",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sqlmodel.sql.sqltypes.AutoString(length=190), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=250), nullable=False),
        sa.Column("version", sqlmodel.sql.sqltypes.AutoString(length=100), nullable=False),
        sa.Column("active_installs", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_bugfinder_plugin_slug"), "bugfinder_plugin", ["slug"], unique=True)

    op.create_table(
        "bugfinder_scan",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plugin_slug", sqlmodel.sql.sqltypes.AutoString(length=190), nullable=False),
        sa.Column("version", sqlmodel.sql.sqltypes.AutoString(length=100), nullable=False),
        sa.Column("files_scanned", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("in_scope_count", sa.Integer(), nullable=False),
        sa.Column("max_score", sa.Float(), nullable=False),
        sa.Column("max_severity", sqlmodel.sql.sqltypes.AutoString(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_bugfinder_scan_plugin_slug"), "bugfinder_scan", ["plugin_slug"], unique=False)

    op.create_table(
        "bugfinder_finding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("plugin_slug", sqlmodel.sql.sqltypes.AutoString(length=190), nullable=False),
        sa.Column("version", sqlmodel.sql.sqltypes.AutoString(length=100), nullable=False),
        sa.Column("rule", sqlmodel.sql.sqltypes.AutoString(length=50), nullable=False),
        sa.Column("severity", sqlmodel.sql.sqltypes.AutoString(length=20), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("vector", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(length=250), nullable=False),
        sa.Column("attacker", sqlmodel.sql.sqltypes.AutoString(length=30), nullable=False),
        sa.Column("cwe", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("file", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("snippet", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("entry", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("taint_path", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("scope_note", sqlmodel.sql.sqltypes.AutoString(length=250), nullable=False),
        sa.Column("note", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("active_installs", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_bugfinder_finding_scan_id"), "bugfinder_finding", ["scan_id"], unique=False)
    op.create_index(op.f("ix_bugfinder_finding_plugin_slug"), "bugfinder_finding", ["plugin_slug"], unique=False)
    op.create_index(op.f("ix_bugfinder_finding_rule"), "bugfinder_finding", ["rule"], unique=False)
    op.create_index(op.f("ix_bugfinder_finding_severity"), "bugfinder_finding", ["severity"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_bugfinder_finding_severity"), table_name="bugfinder_finding")
    op.drop_index(op.f("ix_bugfinder_finding_rule"), table_name="bugfinder_finding")
    op.drop_index(op.f("ix_bugfinder_finding_plugin_slug"), table_name="bugfinder_finding")
    op.drop_index(op.f("ix_bugfinder_finding_scan_id"), table_name="bugfinder_finding")
    op.drop_table("bugfinder_finding")
    op.drop_index(op.f("ix_bugfinder_scan_plugin_slug"), table_name="bugfinder_scan")
    op.drop_table("bugfinder_scan")
    op.drop_index(op.f("ix_bugfinder_plugin_slug"), table_name="bugfinder_plugin")
    op.drop_table("bugfinder_plugin")
