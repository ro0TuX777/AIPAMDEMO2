"""add bluescrub tables

Six additive tables for the BlueScrub code-artifact pipeline. No existing table
is altered.

Three carry no foreign key to ``jobs`` on purpose. ``aipam.prune_old_jobs``
deletes whole jobs at the platform retention horizon and ``Finding`` cascades,
so triage decisions, frozen baselines, and score history would vanish with the
job that produced them. The baseline keeps a nullable job reference for
provenance only, with ``ON DELETE SET NULL``.

Revision ID: a7b1c2d3e4f5
Revises: f1a2b3c4d5e6
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7b1c2d3e4f5"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bluescrub_projects",
        sa.Column("project_id", sa.String(), primary_key=True),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False, server_default="0"),
    )

    op.create_table(
        "bluescrub_job_lineage",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=True),
        sa.Column("lineage_parent_job_id", sa.String(), nullable=True),
        sa.Column("derived_from_job_id", sa.String(), nullable=True),
        sa.Column("derived_from_file_id", sa.String(), nullable=True),
        sa.Column("artifact_sha256", sa.String(), nullable=True),
        sa.Column("analysis_kind", sa.String(), nullable=False,
                  server_default="source_audit"),
        sa.Column("compatibility_signature", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    )
    op.create_index("ix_bluescrub_job_lineage_project_id",
                    "bluescrub_job_lineage", ["project_id"])

    op.create_table(
        "bluescrub_triage_ledger",
        sa.Column("project_id", sa.String(), primary_key=True),
        sa.Column("finding_id", sa.String(), primary_key=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("rule_version", sa.String(), nullable=True),
        sa.Column("fingerprint_scheme", sa.String(), nullable=False),
        sa.Column("decided_at", sa.String(), nullable=False),
        sa.Column("decided_by", sa.String(), nullable=True),
        sa.Column("origin_job_id", sa.String(), nullable=True),
    )
    op.create_index("idx_bs_triage_project", "bluescrub_triage_ledger", ["project_id"])

    op.create_table(
        "bluescrub_baselines",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("compatibility_signature", sa.String(), nullable=False),
        sa.Column("findings_json", sa.Text(), nullable=False),
        sa.Column("metrics_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="SET NULL"),
    )
    op.create_index("ix_bluescrub_baselines_project_id",
                    "bluescrub_baselines", ["project_id"])
    op.create_index(
        "uq_bs_active_baseline", "bluescrub_baselines", ["project_id"],
        unique=True, sqlite_where=sa.text("active = 1"),
    )

    op.create_table(
        "bluescrub_score_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False, unique=True),
        sa.Column("scanned_at", sa.String(), nullable=False),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("scoring_model", sa.String(), nullable=False),
        sa.Column("compatibility_signature", sa.String(), nullable=False),
        sa.Column("coverage_json", sa.Text(), nullable=False),
        sa.Column("pillars_json", sa.Text(), nullable=False),
        sa.Column("overall_score", sa.Integer(), nullable=True),
        sa.Column("grade", sa.String(), nullable=True),
        sa.Column("scoped_score", sa.Integer(), nullable=False),
        sa.Column("severity_counts_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_bluescrub_score_history_project_id",
                    "bluescrub_score_history", ["project_id"])

    op.create_table(
        "bluescrub_audit",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("at", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=True),
        sa.Column("job_id", sa.String(), nullable=True),
        sa.Column("old_json", sa.Text(), nullable=True),
        sa.Column("new_json", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("session", sa.String(), nullable=True),
    )
    op.create_index("ix_bluescrub_audit_project_id", "bluescrub_audit", ["project_id"])


def downgrade() -> None:
    op.drop_table("bluescrub_audit")
    op.drop_table("bluescrub_score_history")
    op.drop_table("bluescrub_baselines")
    op.drop_table("bluescrub_triage_ledger")
    op.drop_table("bluescrub_job_lineage")
    op.drop_table("bluescrub_projects")
