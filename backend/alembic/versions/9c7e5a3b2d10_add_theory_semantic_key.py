"""Give theories a non-null semantic identity and consolidate legacy duplicates."""

from alembic import op
import sqlalchemy as sa

revision = "9c7e5a3b2d10"
down_revision = "ac4e7b9d2103"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("theories", sa.Column("phase_key", sa.String(), nullable=True))
    op.add_column("theories", sa.Column("scope_id_key", sa.String(), nullable=True))
    op.add_column("theories", sa.Column("theory_key", sa.String(), nullable=True))
    op.execute("UPDATE theories SET phase_key = COALESCE(pcap_label, ''), "
               "scope_id_key = COALESCE(scope_id, ''), theory_key = hypothesis_type")

    conn = op.get_bind()
    theories = sa.table("theories", sa.column("id", sa.Integer),
        sa.column("job_id", sa.String), sa.column("phase_key", sa.String),
        sa.column("scope_type", sa.String), sa.column("scope_id_key", sa.String),
        sa.column("theory_key", sa.String), sa.column("analyst_status", sa.String),
        sa.column("analyst_notes", sa.Text), sa.column("reviewed_at", sa.String),
        sa.column("reviewer_id", sa.String))
    rows = list(conn.execute(sa.select(theories).order_by(theories.c.id)).mappings())
    groups = {}
    for row in rows:
        key = tuple(row[name] for name in ("job_id", "phase_key", "scope_type", "scope_id_key", "theory_key"))
        groups.setdefault(key, []).append(row)
    review_fields = ("analyst_status", "analyst_notes", "reviewed_at", "reviewer_id")
    def reviewed(row):
        return (row["analyst_status"] not in (None, "unreviewed")
                or any(row[name] is not None for name in review_fields[1:]))
    for group in groups.values():
        if len(group) < 2:
            continue
        survivor = min(group, key=lambda row: (not reviewed(row), row["id"]))
        by_recency = sorted(group, key=lambda row: (row["reviewed_at"] or "", row["id"]), reverse=True)
        changes = {}
        for name in review_fields:
            if name == "analyst_status":
                candidate = next((row[name] for row in by_recency if row[name] not in (None, "unreviewed")), None)
            else:
                candidate = next((row[name] for row in by_recency if row[name] is not None), None)
            if candidate is not None:
                changes[name] = candidate
        if changes:
            conn.execute(theories.update().where(theories.c.id == survivor["id"]).values(**changes))
        conn.execute(theories.delete().where(theories.c.id.in_(
            [row["id"] for row in group if row["id"] != survivor["id"]])))

    with op.batch_alter_table("theories") as batch:
        for name in ("phase_key", "scope_id_key", "theory_key"):
            batch.alter_column(name, existing_type=sa.String(), nullable=False)
        batch.create_unique_constraint("uq_theories_semantic",
            ["job_id", "phase_key", "scope_type", "scope_id_key", "theory_key"])


def downgrade():
    with op.batch_alter_table("theories") as batch:
        batch.drop_constraint("uq_theories_semantic", type_="unique")
        batch.drop_column("theory_key")
        batch.drop_column("scope_id_key")
        batch.drop_column("phase_key")
