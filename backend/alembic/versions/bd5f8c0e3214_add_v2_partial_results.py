"""Store V2 progressive snapshots under their authoritative jobs.

Revision ID: bd5f8c0e3214
Revises: 9c7e5a3b2d10
"""
from alembic import op
import sqlalchemy as sa

revision = "bd5f8c0e3214"
down_revision = "9c7e5a3b2d10"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("partial_results"):
        # Development startup may create metadata tables before Alembic runs.
        # Adopt only the exact supported structure and preserve newer snapshots.
        columns = {column['name']: column for column in inspector.get_columns('partial_results')}
        types = {'job_id': sa.String, 'result': sa.JSON, 'updated_at': sa.DateTime}
        foreign_keys = inspector.get_foreign_keys('partial_results')
        supported = (
            set(columns) == set(types)
            and all(isinstance(columns[name]['type'], kind) and not columns[name]['nullable']
                    and columns[name]['default'] is None for name, kind in types.items())
            and inspector.get_pk_constraint('partial_results')['constrained_columns'] == ['job_id']
            and len(foreign_keys) == 1
            and foreign_keys[0]['constrained_columns'] == ['job_id']
            and foreign_keys[0]['referred_table'] == 'jobs'
            and foreign_keys[0]['referred_columns'] == ['job_id']
            and foreign_keys[0].get('options', {}).get('ondelete', '').upper() == 'CASCADE'
        )
        if not supported:
            raise RuntimeError('Unsupported partial_results schema')
    else:
        op.create_table(
            "partial_results",
            sa.Column("job_id", sa.String(), sa.ForeignKey("jobs.job_id", ondelete="CASCADE"), primary_key=True),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    if inspector.has_table("partialjobresultdb"):
        # Keep the legacy store intact. Only snapshots for real V2 jobs belong
        # in the V2 store; arbitrary legacy IDs must not bypass its FK.
        op.execute(sa.text(
            "INSERT INTO partial_results (job_id, result, updated_at) "
            "SELECT p.job_id, p.result, p.updated_at FROM partialjobresultdb AS p "
            "JOIN jobs AS j ON j.job_id = p.job_id "
            "WHERE NOT EXISTS (SELECT 1 FROM partial_results AS current WHERE current.job_id = p.job_id)"
        ))


def downgrade():
    # Progressive snapshots are disposable; legacy records remain untouched.
    op.drop_table("partial_results")
