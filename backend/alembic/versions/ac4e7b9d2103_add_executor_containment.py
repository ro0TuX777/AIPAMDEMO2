"""Persist the session containment established before analysis work."""
from alembic import op
import sqlalchemy as sa

revision = 'ac4e7b9d2103'
down_revision = '9c7a5e3b2d01'
branch_labels = None
depends_on = None


def upgrade():
    # A legacy process has no launch-time proof. Never invent one by backfill.
    op.add_column('jobs', sa.Column('executor_session_id', sa.Integer(), nullable=True))
    op.add_column('jobs', sa.Column('executor_group_nonce', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('jobs') as batch:
        batch.drop_column('executor_group_nonce')
        batch.drop_column('executor_session_id')
