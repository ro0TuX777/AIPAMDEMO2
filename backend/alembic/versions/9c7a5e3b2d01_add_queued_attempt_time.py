"""Give every queued attempt its own database-time dispatch grace."""
from alembic import op
import sqlalchemy as sa

revision = '9c7a5e3b2d01'
down_revision = '8b6f4d2a1c90'
branch_labels = None
depends_on = None


def upgrade():
    # SQLite cannot ADD a nonconstant default to an existing table.
    op.add_column('jobs', sa.Column('queued_at', sa.String(), nullable=True))
    op.execute('UPDATE jobs SET queued_at = created_at')
    with op.batch_alter_table('jobs') as batch:
        batch.alter_column('queued_at', existing_type=sa.String(),
                           server_default=sa.text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"))


def downgrade():
    with op.batch_alter_table('jobs') as batch:
        batch.drop_column('queued_at')
