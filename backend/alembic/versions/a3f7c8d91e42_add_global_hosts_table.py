"""add_global_hosts_table

Revision ID: a3f7c8d91e42
Revises: d1c2b579a7fc
Create Date: 2026-03-08 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f7c8d91e42'
down_revision: Union[str, Sequence[str], None] = 'd1c2b579a7fc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create global_hosts table for cross-job host forensics."""
    op.create_table('global_hosts',
        sa.Column('ip', sa.String(), nullable=False),
        sa.Column('hostname', sa.String(), nullable=True),
        sa.Column('first_seen', sa.String(), nullable=True),
        sa.Column('last_seen', sa.String(), nullable=True),
        sa.Column('job_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('total_alerts', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('total_findings', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('seen_as_internal', sa.Boolean(), nullable=True, server_default='0'),
        sa.Column('roles_json', sa.Text(), nullable=True),
        sa.Column('history_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('ip')
    )
    with op.batch_alter_table('global_hosts', schema=None) as batch_op:
        batch_op.create_index('idx_global_hosts_last_seen', ['last_seen'], unique=False)


def downgrade() -> None:
    """Drop global_hosts table."""
    with op.batch_alter_table('global_hosts', schema=None) as batch_op:
        batch_op.drop_index('idx_global_hosts_last_seen')

    op.drop_table('global_hosts')

