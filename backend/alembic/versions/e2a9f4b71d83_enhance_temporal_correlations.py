"""enhance_temporal_correlations

Add multi-key / label-aware / clock-aligned metadata columns to
temporal_correlations for the enhanced temporal correlation framework.

Revision ID: e2a9f4b71d83
Revises: a3f7c8d91e42
Create Date: 2026-06-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2a9f4b71d83'
down_revision: Union[str, Sequence[str], None] = 'a3f7c8d91e42'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('temporal_correlations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('community_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('match_keys_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('log_label', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('pcap_label', sa.String(), nullable=True))
        batch_op.add_column(
            sa.Column('clock_offset_seconds', sa.Float(), nullable=True, server_default='0.0')
        )
        batch_op.add_column(sa.Column('adjusted_time_delta_seconds', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('confidence_band', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('temporal_correlations', schema=None) as batch_op:
        batch_op.drop_column('confidence_band')
        batch_op.drop_column('adjusted_time_delta_seconds')
        batch_op.drop_column('clock_offset_seconds')
        batch_op.drop_column('pcap_label')
        batch_op.drop_column('log_label')
        batch_op.drop_column('match_keys_json')
        batch_op.drop_column('community_id')
