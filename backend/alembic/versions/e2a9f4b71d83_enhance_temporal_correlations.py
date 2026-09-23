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
    if not sa.inspect(op.get_bind()).has_table("temporal_correlations"):
        op.create_table("temporal_correlations",
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('job_id', sa.String(), nullable=False),
            sa.Column('log_event_id', sa.String(), nullable=False),
            sa.Column('log_source', sa.String(), nullable=True),
            sa.Column('log_event_type', sa.String(), nullable=True),
            sa.Column('log_timestamp', sa.String(), nullable=False),
            sa.Column('pcap_entity_type', sa.String(), nullable=False),
            sa.Column('pcap_entity_id', sa.String(), nullable=False),
            sa.Column('pcap_summary', sa.Text(), nullable=True),
            sa.Column('pcap_timestamp', sa.String(), nullable=False),
            sa.Column('shared_ip', sa.String(), nullable=False),
            sa.Column('time_delta_seconds', sa.Float(), nullable=False),
            sa.Column('match_score', sa.Float(), nullable=False),
            sa.Column('match_type', sa.String(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.ForeignKeyConstraint(['job_id'], ['jobs.job_id'], ondelete='CASCADE'),
        )
        op.create_index('idx_tc_job', "temporal_correlations", ['job_id'], unique=False)
        op.create_index('idx_tc_job_score', "temporal_correlations", ['job_id', 'match_score'], unique=False)
        op.create_index('idx_tc_log_event', "temporal_correlations", ['job_id', 'log_event_id'], unique=False)
        op.create_index('idx_tc_pcap_entity', "temporal_correlations", ['job_id', 'pcap_entity_type', 'pcap_entity_id'], unique=False)
        op.create_index('ix_temporal_correlations_log_event_id', "temporal_correlations", ['log_event_id'], unique=False)
        op.create_index('ix_temporal_correlations_pcap_entity_id', "temporal_correlations", ['pcap_entity_id'], unique=False)
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
