"""add_upload_artifact_class (merge heads)

Adds the ``artifact_class`` column to the uploads table to support generic
artifact upload/classification, and merges the two existing migration heads
(temporal correlations + explanation feedback) into a single head.

Revision ID: f1a2b3c4d5e6
Revises: e2a9f4b71d83, c7d4f6a1e2b3
Create Date: 2026-06-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = ('e2a9f4b71d83', 'c7d4f6a1e2b3')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('uploads', schema=None) as batch_op:
        batch_op.add_column(sa.Column('artifact_class', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('uploads', schema=None) as batch_op:
        batch_op.drop_column('artifact_class')
