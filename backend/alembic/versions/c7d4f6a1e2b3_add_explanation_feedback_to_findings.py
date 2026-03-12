"""add_explanation_feedback_to_findings

Revision ID: c7d4f6a1e2b3
Revises: a3f7c8d91e42
Create Date: 2026-03-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7d4f6a1e2b3'
down_revision: Union[str, Sequence[str], None] = 'a3f7c8d91e42'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('explanation_feedback', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_column('explanation_feedback')