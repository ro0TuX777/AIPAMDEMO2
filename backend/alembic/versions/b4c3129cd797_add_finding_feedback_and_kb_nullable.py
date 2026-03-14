"""add_finding_feedback_and_kb_nullable

Revision ID: b4c3129cd797
Revises: 001e6676c340
Create Date: 2026-03-07 20:53:21.387024

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b4c3129cd797'
down_revision: Union[str, Sequence[str], None] = '001e6676c340'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Only the two V2 schema changes are applied here.  The original
    auto-generated migration also included DROP TABLE statements for V1
    SQLModel tables (jobdb, alertdb, flowdb, …) which never existed in the
    V2-only production database.  Those have been removed so this migration
    runs cleanly on both fresh and existing V2 databases.
    """
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('feedback', sa.String(), nullable=True))

    with op.batch_alter_table('kb_documents', schema=None) as batch_op:
        batch_op.alter_column('job_id',
               existing_type=sa.VARCHAR(),
               nullable=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('kb_documents', schema=None) as batch_op:
        batch_op.alter_column('job_id',
               existing_type=sa.VARCHAR(),
               nullable=False)

    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_column('feedback')
    # ### end Alembic commands ###
