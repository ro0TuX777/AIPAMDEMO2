"""add bluescrub wordlists

Operator-editable dirty-word lists and the read-only shipped packs. Specified
in the v1.0 plan and lost in the v1.1 rewrite; the wordlists module needs it.

Revision ID: b8c2d3e4f5a6
Revises: a7b1c2d3e4f5
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b8c2d3e4f5a6"
down_revision: Union[str, Sequence[str], None] = "a7b1c2d3e4f5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bluescrub_wordlists",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("entries_json", sa.Text(), nullable=False),
        sa.Column("case_sensitive", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("bluescrub_wordlists")
