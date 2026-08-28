"""add bluescrub wordlist enabled flag

Measured on a 414-file corpus, 2853 of 5866 findings — 49% — came from the
builtin pack's developer-hygiene terms. The dirty-word scanner's premise is
that the operator declared what matters; nobody declared `TODO`. The packs
seed on every job whether or not anyone wants them, and there was no way to
turn one off: `builtin` made a list read-only, which is about editing its
terms, not about whether it is hunted.

Revision ID: c9d3e4f5a6b7
Revises: b8c2d3e4f5a6
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c9d3e4f5a6b7"
down_revision: Union[str, Sequence[str], None] = "b8c2d3e4f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing lists stay enabled: an operator who already created a list was
    # already scanning against it, and a migration must not quietly stop that.
    op.add_column(
        "bluescrub_wordlists",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("bluescrub_wordlists", "enabled")
