"""store the comparability signature's fields, not only its digest

SCORING_SPEC §6 requires a rejected comparison to name the field that
differs. A SHA-256 cannot answer that: it says two scans are incomparable and
nothing about why, which is precisely the unactionable message the contract
forbids. Whoever stores a signature has to store what went into it.

Revision ID: d4e5f6a7b8c9
Revises: c9d3e4f5a6b7
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c9d3e4f5a6b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Nullable: rows written before this exist, and a baseline built from one
    # falls back to comparing digests — able to say whether two scans are
    # comparable, honest that it cannot say which field moved.
    op.add_column(
        "bluescrub_job_lineage",
        sa.Column("signature_fields_json", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("bluescrub_job_lineage", "signature_fields_json")
