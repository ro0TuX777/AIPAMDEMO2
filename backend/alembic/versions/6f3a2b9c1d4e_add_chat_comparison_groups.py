"""add chat comparison groups

Revision ID: 6f3a2b9c1d4e
Revises: d4e5f6a7b8c9
Create Date: 2026-09-22 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "6f3a2b9c1d4e"
down_revision: Union[str, Sequence[str], None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "chat_comparison_groups",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("root_conversation_id", sa.String(), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("active_branch_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["root_conversation_id"],
            ["chat_conversations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["active_branch_id"],
            ["chat_comparison_branches.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_chat_comparison_group_root",
        "chat_comparison_groups",
        ["root_conversation_id"],
        unique=True,
    )
    op.create_index(
        "idx_chat_comparison_group_job",
        "chat_comparison_groups",
        ["job_id"],
        unique=False,
    )

    with op.batch_alter_table("chat_conversations") as batch_op:
        batch_op.add_column(sa.Column("comparison_group_id", sa.String(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "mode",
                sa.String(),
                nullable=False,
                server_default="baseline",
            )
        )
        batch_op.add_column(sa.Column("parent_branch_id", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("source_message_id", sa.String(), nullable=True))
        batch_op.add_column(
            sa.Column("history_cutoff_sequence", sa.Integer(), nullable=True)
        )
        batch_op.add_column(sa.Column("request_id", sa.String(), nullable=True))

    with op.batch_alter_table("chat_messages") as batch_op:
        batch_op.add_column(sa.Column("sequence", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("metadata_json", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("request_id", sa.String(), nullable=True))

    op.execute(
        sa.text(
            """
            INSERT INTO chat_comparison_groups (
                id, job_id, root_conversation_id, title,
                active_branch_id, created_at, updated_at
            )
            SELECT
                'group:' || id, job_id, id, title,
                NULL, created_at, updated_at
            FROM chat_conversations
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE chat_conversations
            SET comparison_group_id = 'group:' || id,
                mode = 'baseline'
            """
        )
    )
    op.execute(
        sa.text(
            """
            WITH ordered AS (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY conversation_id
                        ORDER BY created_at, id
                    ) AS stable_sequence
                FROM chat_messages
            )
            UPDATE chat_messages
            SET sequence = (
                SELECT stable_sequence FROM ordered
                WHERE ordered.id = chat_messages.id
            )
            """
        )
    )

    with op.batch_alter_table("chat_messages") as batch_op:
        batch_op.alter_column(
            "sequence",
            existing_type=sa.Integer(),
            nullable=False,
        )

    op.create_table(
        "chat_comparison_branches",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("conversation_id", sa.String(), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("source_message_id", sa.String(), nullable=True),
        sa.Column("history_cutoff_sequence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"], ["chat_comparison_groups.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["conversation_id"], ["chat_conversations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["source_message_id"], ["chat_messages.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    with op.batch_alter_table("chat_conversations") as batch_op:
        batch_op.create_foreign_key(
            "fk_chat_conv_comparison_group",
            "chat_comparison_groups",
            ["comparison_group_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            "fk_chat_conv_parent_branch",
            "chat_conversations",
            ["parent_branch_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            "fk_chat_conv_source_message",
            "chat_messages",
            ["source_message_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_index(
            "idx_chat_conv_comparison_group", ["comparison_group_id"], unique=False
        )

    op.create_index(
        "uq_chat_conv_baseline_group",
        "chat_conversations",
        ["comparison_group_id", "mode"],
        unique=True,
        sqlite_where=sa.text("mode = 'baseline'"),
    )
    op.create_index(
        "uq_chat_conv_group_request",
        "chat_conversations",
        ["comparison_group_id", "request_id"],
        unique=True,
        sqlite_where=sa.text("request_id IS NOT NULL"),
    )
    op.create_index(
        "uq_chat_msg_conv_sequence",
        "chat_messages",
        ["conversation_id", "sequence"],
        unique=True,
    )
    op.create_index(
        "uq_chat_msg_conv_request",
        "chat_messages",
        ["conversation_id", "request_id"],
        unique=True,
        sqlite_where=sa.text("request_id IS NOT NULL"),
    )
    op.create_index(
        "idx_chat_comparison_branch_group",
        "chat_comparison_branches",
        ["group_id"],
        unique=False,
    )
    op.create_index(
        "uq_chat_comparison_branch_conversation",
        "chat_comparison_branches",
        ["conversation_id"],
        unique=True,
    )
    op.create_index(
        "uq_chat_comparison_snapshot_group",
        "chat_comparison_branches",
        ["group_id"],
        unique=True,
        sqlite_where=sa.text("source_message_id IS NULL"),
    )

    op.execute(
        """
        CREATE TRIGGER chat_conversation_provenance_immutable
        BEFORE UPDATE OF comparison_group_id, mode, parent_branch_id,
                         source_message_id, history_cutoff_sequence
        ON chat_conversations
        WHEN (OLD.comparison_group_id IS NOT NULL
              AND OLD.comparison_group_id IS NOT NEW.comparison_group_id)
          OR OLD.mode IS NOT NEW.mode
          OR OLD.parent_branch_id IS NOT NEW.parent_branch_id
          OR OLD.source_message_id IS NOT NEW.source_message_id
          OR OLD.history_cutoff_sequence IS NOT NEW.history_cutoff_sequence
        BEGIN
            SELECT RAISE(ABORT, 'chat conversation provenance is immutable');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER chat_comparison_branch_provenance_immutable
        BEFORE UPDATE OF group_id, conversation_id,
                         source_message_id, history_cutoff_sequence
        ON chat_comparison_branches
        WHEN OLD.group_id IS NOT NEW.group_id
          OR OLD.conversation_id IS NOT NEW.conversation_id
          OR OLD.source_message_id IS NOT NEW.source_message_id
          OR OLD.history_cutoff_sequence IS NOT NEW.history_cutoff_sequence
        BEGIN
            SELECT RAISE(ABORT, 'chat comparison branch provenance is immutable');
        END
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS chat_comparison_branch_provenance_immutable")
    op.execute("DROP TRIGGER IF EXISTS chat_conversation_provenance_immutable")

    op.drop_index("uq_chat_msg_conv_request", table_name="chat_messages")
    op.drop_index("uq_chat_msg_conv_sequence", table_name="chat_messages")
    op.drop_index("uq_chat_conv_group_request", table_name="chat_conversations")
    op.drop_index("uq_chat_conv_baseline_group", table_name="chat_conversations")

    with op.batch_alter_table("chat_messages") as batch_op:
        batch_op.drop_column("request_id")
        batch_op.drop_column("metadata_json")
        batch_op.drop_column("sequence")

    with op.batch_alter_table("chat_conversations") as batch_op:
        batch_op.drop_index("idx_chat_conv_comparison_group")
        batch_op.drop_constraint("fk_chat_conv_source_message", type_="foreignkey")
        batch_op.drop_constraint("fk_chat_conv_parent_branch", type_="foreignkey")
        batch_op.drop_constraint("fk_chat_conv_comparison_group", type_="foreignkey")
        batch_op.drop_column("request_id")
        batch_op.drop_column("history_cutoff_sequence")
        batch_op.drop_column("source_message_id")
        batch_op.drop_column("parent_branch_id")
        batch_op.drop_column("mode")
        batch_op.drop_column("comparison_group_id")

    op.drop_index(
        "uq_chat_comparison_snapshot_group",
        table_name="chat_comparison_branches",
    )
    op.drop_index(
        "uq_chat_comparison_branch_conversation",
        table_name="chat_comparison_branches",
    )
    op.drop_index(
        "idx_chat_comparison_branch_group",
        table_name="chat_comparison_branches",
    )
    op.drop_table("chat_comparison_branches")

    op.drop_index(
        "idx_chat_comparison_group_job", table_name="chat_comparison_groups"
    )
    op.drop_index(
        "uq_chat_comparison_group_root", table_name="chat_comparison_groups"
    )
    op.drop_table("chat_comparison_groups")
