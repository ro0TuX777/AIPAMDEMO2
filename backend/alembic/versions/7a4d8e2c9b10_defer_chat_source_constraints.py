"""Defer source constraints until commit so whole-job cascades remain atomic.

Revision ID: 7a4d8e2c9b10
Revises: 6f3a2b9c1d4e
"""
from alembic import op

revision = "7a4d8e2c9b10"
down_revision = "6f3a2b9c1d4e"
branch_labels = None
depends_on = None


def _change(deferred: bool):
    connection = op.get_bind()
    triggers = connection.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name IN "
        "('chat_conversation_provenance_immutable', 'chat_comparison_branch_provenance_immutable')"
    ).all()
    for name, _ in triggers:
        op.execute(f"DROP TRIGGER {name}")
    naming = {"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}
    for table, constraint in (
        ("chat_conversations", "fk_chat_conv_source_message"),
        ("chat_comparison_branches", "fk_chat_comparison_branches_source_message_id_chat_messages"),
    ):
        with op.batch_alter_table(table, naming_convention=naming) as batch:
            if table == "chat_conversations":
                batch.drop_constraint("fk_chat_conversations_job_id_jobs", type_="foreignkey")
                batch.create_foreign_key("fk_chat_conversations_job_id_jobs", "jobs", ["job_id"], ["job_id"], ondelete="CASCADE")
            batch.drop_constraint(constraint, type_="foreignkey")
            batch.create_foreign_key(
                constraint, "chat_messages", ["source_message_id"], ["id"],
                ondelete="NO ACTION" if deferred else "RESTRICT",
                deferrable=deferred, initially="DEFERRED" if deferred else "IMMEDIATE",
            )
    # Some legacy SQLite schemas used inline references; batch reflection in
    # the previous migration could omit their cascade. Restore ownership FKs.
    with op.batch_alter_table("chat_messages", naming_convention=naming) as batch:
        batch.drop_constraint("fk_chat_messages_conversation_id_chat_conversations", type_="foreignkey")
        batch.create_foreign_key("fk_chat_messages_conversation_id_chat_conversations", "chat_conversations", ["conversation_id"], ["id"], ondelete="CASCADE")
    for _, sql in triggers:
        op.execute(sql)


def upgrade():
    _change(True)


def downgrade():
    _change(False)
