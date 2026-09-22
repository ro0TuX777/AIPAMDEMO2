"""Chat conversation, comparison, and message models for V2."""

from collections import defaultdict

from sqlalchemy import Column, ForeignKey, Index, Integer, String, Text, event, func, select, text
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base


class ChatComparisonGroup(Base):
    __tablename__ = "chat_comparison_groups"

    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    root_conversation_id = Column(
        String,
        ForeignKey("chat_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    title = Column(Text, nullable=True)
    active_branch_id = Column(
        String,
        ForeignKey("chat_comparison_branches.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("uq_chat_comparison_group_root", "root_conversation_id", unique=True),
        Index("idx_chat_comparison_group_job", "job_id"),
    )


class ChatConversation(Base):
    __tablename__ = "chat_conversations"

    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    comparison_group_id = Column(
        String,
        ForeignKey("chat_comparison_groups.id", ondelete="CASCADE"),
        nullable=True,
    )
    mode = Column(String, nullable=False, default="baseline")
    parent_branch_id = Column(
        String,
        ForeignKey("chat_conversations.id", ondelete="CASCADE"),
        nullable=True,
    )
    source_message_id = Column(
        String,
        ForeignKey("chat_messages.id", ondelete="RESTRICT"),
        nullable=True,
    )
    history_cutoff_sequence = Column(Integer, nullable=True)
    request_id = Column(String, nullable=True)
    title = Column(Text, nullable=True)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_chat_conv_job", "job_id"),
        Index("idx_chat_conv_comparison_group", "comparison_group_id"),
        Index(
            "uq_chat_conv_baseline_group",
            "comparison_group_id",
            "mode",
            unique=True,
            sqlite_where=text("mode = 'baseline'"),
        ),
        Index(
            "uq_chat_conv_group_request",
            "comparison_group_id",
            "request_id",
            unique=True,
            sqlite_where=text("request_id IS NOT NULL"),
        ),
    )

    def __repr__(self) -> str:
        return f"<ChatConversation {self.id} job={self.job_id}>"


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(String, primary_key=True)
    conversation_id = Column(
        String,
        ForeignKey("chat_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    sequence = Column(Integer, nullable=False)
    role = Column(String, nullable=False)  # "user" or "assistant"
    content = Column(Text, nullable=False)
    citations_json = Column(Text, nullable=True)  # JSON blob
    metadata_json = Column(Text, nullable=True)  # JSON response provenance
    request_id = Column(String, nullable=True)
    created_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_chat_msg_conv", "conversation_id"),
        Index("uq_chat_msg_conv_sequence", "conversation_id", "sequence", unique=True),
        Index(
            "uq_chat_msg_conv_request",
            "conversation_id",
            "request_id",
            unique=True,
            sqlite_where=text("request_id IS NOT NULL"),
        ),
    )

    def __repr__(self) -> str:
        return f"<ChatMessage {self.id} role={self.role}>"


class ChatComparisonBranch(Base):
    __tablename__ = "chat_comparison_branches"

    id = Column(String, primary_key=True)
    group_id = Column(
        String,
        ForeignKey("chat_comparison_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    conversation_id = Column(
        String,
        ForeignKey("chat_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    label = Column(Text, nullable=False)
    source_message_id = Column(
        String,
        ForeignKey("chat_messages.id", ondelete="RESTRICT"),
        nullable=True,
    )
    history_cutoff_sequence = Column(Integer, nullable=False)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_chat_comparison_branch_group", "group_id"),
        Index("uq_chat_comparison_branch_conversation", "conversation_id", unique=True),
        Index(
            "uq_chat_comparison_snapshot_group",
            "group_id",
            unique=True,
            sqlite_where=text("source_message_id IS NULL"),
        ),
    )


@event.listens_for(Session, "before_flush")
def _assign_message_sequences(session: Session, _flush_context, _instances) -> None:
    """Give legacy message writes stable positions before batched inserts."""
    pending_by_conversation: dict[str, list[ChatMessage]] = defaultdict(list)
    explicit_maximums: dict[str, int] = {}
    for instance in session.new:
        if not isinstance(instance, ChatMessage):
            continue
        if instance.sequence is None:
            pending_by_conversation[instance.conversation_id].append(instance)
        else:
            explicit_maximums[instance.conversation_id] = max(
                explicit_maximums.get(instance.conversation_id, 0),
                instance.sequence,
            )

    for conversation_id, pending in pending_by_conversation.items():
        persisted_maximum = session.connection().scalar(
            select(func.max(ChatMessage.sequence)).where(
                ChatMessage.conversation_id == conversation_id
            )
        )
        next_sequence = max(
            persisted_maximum or 0,
            explicit_maximums.get(conversation_id, 0),
        ) + 1
        for message in sorted(pending, key=lambda item: (item.created_at, item.id)):
            message.sequence = next_sequence
            next_sequence += 1
