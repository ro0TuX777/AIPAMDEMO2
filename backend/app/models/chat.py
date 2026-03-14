"""Chat conversation and message models for V2."""

from sqlalchemy import Column, ForeignKey, Index, String, Text

from backend.app.database_v2 import Base


class ChatConversation(Base):
    __tablename__ = "chat_conversations"

    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"), nullable=False)
    title = Column(Text, nullable=True)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_chat_conv_job", "job_id"),
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
    role = Column(String, nullable=False)  # "user" or "assistant"
    content = Column(Text, nullable=False)
    citations_json = Column(Text, nullable=True)  # JSON blob
    created_at = Column(String, nullable=False)

    __table_args__ = (
        Index("idx_chat_msg_conv", "conversation_id"),
    )

    def __repr__(self) -> str:
        return f"<ChatMessage {self.id} role={self.role}>"

