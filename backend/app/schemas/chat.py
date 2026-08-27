"""Chat-related Pydantic schemas shared across api/chat.py and services/chat_citations.py."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ChatCitationOut(BaseModel):
    type: str  # "finding", "alert", "host_summary", "knowledge_base", "code_evidence"
    id: str | None = None
    snippet: str


class ChatRequestBody(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    conversation_id: str | None = None
    context_hint: str | None = None


class EvidenceRefOut(BaseModel):
    type: str          # "host", "finding", "alert", "ioc"
    id: str | None = None
    label: str         # human-readable label, e.g. "Host 10.0.0.5"


class ChatResponseBody(BaseModel):
    response: str
    citations: list[ChatCitationOut] = []
    conversation_id: str
    confidence: float | None = None
    evidence_refs: list[EvidenceRefOut] = []
    suggested_followups: list[str] = []


class ConversationSummaryOut(BaseModel):
    id: str
    job_id: str
    created_at: str
    updated_at: str
    title: str | None = None
    message_count: int


class ConversationHistoryOut(BaseModel):
    id: str
    job_id: str
    messages: list[dict]
    created_at: str
    updated_at: str


class ConversationRenameRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)

