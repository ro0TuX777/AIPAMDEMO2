"""Chat-related Pydantic schemas shared across api/chat.py and services/chat_citations.py."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ChatCitationOut(BaseModel):
    type: Literal[
        "finding", "alert", "host_summary", "knowledge_base", "code_evidence"
    ]
    id: str | None = None
    snippet: str


class HistoricalChatCitationOut(BaseModel):
    type: Literal["historical_finding"] = "historical_finding"
    id: str
    snippet: str
    source_job_id: str
    source_project_id: str | None
    href: str


ChatCitation = HistoricalChatCitationOut | ChatCitationOut


class ChatRequestBody(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    conversation_id: str | None = None
    context_hint: str | None = None
    mode: Literal["baseline", "mnemos"] = "baseline"
    request_id: str | None = None
    comparison_source_message_id: str | None = None


class EvidenceRefOut(BaseModel):
    type: str          # "host", "finding", "alert", "ioc"
    id: str | None = None
    label: str         # human-readable label, e.g. "Host 10.0.0.5"


class ChatResponseBody(BaseModel):
    response: str
    citations: list[ChatCitation] = []
    conversation_id: str
    confidence: float | None = None
    evidence_refs: list[EvidenceRefOut] = []
    suggested_followups: list[str] = []
    retrieval_status: Literal["used", "no_matches", "unavailable", "error"] | None = None
    model_id: str | None = None
    generation: dict[str, Any] | None = None


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
