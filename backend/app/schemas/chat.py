"""Chat-related Pydantic schemas shared across api/chat.py and services/chat_citations.py."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


SourceId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, pattern=r"^[^/]+$"),
]


class ChatCitationOut(BaseModel):
    type: Literal[
        "finding", "alert", "host_summary", "knowledge_base", "code_evidence"
    ]
    id: str | None = None
    snippet: str


class HistoricalChatCitationOut(BaseModel):
    type: Literal["historical_finding"] = "historical_finding"
    id: SourceId
    snippet: str
    source_job_id: SourceId
    source_project_id: str | None
    href: str

    @model_validator(mode="after")
    def validate_finding_href(self) -> "HistoricalChatCitationOut":
        expected_href = f"/jobs/{self.source_job_id}/findings/{self.id}"
        if self.href != expected_href:
            raise ValueError("href must identify the cited source job and finding")
        return self


ChatCitation = HistoricalChatCitationOut | ChatCitationOut


class ChatGenerationMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    temperature: float
    max_tokens: int = Field(gt=0)


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
    generation: ChatGenerationMetadata | None = None


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
