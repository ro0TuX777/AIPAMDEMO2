"""Chat-related Pydantic schemas shared across api/chat.py and services/chat_citations.py."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)


def _reject_dot_path_segment(value: str) -> str:
    if value in {".", ".."}:
        raise ValueError("source identifiers cannot be dot path segments")
    return value


SourceId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    AfterValidator(_reject_dot_path_segment),
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
    source_content_sha256: str | None = None
    # Live availability never replaces the saved retrieval outcome or excerpt.
    source_availability: Literal["available", "changed", "unavailable", "unknown"] = "unknown"

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
    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    comparison_source_message_id: str | None = None


class ChatComparisonCreateRequest(BaseModel):
    root_conversation_id: str = Field(..., min_length=1)


class ChatComparisonBranchCreateRequest(BaseModel):
    source_message_id: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1, max_length=128)


class ChatComparisonActiveBranchRequest(BaseModel):
    active_branch_id: str = Field(..., min_length=1)


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
    branch_id: str | None = None
    request_id: str | None = None
    status: Literal["pending", "completed", "error"] = "completed"
    retry_after_seconds: int | None = None
    receipt_id: str | None = None


class ChatMessageOut(BaseModel):
    id: str
    sequence: int
    role: Literal["user", "assistant"]
    content: str
    citations: list[ChatCitation] = Field(default_factory=list)
    metadata: dict | None = None
    request_id: str | None = None
    timestamp: str


class ChatComparisonBranchOut(BaseModel):
    id: str
    conversation_id: str
    label: str
    source_message_id: str | None = None
    request_id: str | None = None
    history_cutoff_sequence: int
    created_at: str
    updated_at: str
    messages: list[ChatMessageOut] = Field(default_factory=list)
    # Read-only root prefix selected and validated by the server's cutoff rule.
    inherited_root_conversation_id: str | None = None
    inherited_cutoff_sequence: int | None = None
    inherited_messages: list[ChatMessageOut] = Field(default_factory=list)


class ChatComparisonGroupOut(BaseModel):
    group_id: str
    job_id: str
    root_conversation_id: str
    title: str | None = None
    snapshot_branch_id: str
    active_branch_id: str
    conversation_id: str
    created_at: str
    updated_at: str
    branches: list[ChatComparisonBranchOut] = Field(default_factory=list)


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
