"""Finding schemas (openapi.yaml: FindingItem, FindingListResponse, FindingExplain*)."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo, Severity


FindingExplanationFeedbackValue = Literal["useful", "not_useful"]


class FindingItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    title: str
    severity: Severity
    category: str | None = None
    sensor: str | None = None
    pcap_label: str | None = None
    summary: str | None = None
    evidence: dict[str, Any] | None = None
    feedback: str | None = None
    confidence: float = 0.0


class FindingRelatedHost(BaseModel):
    ip: str
    role: str | None = None
    conn_count: int | None = None
    alert_count: int | None = None
    finding_count: int | None = None


class FindingRelatedAlert(BaseModel):
    alert_id: str
    ts: str
    severity: Severity
    signature: str
    category: str | None = None
    host_ip: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    pcap_label: str | None = None


class FindingRelatedConnection(BaseModel):
    connection_id: str
    src_ip: str
    src_port: int | None = None
    dest_ip: str
    dest_port: int | None = None
    proto: str
    service: str | None = None
    ts: str
    pcap_label: str | None = None


class FindingFeedbackRequest(BaseModel):
    feedback: str | None  # confirmed, false_positive, false_negative


class FindingExplainFeedbackRequest(BaseModel):
    explanation_feedback: FindingExplanationFeedbackValue | None


class FindingExplainFeedbackResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    explanation_feedback: FindingExplanationFeedbackValue | None = None


class FindingListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[FindingItem]
    page: PageInfo


class FindingDetailResponse(FindingItem):
    community_id: str | None = None
    explanation_feedback: FindingExplanationFeedbackValue | None = None
    related_hosts: list[FindingRelatedHost] = Field(default_factory=list)
    related_alerts: list[FindingRelatedAlert] = Field(default_factory=list)
    related_connections: list[FindingRelatedConnection] = Field(default_factory=list)


class FindingExplainRequest(BaseModel):
    format: str  # "markdown" | "text"


class FindingExplainSection(BaseModel):
    id: Literal["assessment", "why_it_matters", "recommended_next_steps"]
    title: str
    body: str | None = None
    bullets: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)


class FindingExplainEvidenceItem(BaseModel):
    label: str
    value: str
    citation: str


class FindingExplainResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    format: str
    content: str
    duration_ms: int
    source: Literal["deterministic", "llm", "fallback"]
    warning: str | None = None
    explanation_feedback: FindingExplanationFeedbackValue | None = None
    sections: list[FindingExplainSection] = Field(default_factory=list)
    evidence_items: list[FindingExplainEvidenceItem] = Field(default_factory=list)

