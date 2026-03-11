"""Finding schemas (openapi.yaml: FindingItem, FindingListResponse, FindingExplain*)."""

from typing import Any

from pydantic import BaseModel, ConfigDict

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo, Severity


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


class FindingFeedbackRequest(BaseModel):
    feedback: str | None  # confirmed, false_positive, false_negative


class FindingListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[FindingItem]
    page: PageInfo


class FindingExplainRequest(BaseModel):
    format: str  # "markdown" | "text"


class FindingExplainResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    format: str
    content: str

