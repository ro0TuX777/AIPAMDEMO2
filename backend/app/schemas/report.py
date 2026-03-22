"""Report schemas — generated executive and analyst reports."""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.schemas.common import SCHEMA_VERSION

ReportMode = Literal["executive", "analyst"]


class ReportItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    mode: str
    title: str
    threat_level: str
    confidence: float
    content_markdown: str
    content_json: dict = Field(default_factory=dict)
    theory_count: int = 0
    slice_count: int = 0
    finding_count: int = 0
    alert_count: int = 0
    ioc_count: int = 0
    host_count: int = 0
    annotation_count: int = 0
    evidence_refs: list[str] = Field(default_factory=list)
    pcap_label: str | None = None
    created_at: str

    @field_validator("content_json", mode="before")
    @classmethod
    def _parse_content_json(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else {}
            except Exception:
                return {}
        return v or {}

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _parse_evidence_refs(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else []
            except Exception:
                return []
        return v or []


class ReportGenerateRequest(BaseModel):
    mode: ReportMode = "analyst"
    pcap_label: str | None = None


class ReportListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[ReportItem]
    job_id: str


class ReportDetailResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    item: ReportItem
    job_id: str

