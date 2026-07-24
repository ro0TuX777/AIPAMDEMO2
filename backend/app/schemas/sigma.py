"""Sigma detection schemas (first-class log analysis)."""

from typing import Any

from pydantic import BaseModel

from backend.app.schemas.common import SCHEMA_VERSION, Severity


class SigmaDetectionItem(BaseModel):
    """One Sigma detection persisted as a first-class finding."""

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    category: str | None = None
    tags: list[str] = []
    event_id: str | None = None
    hostname: str | None = None
    timestamp: str | None = None
    evidence: dict[str, Any] | None = None


class SigmaDetectionListResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[SigmaDetectionItem]
    total: int


class SigmaAnalyzeResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    rules_evaluated: int
    events_scanned: int
    detections_created: int
    detections_total: int
    items: list[SigmaDetectionItem]
