"""Investigation Queue schemas — unified triage queue for findings, alerts, theories."""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.common import SCHEMA_VERSION, PageInfo, Severity


class AnalystStatus(str, Enum):
    unreviewed = "unreviewed"
    confirmed = "confirmed"
    false_positive = "false_positive"
    needs_review = "needs_review"
    deferred = "deferred"


class QueueItemSource(str, Enum):
    finding = "finding"
    alert = "alert"
    theory = "theory"


class InvestigationQueueItem(BaseModel):
    """A single item in the unified investigation queue."""
    model_config = ConfigDict(from_attributes=True)

    item_id: str                         # source-prefixed ID: "finding:F-001", "alert:A-55"
    source_type: QueueItemSource         # finding | alert | theory
    source_id: str                       # original ID in source table
    job_id: str

    # Display fields
    title: str
    severity: Severity
    confidence: float = 0.0
    category: str | None = None
    sensor: str | None = None            # analyzer source for findings, engine for alerts
    description: str | None = None
    pcap_label: str | None = None

    # Ranking
    rank_score: float = 0.0
    rank_position: int = 0               # 1-based position in queue

    # Sprint 2: enriched metadata
    corroborating_count: int = 0         # number of related items sharing hosts/community_ids
    affected_hosts: list[str] = Field(default_factory=list)  # list of IPs involved
    affected_hosts_count: int = 0        # len(affected_hosts)
    mitre_ids: list[str] = Field(default_factory=list)       # MITRE ATT&CK technique IDs

    # Analyst review state
    analyst_status: AnalystStatus = AnalystStatus.unreviewed
    analyst_notes: str | None = None
    reviewed_at: str | None = None
    reviewer_id: str | None = None

    # Extra context (varies by source type)
    extra: dict[str, Any] = Field(default_factory=dict)


class QueueSummary(BaseModel):
    """Counts by analyst_status for the summary bar."""
    total: int = 0
    unreviewed: int = 0
    confirmed: int = 0
    false_positive: int = 0
    needs_review: int = 0
    deferred: int = 0
    review_rate: float = 0.0  # fraction of items that have been reviewed (not unreviewed)


class InvestigationQueueResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    items: list[InvestigationQueueItem]
    page: PageInfo
    summary: QueueSummary


class ReviewQueueResponse(BaseModel):
    """Response for the review-queue endpoint — filtered view with review stats."""
    schema_version: str = SCHEMA_VERSION
    items: list[InvestigationQueueItem]
    page: PageInfo
    stats: QueueSummary


class StatusUpdateRequest(BaseModel):
    analyst_status: AnalystStatus
    analyst_notes: str | None = None
    reviewer_id: str | None = None


class StatusUpdateResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    item_id: str
    analyst_status: AnalystStatus
    analyst_notes: str | None = None
    reviewer_id: str | None = None
    reviewed_at: str


class BulkStatusUpdateRequest(BaseModel):
    item_ids: list[str]
    analyst_status: AnalystStatus
    analyst_notes: str | None = None
    reviewer_id: str | None = None


class BulkStatusUpdateResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    updated: list[str]
    failed: list[str] = Field(default_factory=list)


class EvidenceBundleResponse(BaseModel):
    """All corroborating evidence for a single queue item."""
    schema_version: str = SCHEMA_VERSION
    item: InvestigationQueueItem
    related_findings: list[dict[str, Any]] = Field(default_factory=list)
    related_alerts: list[dict[str, Any]] = Field(default_factory=list)
    related_connections: list[dict[str, Any]] = Field(default_factory=list)
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)

