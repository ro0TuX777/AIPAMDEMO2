"""Sprint 8 — Cross-Job Correlation schemas.

Pydantic models for the correlation and related-jobs endpoints.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ── Match types ───────────────────────────────────────────────────────

MatchType = Literal["same_host", "same_ioc", "same_mitre", "similar_pattern"]
OverlapType = Literal["shared_hosts", "shared_iocs", "shared_mitre"]


class CorrelationMatch(BaseModel):
    """A single cross-job entity match."""

    job_id: str
    job_name: str
    job_created_at: str | None = None
    match_type: MatchType
    matched_entity: str          # the IP / IOC value / MITRE category that matched
    matched_item_id: str | None = None  # finding:xxx or alert:xxx in the other job
    matched_title: str | None = None
    similarity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    context: str = ""            # human-readable explanation


class CampaignCandidate(BaseModel):
    """A cluster of jobs that may belong to the same campaign."""

    campaign_id: str
    label: str
    job_ids: list[str] = Field(default_factory=list)
    shared_iocs: list[str] = Field(default_factory=list)
    shared_hosts: list[str] = Field(default_factory=list)
    shared_mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class CorrelationQuery(BaseModel):
    """Echo of the query parameters for the correlation request."""

    job_id: str
    item_id: str | None = None
    host: str | None = None
    ioc: str | None = None


class CorrelationResponse(BaseModel):
    """Top-level response for ``GET /jobs/{job_id}/correlations``."""

    query: CorrelationQuery
    matches: list[CorrelationMatch] = Field(default_factory=list)
    campaigns: list[CampaignCandidate] = Field(default_factory=list)
    total_matches: int = 0


class RelatedJob(BaseModel):
    """A job related to the current one via shared entities."""

    job_id: str
    job_name: str
    job_created_at: str | None = None
    overlap_type: OverlapType
    shared_entities: list[str] = Field(default_factory=list)
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)


class RelatedJobsResponse(BaseModel):
    """Response for ``GET /jobs/{job_id}/related-jobs``."""

    job_id: str
    related_jobs: list[RelatedJob] = Field(default_factory=list)

