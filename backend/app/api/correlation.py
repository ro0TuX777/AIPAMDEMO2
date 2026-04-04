"""Sprint 8 — Cross-Job Correlation API endpoints + Telemetry Correlation."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, verify_token
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.schemas.correlation import CorrelationResponse, RelatedJobsResponse
from backend.app.services.correlation import get_correlations, get_related_jobs
from backend.app.services.telemetry_correlator import (
    build_correlation_clusters,
    correlate_and_upgrade,
)

router = APIRouter(tags=["correlation"])


# ── Cross-job correlation endpoints (Sprint 8) ────────────────────────


@router.get(
    "/jobs/{job_id}/correlations",
    response_model=CorrelationResponse,
    summary="Cross-job correlations for a job",
)
def job_correlations(
    job_id: str,
    item_id: str | None = Query(None, description="Specific queue item to correlate"),
    host: str | None = Query(None, description="Specific IP to correlate"),
    ioc: str | None = Query(None, description="Specific IOC value to correlate"),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _token: str = Depends(verify_token),
) -> CorrelationResponse:
    return get_correlations(db, job_id, item_id=item_id, host=host, ioc=ioc, limit=limit)


@router.get(
    "/jobs/{job_id}/related-jobs",
    response_model=RelatedJobsResponse,
    summary="Jobs related to this one via shared entities",
)
def related_jobs(
    job_id: str,
    db: Session = Depends(get_db),
    _token: str = Depends(verify_token),
) -> RelatedJobsResponse:
    return get_related_jobs(db, job_id)


# ── Telemetry correlation endpoints ───────────────────────────────────


class TelemetryEventOut(BaseModel):
    """Single normalized telemetry event."""

    event_id: str
    event_type: str
    timestamp: str
    source_system: str | None = None
    source_filename: str | None = None
    evidence_status: str
    corroboration_score: float = 0.0
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    hostname: str | None = None
    username: str | None = None
    proto: str | None = None
    community_id: str | None = None


class TelemetryClusterOut(BaseModel):
    """A cluster of correlated telemetry events."""

    event_ids: list[str] = Field(default_factory=list)
    shared_keys: dict[str, list[str]] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    score: float = 0.0
    size: int = 0


class TelemetryCorrelationResponse(BaseModel):
    """Response for ``GET /jobs/{job_id}/telemetry``."""

    job_id: str
    total_events: int = 0
    events: list[TelemetryEventOut] = Field(default_factory=list)
    clusters: list[TelemetryClusterOut] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


def _event_to_out(evt: NormalizedEvent) -> TelemetryEventOut:
    return TelemetryEventOut(
        event_id=evt.event_id,
        event_type=evt.event_type,
        timestamp=evt.timestamp or "",
        source_system=evt.source_system,
        source_filename=evt.source_filename,
        evidence_status=evt.evidence_status or "observed",
        corroboration_score=evt.corroboration_score or 0.0,
        src_ip=evt.src_ip,
        dest_ip=evt.dest_ip,
        src_port=evt.src_port,
        dest_port=evt.dest_port,
        hostname=evt.hostname,
        username=evt.username,
        proto=evt.proto,
        community_id=evt.community_id,
    )


@router.get(
    "/jobs/{job_id}/telemetry",
    response_model=TelemetryCorrelationResponse,
    summary="Telemetry events and correlation clusters for a job",
)
def job_telemetry(
    job_id: str,
    status: str | None = Query(None, description="Filter by evidence_status (observed, corroborated)"),
    source: str | None = Query(None, description="Filter by source_system"),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    _token: str = Depends(verify_token),
) -> TelemetryCorrelationResponse:
    """Return normalized telemetry events and their correlation clusters."""
    q = select(NormalizedEvent).where(NormalizedEvent.job_id == job_id)
    if status:
        q = q.where(NormalizedEvent.evidence_status == status)
    if source:
        q = q.where(NormalizedEvent.source_system == source)
    q = q.limit(limit)

    events = list(db.execute(q).scalars().all())
    clusters = build_correlation_clusters(events) if events else []

    # Summarize stats
    source_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for evt in events:
        src = evt.source_system or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1
        st = evt.evidence_status or "observed"
        status_counts[st] = status_counts.get(st, 0) + 1

    return TelemetryCorrelationResponse(
        job_id=job_id,
        total_events=len(events),
        events=[_event_to_out(e) for e in events],
        clusters=[
            TelemetryClusterOut(
                event_ids=sorted(c["event_ids"]),
                shared_keys=c["shared_keys"],
                sources=sorted(c["sources"]),
                score=c["score"],
                size=c["size"],
            )
            for c in clusters
        ],
        stats={
            "by_source": source_counts,
            "by_status": status_counts,
            "cluster_count": len(clusters),
            "multi_source_clusters": sum(1 for c in clusters if len(c["sources"]) > 1),
        },
    )


@router.post(
    "/jobs/{job_id}/telemetry/correlate",
    response_model=dict,
    summary="Run telemetry correlation for a job (upgrades observed → corroborated)",
)
def run_telemetry_correlation(
    job_id: str,
    db: Session = Depends(get_db),
    _token: str = Depends(verify_token),
) -> dict[str, Any]:
    """Trigger correlation and evidence upgrade for all telemetry in a job."""
    return correlate_and_upgrade(job_id, db)


# ── Single telemetry event detail ──────────────────────────────────


class TelemetryEventDetail(BaseModel):
    """Full detail for a single normalized telemetry event."""

    event_id: str
    event_type: str
    timestamp: str
    source_type: str | None = None
    source_system: str | None = None
    source_filename: str | None = None
    parser_name: str | None = None
    parser_version: str | None = None
    evidence_status: str
    corroboration_score: float = 0.0
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    hostname: str | None = None
    username: str | None = None
    proto: str | None = None
    community_id: str | None = None
    session_id: str | None = None
    process_guid: str | None = None
    pcap_label: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    correlation_keys: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    raw_ref: str | None = None


@router.get(
    "/jobs/{job_id}/telemetry/{event_id}",
    response_model=TelemetryEventDetail,
    summary="Get full detail for a single telemetry event",
)
def get_telemetry_event(
    job_id: str,
    event_id: str,
    db: Session = Depends(get_db),
    _token: str = Depends(verify_token),
) -> TelemetryEventDetail:
    """Return full detail for a single NormalizedEvent by event_id."""
    evt = db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_id == event_id,
        )
    ).scalar_one_or_none()
    if not evt:
        raise HTTPException(status_code=404, detail="Telemetry event not found")

    data: dict[str, Any] = {}
    if evt.data_json:
        try:
            data = json.loads(evt.data_json)
        except Exception:
            data = {"_raw": evt.data_json}

    corr_keys: dict[str, Any] = {}
    if evt.correlation_keys_json:
        try:
            corr_keys = json.loads(evt.correlation_keys_json)
        except Exception:
            pass

    tags: list[str] = []
    if evt.tags_json:
        try:
            tags = json.loads(evt.tags_json)
        except Exception:
            pass

    return TelemetryEventDetail(
        event_id=evt.event_id,
        event_type=evt.event_type,
        timestamp=evt.timestamp or "",
        source_type=evt.source_type,
        source_system=evt.source_system,
        source_filename=evt.source_filename,
        parser_name=evt.parser_name,
        parser_version=evt.parser_version,
        evidence_status=evt.evidence_status or "observed",
        corroboration_score=evt.corroboration_score or 0.0,
        src_ip=evt.src_ip,
        dest_ip=evt.dest_ip,
        src_port=evt.src_port,
        dest_port=evt.dest_port,
        hostname=evt.hostname,
        username=evt.username,
        proto=evt.proto,
        community_id=evt.community_id,
        session_id=evt.session_id,
        process_guid=evt.process_guid,
        pcap_label=evt.pcap_label,
        data=data,
        correlation_keys=corr_keys,
        tags=tags,
        raw_ref=evt.raw_ref,
    )

