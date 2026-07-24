"""
Raw event explorer endpoints (search, aggregation, flow visualization).

GET /jobs/{jobId}/raw-events            – search/filter/paginate normalized events
GET /jobs/{jobId}/raw-events/aggregate  – group events by a field (counts)
GET /jobs/{jobId}/raw-events/flow       – src -> dest -> port flow summary (Sankey)

Note: the base path is ``raw-events`` (not ``events``) because ``/jobs/{id}/events``
is already used by the jobs router for the SSE progress stream.
"""

from __future__ import annotations

import json
import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.schemas.events import (
    AggregationBucket,
    EventAggregationResponse,
    EventFlowResponse,
    FlowLink,
    FlowNode,
    RawEventItem,
    RawEventListResponse,
)

logger = logging.getLogger("aipam.events")

router = APIRouter(tags=["Events"], dependencies=[Depends(verify_token)])

# Columns the caller may filter on / aggregate by (allowlist for safety).
_FILTER_FIELDS = {
    "event_type", "source_type", "source_system", "hostname", "username",
    "src_ip", "dest_ip", "dest_port", "proto", "evidence_status",
}
_AGG_FIELDS = _FILTER_FIELDS | {"src_port"}
_SEARCH_COLUMNS = (
    "hostname", "username", "src_ip", "dest_ip", "proto", "event_type",
    "source_type", "source_system", "data_json",
)


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _to_item(ne: NormalizedEvent) -> RawEventItem:
    data: dict = {}
    if ne.data_json:
        try:
            parsed = json.loads(ne.data_json)
            if isinstance(parsed, dict):
                data = parsed
        except json.JSONDecodeError:
            pass
    tags: list[str] = []
    if ne.tags_json:
        try:
            parsed_tags = json.loads(ne.tags_json)
            if isinstance(parsed_tags, list):
                tags = [str(t) for t in parsed_tags]
        except json.JSONDecodeError:
            pass
    return RawEventItem(
        event_id=ne.event_id, event_type=ne.event_type, timestamp=ne.timestamp,
        source_type=ne.source_type, source_system=ne.source_system,
        hostname=ne.hostname, username=ne.username, src_ip=ne.src_ip,
        src_port=ne.src_port, dest_ip=ne.dest_ip, dest_port=ne.dest_port,
        proto=ne.proto, evidence_status=ne.evidence_status, tags=tags, data=data,
    )


@router.get("/jobs/{job_id}/raw-events", response_model=RawEventListResponse)
async def search_events(
    job_id: str,
    response: Response,
    q: str | None = Query(None, description="Substring search across key fields"),
    event_type: str | None = None,
    source_type: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    hostname: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Full-text (substring) search + structured filters over normalized events."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    conds = [NormalizedEvent.job_id == job_id]
    for field, val in (("event_type", event_type), ("source_type", source_type),
                       ("src_ip", src_ip), ("dest_ip", dest_ip), ("hostname", hostname)):
        if val is not None:
            conds.append(getattr(NormalizedEvent, field) == val)
    if q:
        like = f"%{q}%"
        conds.append(or_(*[getattr(NormalizedEvent, c).like(like) for c in _SEARCH_COLUMNS]))

    total = db.scalar(select(func.count()).select_from(NormalizedEvent).where(*conds)) or 0
    rows = db.scalars(
        select(NormalizedEvent).where(*conds)
        .order_by(NormalizedEvent.timestamp.desc()).limit(limit).offset(offset)
    ).all()
    return RawEventListResponse(
        items=[_to_item(r) for r in rows], total=total, limit=limit, offset=offset,
    )


@router.get("/jobs/{job_id}/raw-events/aggregate", response_model=EventAggregationResponse)
async def aggregate_events(
    job_id: str,
    response: Response,
    field: str = Query(..., description="Field to group by"),
    limit: int = Query(50, ge=1, le=500),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Group events by ``field`` and return value counts (descending)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    if field not in _AGG_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot aggregate by '{field}'. Allowed: {sorted(_AGG_FIELDS)}",
        )
    col = getattr(NormalizedEvent, field)
    rows = db.execute(
        select(col, func.count().label("c")).where(NormalizedEvent.job_id == job_id)
        .group_by(col).order_by(func.count().desc()).limit(limit)
    ).all()
    total = db.scalar(
        select(func.count()).select_from(NormalizedEvent)
        .where(NormalizedEvent.job_id == job_id)
    ) or 0
    buckets = [
        AggregationBucket(value=None if v is None else str(v), count=c) for v, c in rows
    ]
    return EventAggregationResponse(field=field, buckets=buckets, total_events=total)


@router.get("/jobs/{job_id}/raw-events/flow", response_model=EventFlowResponse)
async def event_flow(
    job_id: str,
    response: Response,
    limit: int = Query(50, ge=1, le=500, description="Top N links per stage"),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Summarize src_ip -> dest_ip -> dest_port flows for a Sankey diagram."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    rows = db.execute(
        select(NormalizedEvent.src_ip, NormalizedEvent.dest_ip, NormalizedEvent.dest_port)
        .where(NormalizedEvent.job_id == job_id,
               NormalizedEvent.src_ip.is_not(None),
               NormalizedEvent.dest_ip.is_not(None))
    ).all()

    stage1: Counter[tuple[str, str]] = Counter()
    stage2: Counter[tuple[str, str]] = Counter()
    for src_ip, dest_ip, dest_port in rows:
        stage1[(f"src:{src_ip}", f"host:{dest_ip}")] += 1
        if dest_port is not None:
            stage2[(f"host:{dest_ip}", f"port:{dest_port}")] += 1

    top1 = stage1.most_common(limit)
    top2 = stage2.most_common(limit)

    node_index: dict[str, int] = {}
    nodes: list[FlowNode] = []

    def _node(nid: str) -> int:
        if nid not in node_index:
            node_index[nid] = len(nodes)
            kind, label = nid.split(":", 1)
            nodes.append(FlowNode(id=nid, label=label, kind=kind))
        return node_index[nid]

    links: list[FlowLink] = []
    for (s, t), v in [*top1, *top2]:
        links.append(FlowLink(source=_node(s), target=_node(t), value=v))

    return EventFlowResponse(nodes=nodes, links=links, flows_considered=len(rows))
