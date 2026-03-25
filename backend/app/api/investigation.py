"""
Investigation Queue endpoints.

GET   /jobs/{jobId}/investigation-queue                          – ranked triage queue
GET   /jobs/{jobId}/review-queue                                 – review-focused queue with stats
GET   /jobs/{jobId}/investigation-queue/{itemId}/evidence-bundle – corroborating evidence
PATCH /jobs/{jobId}/investigation-queue/{itemId}/status          – update analyst status
POST  /jobs/{jobId}/investigation-queue/bulk-status              – bulk status update
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.models.theory import Theory
from backend.app.schemas.common import PageInfo
from backend.app.schemas.investigation import (
    AnalystStatus,
    BulkStatusUpdateRequest,
    BulkStatusUpdateResponse,
    EvidenceBundleResponse,
    InvestigationQueueResponse,
    QueueItemSource,
    ReviewQueueResponse,
    StatusUpdateRequest,
    StatusUpdateResponse,
)
from backend.app.services.ranking import build_investigation_queue, get_evidence_bundle

router = APIRouter(tags=["Investigation Queue"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _resolve_item(db: Session, job_id: str, item_id: str):
    """Parse 'source_type:source_id' and return (orm_object, source_type)."""
    if ":" not in item_id:
        raise HTTPException(status_code=400, detail=f"Invalid item_id format: {item_id}")

    source_type, source_id = item_id.split(":", 1)

    if source_type == "finding":
        obj = db.execute(
            select(Finding).where(Finding.job_id == job_id, Finding.finding_id == source_id)
        ).scalar_one_or_none()
    elif source_type == "alert":
        obj = db.execute(
            select(Alert).where(Alert.job_id == job_id, Alert.alert_id == source_id)
        ).scalar_one_or_none()
    elif source_type == "theory":
        obj = db.execute(
            select(Theory).where(Theory.job_id == job_id, Theory.theory_id == source_id)
        ).scalar_one_or_none()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}")

    if obj is None:
        raise HTTPException(status_code=404, detail=f"Item not found: {item_id}")

    return obj, source_type


@router.get("/jobs/{job_id}/investigation-queue", response_model=InvestigationQueueResponse)
async def get_investigation_queue(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    status_filter: AnalystStatus | None = Query(None, alias="status"),
    source: QueueItemSource | None = Query(None),
    severity: str | None = Query(None),
    search: str | None = Query(None, alias="q"),
    host: str | None = Query(None),
    mitre_id: str | None = Query(None),
    has_corroboration: bool | None = Query(None),
    reviewed: bool | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """Return the ranked investigation queue for a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    items, summary = build_investigation_queue(
        db,
        job_id,
        status_filter=status_filter,
        source_filter=source,
        severity_filter=severity,
        search=search,
        host_filter=host,
        mitre_filter=mitre_id,
        has_corroboration=has_corroboration,
        reviewed=reviewed,
    )

    # Paginate
    total = len(items)
    page_items = items[offset: offset + limit]
    has_more = (offset + limit) < total

    return InvestigationQueueResponse(
        items=page_items,
        page=PageInfo(
            has_more=has_more,
            next_cursor=str(offset + limit) if has_more else None,
        ),
        summary=summary,
    )


@router.get("/jobs/{job_id}/review-queue", response_model=ReviewQueueResponse)
async def get_review_queue(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    status_filter: AnalystStatus | None = Query(None, alias="status"),
    reviewer: str | None = Query(None),
    since: str | None = Query(None, description="ISO-8601 timestamp — show items reviewed after this time"),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """Return a review-focused view of the investigation queue with review statistics."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    items, summary = build_investigation_queue(db, job_id, status_filter=status_filter)

    # Apply review-specific filters
    if reviewer:
        items = [i for i in items if getattr(i, "reviewer_id", None) == reviewer]
    if since:
        items = [i for i in items if i.reviewed_at and i.reviewed_at >= since]

    # Paginate
    total = len(items)
    page_items = items[offset: offset + limit]
    has_more = (offset + limit) < total

    return ReviewQueueResponse(
        items=page_items,
        page=PageInfo(
            has_more=has_more,
            next_cursor=str(offset + limit) if has_more else None,
        ),
        stats=summary,
    )


@router.get(
    "/jobs/{job_id}/investigation-queue/{item_id}/evidence-bundle",
    response_model=EvidenceBundleResponse,
)
async def get_item_evidence_bundle(
    job_id: str,
    item_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Return corroborating evidence for a single queue item."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    # Validate the item exists
    obj, source_type = _resolve_item(db, job_id, item_id)

    # Build the queue item for the response
    from backend.app.services.ranking import (
        _alert_to_queue_item,
        _finding_to_queue_item,
        _theory_to_queue_item,
    )
    from datetime import timezone as _tz

    now = datetime.now(_tz.utc)
    if source_type == "finding":
        queue_item = _finding_to_queue_item(obj, db, now)
    elif source_type == "alert":
        queue_item = _alert_to_queue_item(obj, db, now)
    else:
        queue_item = _theory_to_queue_item(obj, db, now)

    bundle = get_evidence_bundle(db, job_id, item_id)

    return EvidenceBundleResponse(
        item=queue_item,
        **bundle,
    )


@router.patch(
    "/jobs/{job_id}/investigation-queue/{item_id}/status",
    response_model=StatusUpdateResponse,
)
async def update_item_status(
    job_id: str,
    item_id: str,
    body: StatusUpdateRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Update the analyst status of a single queue item."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    obj, source_type = _resolve_item(db, job_id, item_id)
    now = datetime.now(timezone.utc).isoformat()

    obj.analyst_status = body.analyst_status.value
    obj.analyst_notes = body.analyst_notes
    obj.reviewed_at = now
    obj.reviewer_id = body.reviewer_id
    db.commit()

    return StatusUpdateResponse(
        item_id=item_id,
        analyst_status=body.analyst_status,
        analyst_notes=body.analyst_notes,
        reviewer_id=body.reviewer_id,
        reviewed_at=now,
    )


@router.post(
    "/jobs/{job_id}/investigation-queue/bulk-status",
    response_model=BulkStatusUpdateResponse,
)
async def bulk_update_status(
    job_id: str,
    body: BulkStatusUpdateRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Bulk-update analyst status for multiple queue items."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    now = datetime.now(timezone.utc).isoformat()
    updated: list[str] = []
    failed: list[str] = []

    for iid in body.item_ids:
        try:
            obj, _ = _resolve_item(db, job_id, iid)
            obj.analyst_status = body.analyst_status.value
            obj.analyst_notes = body.analyst_notes
            obj.reviewed_at = now
            obj.reviewer_id = body.reviewer_id
            updated.append(iid)
        except HTTPException:
            failed.append(iid)

    db.commit()

    return BulkStatusUpdateResponse(
        updated=updated,
        failed=failed,
    )

