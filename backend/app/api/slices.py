"""
Incident Slicer API endpoints.

GET  /jobs/{jobId}/slices              – list slices for a job
GET  /jobs/{jobId}/slices/{sliceId}    – get a single slice
POST /jobs/{jobId}/slices/generate     – trigger slice generation
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.job import Job
from backend.app.models.slice import IncidentSlice
from backend.app.schemas.slice import SliceDetailResponse, SliceItem, SliceListResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Slices"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _slice_to_item(s: IncidentSlice) -> SliceItem:
    """Convert an IncidentSlice ORM object to a SliceItem schema."""
    def _load_json_list(raw: str | None) -> list[str]:
        if not raw:
            return []
        try:
            return json.loads(raw)
        except Exception:
            return []

    return SliceItem(
        slice_id=s.slice_id,
        label=s.label,
        slice_type=s.slice_type,
        severity=s.severity,
        confidence=s.confidence,
        community_ids=_load_json_list(s.community_ids_json),
        host_ips=_load_json_list(s.host_ips_json),
        time_start=s.time_start,
        time_end=s.time_end,
        alert_ids=_load_json_list(s.alert_ids_json),
        finding_ids=_load_json_list(s.finding_ids_json),
        ioc_ids=_load_json_list(s.ioc_ids_json),
        connection_ids=_load_json_list(s.connection_ids_json),
        summary=s.summary,
        rank=s.rank,
        created_at=s.created_at,
    )


@router.get("/jobs/{job_id}/slices", response_model=SliceListResponse)
async def list_slices(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List all incident slices for a job, ranked by significance."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    slices = db.execute(
        select(IncidentSlice)
        .where(IncidentSlice.job_id == job_id)
        .order_by(IncidentSlice.rank.asc())
    ).scalars().all()

    return SliceListResponse(
        items=[_slice_to_item(s) for s in slices],
        job_id=job_id,
    )


@router.get("/jobs/{job_id}/slices/{slice_id}", response_model=SliceDetailResponse)
async def get_slice(
    job_id: str,
    slice_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Get a single incident slice by ID."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    s = db.execute(
        select(IncidentSlice)
        .where(IncidentSlice.job_id == job_id, IncidentSlice.slice_id == slice_id)
    ).scalars().first()

    if not s:
        raise HTTPException(status_code=404, detail="Slice not found")

    return SliceDetailResponse(item=_slice_to_item(s), job_id=job_id)


@router.post("/jobs/{job_id}/slices/generate", response_model=SliceListResponse)
async def generate_slices_endpoint(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Manually trigger slice generation for a job (re-generates all)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.services.slicer import generate_slices

    slices = generate_slices(db, job_id)
    logger.info("Generated %d slices for job %s", len(slices), job_id)

    return SliceListResponse(
        items=[_slice_to_item(s) for s in slices],
        job_id=job_id,
    )

