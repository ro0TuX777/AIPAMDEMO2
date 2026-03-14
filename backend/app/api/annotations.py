"""
Context Annotation API endpoints.

GET  /jobs/{jobId}/annotations          – list annotations for a job
POST /jobs/{jobId}/annotations/generate – trigger annotation generation
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.job import Job
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.schemas.context_annotation import (
    ContextAnnotationItem,
    ContextAnnotationListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Annotations"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _ann_to_item(a: ContextAnnotation) -> ContextAnnotationItem:
    """Convert a ContextAnnotation ORM object to a schema item."""
    return ContextAnnotationItem(
        annotation_id=a.annotation_id,
        host_ip=a.host_ip,
        metric_name=a.metric_name,
        metric_category=a.metric_category,
        baseline_value=a.baseline_value,
        observed_value=a.observed_value,
        deviation_factor=a.deviation_factor,
        population_size=a.population_size,
        severity=a.severity,
        confidence=a.confidence,
        title=a.title,
        description=a.description,
        why_unusual=a.why_unusual,
        related_alert_ids=a.related_alert_ids_json,
        related_finding_ids=a.related_finding_ids_json,
        created_at=a.created_at,
    )


@router.get("/jobs/{job_id}/annotations", response_model=ContextAnnotationListResponse)
async def list_annotations(
    job_id: str,
    response: Response,
    host_ip: str | None = Query(None, description="Filter by host IP"),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List context annotations for a job, optionally filtered by host."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    query = select(ContextAnnotation).where(ContextAnnotation.job_id == job_id)
    if host_ip:
        query = query.where(ContextAnnotation.host_ip == host_ip)
    query = query.order_by(ContextAnnotation.severity.desc())

    annotations = db.execute(query).scalars().all()

    return ContextAnnotationListResponse(
        items=[_ann_to_item(a) for a in annotations],
        job_id=job_id,
    )


@router.post("/jobs/{job_id}/annotations/generate", response_model=ContextAnnotationListResponse)
async def generate_annotations_endpoint(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Manually trigger context annotation generation for a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.services.contextualizer import generate_annotations

    annotations = generate_annotations(db, job_id)
    logger.info("Generated %d annotations for job %s", len(annotations), job_id)

    return ContextAnnotationListResponse(
        items=[_ann_to_item(a) for a in annotations],
        job_id=job_id,
    )

