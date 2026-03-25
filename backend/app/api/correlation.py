"""Sprint 8 — Cross-Job Correlation API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, verify_token
from backend.app.schemas.correlation import CorrelationResponse, RelatedJobsResponse
from backend.app.services.correlation import get_correlations, get_related_jobs

router = APIRouter(tags=["correlation"])


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

