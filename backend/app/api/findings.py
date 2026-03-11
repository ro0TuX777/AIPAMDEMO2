"""
Findings endpoints (§3.6).

GET   /jobs/{jobId}/findings                       – list findings
PATCH /jobs/{jobId}/findings/{findingId}/feedback – update analyst feedback
"""

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.api.pagination import paginate
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.schemas.common import Severity
from backend.app.schemas.finding import FindingFeedbackRequest, FindingItem, FindingListResponse

router = APIRouter(tags=["Findings"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _parse_finding_evidence(finding: Finding) -> Any | None:
    if not finding.evidence_json:
        return None
    try:
        return json.loads(finding.evidence_json)
    except (json.JSONDecodeError, TypeError):
        return None


def _finding_to_item(finding: Finding) -> FindingItem:
    return FindingItem(
        finding_id=finding.finding_id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        sensor=finding.sensor,
        pcap_label=finding.pcap_label,
        summary=finding.summary,
        evidence=_parse_finding_evidence(finding),
        feedback=finding.feedback,
    )


@router.get("/jobs/{job_id}/findings", response_model=FindingListResponse)
async def list_findings(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    severity: Severity | None = Query(None),
    category: str | None = Query(None),
    sensor: str | None = Query(None),
    search: str | None = Query(None, alias="q"),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    stmt = select(Finding).where(Finding.job_id == job_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.value)
    if category:
        stmt = stmt.where(Finding.category == category)
    if sensor:
        stmt = stmt.where(Finding.sensor == sensor)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.summary.ilike(pattern),
                Finding.category.ilike(pattern),
                Finding.sensor.ilike(pattern),
                Finding.pcap_label.ilike(pattern),
            )
        )

    items, page = paginate(db, stmt, Finding.id, Finding.id, cursor, limit)
    return FindingListResponse(
        items=[_finding_to_item(item) for item in items],
        page=page,
    )


@router.patch("/jobs/{job_id}/findings/{finding_id}/feedback", response_model=FindingItem)
async def update_finding_feedback(
    job_id: str,
    finding_id: str,
    body: FindingFeedbackRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    finding = db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id == finding_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.feedback = body.feedback
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return _finding_to_item(finding)
