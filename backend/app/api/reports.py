"""
Report API endpoints.

GET  /jobs/{jobId}/reports              – list reports for a job
GET  /jobs/{jobId}/reports/{reportId}   – get a single report
POST /jobs/{jobId}/reports/generate     – generate a new report
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.job import Job
from backend.app.models.report import Report
from backend.app.schemas.report import (
    ReportDetailResponse,
    ReportGenerateRequest,
    ReportItem,
    ReportListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Reports"], dependencies=[Depends(verify_token)])


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _report_to_item(r: Report) -> ReportItem:
    """Convert a Report ORM object to a schema item."""
    return ReportItem(
        report_id=r.report_id,
        mode=r.mode,
        title=r.title,
        threat_level=r.threat_level,
        confidence=r.confidence,
        content_markdown=r.content_markdown,
        content_json=r.content_json,
        theory_count=r.theory_count,
        slice_count=r.slice_count,
        finding_count=r.finding_count,
        alert_count=r.alert_count,
        ioc_count=r.ioc_count,
        host_count=r.host_count,
        annotation_count=r.annotation_count,
        evidence_refs=r.evidence_refs_json,
        pcap_label=r.pcap_label,
        created_at=r.created_at,
    )


@router.get("/jobs/{job_id}/reports", response_model=ReportListResponse)
async def list_reports(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    pcap_label: str | None = Query(None, description="Filter by PCAP label (before/after)"),
):
    """List all generated reports for a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(Report).where(Report.job_id == job_id)
    if pcap_label:
        q = q.where(Report.pcap_label == pcap_label)
    q = q.order_by(Report.created_at.desc())
    reports = db.execute(q).scalars().all()

    return ReportListResponse(
        items=[_report_to_item(r) for r in reports],
        job_id=job_id,
    )


@router.get("/jobs/{job_id}/reports/{report_id}", response_model=ReportDetailResponse)
async def get_report(
    job_id: str,
    report_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Get a single report by ID."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    report = db.execute(
        select(Report).where(Report.job_id == job_id, Report.report_id == report_id)
    ).scalars().first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportDetailResponse(
        item=_report_to_item(report),
        job_id=job_id,
    )


@router.post("/jobs/{job_id}/reports/generate", response_model=ReportDetailResponse)
async def generate_report_endpoint(
    job_id: str,
    body: ReportGenerateRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Generate a new report for a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.services.report_composer import generate_report

    report = generate_report(db, job_id, mode=body.mode, pcap_label=body.pcap_label)
    logger.info("Generated %s report %s for job %s", body.mode, report.report_id, job_id)

    return ReportDetailResponse(
        item=_report_to_item(report),
        job_id=job_id,
    )

