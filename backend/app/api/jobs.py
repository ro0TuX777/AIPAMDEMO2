"""
Job endpoints (§1.3 + §3.3 + §3.4 + §3.8).

POST /jobs                     – create a job from an upload
GET  /jobs                     – list jobs with cursor pagination
GET  /jobs/{id}                – get job detail
DELETE /jobs/{id}              – delete a job
POST /jobs/{id}/cancel         – cancel a running job
POST /jobs/{id}/rerun          – rerun a job
POST /jobs/batch               – batch operations
GET  /jobs/{id}/summary        – job summary
GET  /jobs/{id}/sensors        – sensor list
GET  /jobs/{id}/timeline       – timeline events
GET  /jobs/{id}/iocs           – IOC list
GET  /jobs/{id}/events         – SSE stream
GET  /jobs/{id}/partial-results – early partial pipeline results
"""

import asyncio
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token, verify_token_or_query
from backend.app.api.pagination import paginate
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.file import File
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.sensor import JobSensor
from backend.app.models.timeline import TimelineEvent
from backend.app.models.theory import Theory
from backend.app.models.upload import Upload
from backend.app.schemas.common import (
    ExecutionProfile,
    JobStatus,
    PageInfo,
)
from backend.app.schemas.file import FileItem, FileListResponse
from backend.app.schemas.host import HostListItem
from backend.app.schemas.ioc import IocItem, IocListResponse
from backend.app.schemas.job import (
    EvidenceGraphResponse,
    GraphEdge,
    GraphNode,
    JobCreateRequest,
    JobCreateResponse,
    JobDetail,
    JobGetResponse,
    JobGraphResponse,
    JobListItem,
    JobListResponse,
    JobPcapItem,
    PcapUploadItem,
    SensorItem,
    SensorListResponse,
    SensorProvenance,
    SensorStats,
)
from backend.app.schemas.system import (
    BatchJobsRequest,
    BatchJobsResponse,
    JobSummaryResponse,
    RejectedJob,
)
from backend.app.schemas.timeline import TimelineItem, TimelineListResponse

router = APIRouter(tags=["Jobs"], dependencies=[Depends(verify_token)])

# Separate router for SSE endpoint — no router-level verify_token because
# EventSource cannot send Authorization headers.  Auth is handled per-endpoint
# via verify_token_or_query (header OR ?token= query param).
sse_router = APIRouter(tags=["Jobs"])

import logging as _logging

_logger = _logging.getLogger("aipam.api.jobs")


def _dispatch_job(job_id: str) -> None:
    """Send the job to the Celery worker. Logs a warning on failure (e.g. no Redis)."""
    try:
        from backend.app.worker import run_job
        run_job.delay(job_id)
    except Exception as exc:
        _logger.warning("Failed to dispatch job %s to Celery: %s", job_id, exc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------- POST /jobs ----------

MAX_PCAPS_PER_JOB = 10
MAX_PCAP_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB per file
MAX_TOTAL_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB total per job


def _resolve_upload_list(body: JobCreateRequest) -> list[PcapUploadItem]:
    """Normalize old single-upload and new multi-upload request formats."""
    if body.uploads:
        return body.uploads
    if body.upload_id:
        return [PcapUploadItem(upload_id=body.upload_id)]
    raise HTTPException(status_code=400, detail="Provide upload_id or uploads[]")


@router.post("/jobs", status_code=status.HTTP_201_CREATED, response_model=JobCreateResponse)
async def create_job(
    body: JobCreateRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Create a new analysis job from one or more validated uploads."""
    response.headers["X-Request-Id"] = request_id

    upload_items = _resolve_upload_list(body)

    if len(upload_items) > MAX_PCAPS_PER_JOB:
        raise HTTPException(status_code=400, detail=f"Max {MAX_PCAPS_PER_JOB} PCAPs per job")

    # Verify all uploads exist and accumulate total size
    uploads: list[Upload] = []
    total_size = 0
    for item in upload_items:
        upload: Upload | None = db.get(Upload, item.upload_id)
        if upload is None:
            raise HTTPException(status_code=400, detail=f"Upload {item.upload_id} not found")
        total_size += upload.size_bytes or 0
        uploads.append(upload)

    if total_size > MAX_TOTAL_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"Total PCAP size exceeds {MAX_TOTAL_SIZE_BYTES // (1024**3)} GB limit")

    job_id = str(uuid.uuid4())

    # Create job directory
    job_dir: Path = settings.aipam_job_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    # Use first PCAP for backward-compat fields on the Job model
    first_upload = uploads[0]
    job = Job(
        job_id=job_id,
        job_name=body.job_name,
        notes=body.notes,
        status="queued",
        execution_profile=body.execution_profile.value,
        priority=body.priority.value,
        upload_id=first_upload.upload_id,
        pcap_filename=first_upload.filename if len(uploads) == 1 else f"{len(uploads)} PCAPs",
        pcap_size_bytes=total_size,
        pcap_sha256=first_upload.sha256 if len(uploads) == 1 else None,
        created_at=_now_iso(),
    )
    db.add(job)

    # Create JobPcap records
    for ordinal, (item, upload) in enumerate(zip(upload_items, uploads)):
        pcap_rec = JobPcap(
            job_id=job_id,
            upload_id=upload.upload_id,
            label=item.label,
            filename=upload.filename,
            ordinal=ordinal,
            size_bytes=upload.size_bytes,
            sha256=upload.sha256,
        )
        db.add(pcap_rec)

    db.commit()

    # Dispatch the pipeline to the Celery worker
    _dispatch_job(job_id)

    return JobCreateResponse(schema_version="1.0", job_id=job_id)


# ---------- GET /jobs ----------

@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    status_filter: JobStatus | None = Query(None, alias="status"),
    profile: ExecutionProfile | None = Query(None),
    q: str | None = Query(None),
):
    """List jobs with cursor pagination, filters, and search."""
    response.headers["X-Request-Id"] = request_id

    query = select(Job)

    # Filters
    if status_filter is not None:
        query = query.where(Job.status == status_filter.value)
    if profile is not None:
        query = query.where(Job.execution_profile == profile.value)
    if q:
        query = query.where(Job.job_name.ilike(f"%{q}%"))

    items, page = paginate(db, query, Job.created_at, Job.job_id, cursor, limit, order)
    return JobListResponse(
        items=[JobListItem.model_validate(j) for j in items],
        page=page,
    )


# ---------- GET /jobs/{jobId} ----------

@router.get("/jobs/{job_id}", response_model=JobGetResponse)
async def get_job(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Get full job detail including metrics, stages, sensors."""
    response.headers["X-Request-Id"] = request_id

    job: Job | None = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    detail = JobDetail.model_validate(job)

    # Attach per-job PCAP records
    pcap_rows = db.execute(
        select(JobPcap).where(JobPcap.job_id == job_id).order_by(JobPcap.ordinal)
    ).scalars().all()
    detail.pcaps = [JobPcapItem.model_validate(r) for r in pcap_rows]

    return JobGetResponse(job=detail)



def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _safe_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


# ---------- DELETE /jobs/{jobId} ----------

@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Delete a job and its data."""
    job = _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    if job.status in ("running",):
        raise HTTPException(status_code=409, detail="Cannot delete a running job; cancel it first")

    job.status = "deleted"
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------- POST /jobs/{jobId}/cancel ----------

@router.post("/jobs/{job_id}/cancel", response_model=JobGetResponse)
async def cancel_job(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Cancel a queued or running job."""
    job = _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    if job.status not in ("queued", "running"):
        raise HTTPException(status_code=409, detail=f"Cannot cancel job in '{job.status}' state")

    job.status = "canceled"
    job.completed_at = _now_iso()
    db.commit()
    db.refresh(job)

    return JobGetResponse(job=JobDetail.model_validate(job))


# ---------- POST /jobs/{jobId}/rerun ----------

@router.post("/jobs/{job_id}/rerun", status_code=status.HTTP_201_CREATED, response_model=JobCreateResponse)
async def rerun_job(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Rerun a completed/failed job by creating a new job with the same parameters."""
    old = _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    new_id = str(uuid.uuid4())
    job_dir: Path = settings.aipam_job_root / new_id
    job_dir.mkdir(parents=True, exist_ok=True)

    new_job = Job(
        job_id=new_id,
        job_name=f"Rerun of {old.job_name or old.job_id}",
        notes=f"Rerun of job {old.job_id}",
        status="queued",
        execution_profile=old.execution_profile,
        priority=old.priority,
        upload_id=old.upload_id,
        pcap_filename=old.pcap_filename,
        pcap_size_bytes=old.pcap_size_bytes,
        pcap_sha256=old.pcap_sha256,
        created_at=_now_iso(),
    )
    db.add(new_job)

    # Copy JobPcap records from the old job
    old_pcaps = db.execute(
        select(JobPcap).where(JobPcap.job_id == old.job_id).order_by(JobPcap.ordinal)
    ).scalars().all()
    for p in old_pcaps:
        db.add(JobPcap(
            job_id=new_id, upload_id=p.upload_id, label=p.label,
            filename=p.filename, ordinal=p.ordinal,
            size_bytes=p.size_bytes, sha256=p.sha256,
        ))

    db.commit()

    # Dispatch the pipeline to the Celery worker
    _dispatch_job(new_id)

    return JobCreateResponse(schema_version="1.0", job_id=new_id)


# ---------- GET /jobs/{jobId}/pcaps ----------

@router.get("/jobs/{job_id}/pcaps")
async def list_job_pcaps(
    job_id: str,
    db: Session = Depends(get_db),
):
    """List all PCAP files associated with a job."""
    _require_job(db, job_id)
    rows = db.execute(
        select(JobPcap).where(JobPcap.job_id == job_id).order_by(JobPcap.ordinal)
    ).scalars().all()
    return {"items": [JobPcapItem.model_validate(r) for r in rows]}


# ---------- POST /jobs/{jobId}/pcaps ----------

@router.post("/jobs/{job_id}/pcaps", status_code=status.HTTP_201_CREATED)
async def add_job_pcap(
    job_id: str,
    body: PcapUploadItem,
    db: Session = Depends(get_db),
):
    """Attach an additional PCAP to an existing job (queued, completed, or failed)."""
    job = _require_job(db, job_id)
    if job.status not in ("queued", "completed", "completed_with_errors", "failed"):
        raise HTTPException(status_code=409, detail="Can only add PCAPs to queued, completed, or failed jobs")

    upload: Upload | None = db.get(Upload, body.upload_id)
    if upload is None:
        raise HTTPException(status_code=400, detail="Upload not found")

    # Count existing pcaps
    count = db.execute(
        select(func.count()).select_from(JobPcap).where(JobPcap.job_id == job_id)
    ).scalar() or 0
    if count >= MAX_PCAPS_PER_JOB:
        raise HTTPException(status_code=400, detail=f"Max {MAX_PCAPS_PER_JOB} PCAPs per job")

    # Auto-label existing unlabeled PCAPs as "before" when adding a labeled PCAP
    if body.label:
        unlabeled = db.execute(
            select(JobPcap).where(JobPcap.job_id == job_id, JobPcap.label.is_(None))
        ).scalars().all()
        if unlabeled:
            for p in unlabeled:
                p.label = "before"

    pcap_rec = JobPcap(
        job_id=job_id,
        upload_id=upload.upload_id,
        label=body.label,
        filename=upload.filename,
        ordinal=count,
        size_bytes=upload.size_bytes,
        sha256=upload.sha256,
    )
    db.add(pcap_rec)

    # Update job-level summary
    job.pcap_filename = f"{count + 1} PCAPs"
    job.pcap_size_bytes = (job.pcap_size_bytes or 0) + (upload.size_bytes or 0)
    db.commit()

    return JobPcapItem.model_validate(pcap_rec)


# ---------- POST /jobs/{jobId}/reanalyze ----------

class ReanalyzeRequest(BaseModel):
    """Request body for re-analysis of specific PCAP labels."""
    pcap_label: str = Field(..., description="The PCAP label/phase to re-analyze (e.g. 'after')")


@router.post("/jobs/{job_id}/reanalyze", status_code=status.HTTP_202_ACCEPTED)
async def reanalyze_job(
    job_id: str,
    body: ReanalyzeRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Trigger re-analysis on PCAPs with a specific label within a completed job.

    This allows temporal "Before/After" analysis: after adding new PCAPs
    labeled "after" to a completed job, this endpoint triggers the pipeline
    on just those PCAPs, producing evidence tagged with the given pcap_label.
    """
    job = _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    if job.status not in ("completed", "completed_with_errors", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Can only re-analyze completed or failed jobs (current: {job.status})"
        )

    # Verify PCAPs with this label exist
    label_count = db.execute(
        select(func.count()).select_from(JobPcap).where(
            JobPcap.job_id == job_id,
            JobPcap.label == body.pcap_label,
        )
    ).scalar() or 0

    if label_count == 0:
        raise HTTPException(
            status_code=400,
            detail=f"No PCAPs with label '{body.pcap_label}' found for this job"
        )

    # Update job status to re-running
    job.status = "running"
    job.error_summary = None
    db.commit()

    # Dispatch with pcap_label so the worker knows to only process that phase
    try:
        from backend.app.worker import run_job_phase
        run_job_phase.delay(job_id, body.pcap_label)
    except Exception as exc:
        _logger.warning("Failed to dispatch reanalyze for job %s: %s", job_id, exc)
        job.status = "failed"
        job.error_summary = f"Failed to dispatch re-analysis: {exc}"
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to dispatch re-analysis task")

    return {"job_id": job_id, "pcap_label": body.pcap_label, "status": "running", "pcap_count": label_count}


# ---------- POST /jobs/batch ----------

@router.post("/jobs/batch", response_model=BatchJobsResponse)
async def batch_jobs(
    body: BatchJobsRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Batch operations: cancel, delete, export_iocs."""
    response.headers["X-Request-Id"] = request_id

    accepted: list[str] = []
    rejected: list[RejectedJob] = []
    all_iocs: list[IocItem] = []

    for jid in body.job_ids:
        job = db.get(Job, jid)
        if not job:
            rejected.append(RejectedJob(job_id=jid, reason="Job not found"))
            continue

        if body.action == "cancel":
            if job.status in ("queued", "running"):
                job.status = "canceled"
                job.completed_at = _now_iso()
                accepted.append(jid)
            else:
                rejected.append(RejectedJob(job_id=jid, reason=f"Cannot cancel: status={job.status}"))
        elif body.action == "delete":
            if job.status != "running":
                job.status = "deleted"
                accepted.append(jid)
            else:
                rejected.append(RejectedJob(job_id=jid, reason="Cannot delete running job"))
        elif body.action == "export_iocs":
            accepted.append(jid)
            iocs = db.execute(select(Ioc).where(Ioc.job_id == jid)).scalars().all()
            for i in iocs:
                all_iocs.append(IocItem(
                    ioc_id=i.ioc_id, type=i.ioc_type, value=i.value,
                    confidence=i.confidence,
                    sources=_safe_json_list(i.sources_json),
                ))
        else:
            rejected.append(RejectedJob(job_id=jid, reason=f"Unknown action: {body.action}"))

    db.commit()

    export = None
    if body.action == "export_iocs" and all_iocs:
        export = IocListResponse(items=all_iocs, page=PageInfo(has_more=False))

    return BatchJobsResponse(accepted=accepted, rejected=rejected, export_iocs=export)


# ---------- GET /jobs/{jobId}/summary ----------

@router.get("/jobs/{job_id}/summary", response_model=JobSummaryResponse)
async def job_summary(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Get a high-level summary of a completed job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    alert_count = db.scalar(select(func.count()).select_from(Alert).where(Alert.job_id == job_id)) or 0
    finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.job_id == job_id)) or 0
    ioc_count = db.scalar(select(func.count()).select_from(Ioc).where(Ioc.job_id == job_id)) or 0
    host_count = db.scalar(select(func.count()).select_from(Host).where(Host.job_id == job_id)) or 0

    # Top hosts by connection count
    top_hosts_rows = db.execute(
        select(Host).where(Host.job_id == job_id).order_by(Host.conn_count.desc()).limit(5)
    ).scalars().all()
    top_hosts = [HostListItem(
        ip=h.ip, role=h.role or "unknown", conn_count=h.conn_count or 0,
        bytes_sent=h.bytes_sent, bytes_recv=h.bytes_recv,
        alert_count=h.alert_count or 0, finding_count=h.finding_count or 0,
        top_domains=_safe_json_list(h.top_domains_json),
    ) for h in top_hosts_rows]

    # Top IOCs
    top_iocs_rows = db.execute(
        select(Ioc).where(Ioc.job_id == job_id).limit(5)
    ).scalars().all()
    top_iocs = [IocItem(
        ioc_id=i.ioc_id, type=i.ioc_type, value=i.value,
        confidence=i.confidence, sources=_safe_json_list(i.sources_json),
    ) for i in top_iocs_rows]

    # Top signals (high/critical alerts)
    top_alerts = db.execute(
        select(Alert.signature).where(
            Alert.job_id == job_id, Alert.severity.in_(["high", "critical"])
        ).group_by(Alert.signature).order_by(func.count().desc()).limit(5)
    ).scalars().all()

    headline = f"Analysis found {alert_count} alerts, {finding_count} findings, {ioc_count} IOCs across {host_count} hosts."

    # Generate recommendations based on evidence
    from backend.app.services.report_composer import _generate_recommendations
    theories = db.execute(
        select(Theory).where(Theory.job_id == job_id)
    ).scalars().all()
    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id)
    ).scalars().all()
    iocs_all = db.execute(
        select(Ioc).where(Ioc.job_id == job_id)
    ).scalars().all()
    # Determine threat level from alert severities
    has_critical = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.job_id == job_id, Alert.severity == "critical"
        )
    ) or 0
    has_high = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.job_id == job_id, Alert.severity == "high"
        )
    ) or 0
    threat = "critical" if has_critical else "high" if has_high else "medium"
    recommendations = _generate_recommendations(threat, theories, findings, iocs_all)

    return JobSummaryResponse(
        job_id=job_id,
        headline=headline,
        top_signals=list(top_alerts),
        top_hosts=top_hosts,
        top_iocs=top_iocs,
        recommendations=recommendations,
        alert_count=alert_count,
        finding_count=finding_count,
        ioc_count=ioc_count,
        host_count=host_count,
    )


# ---------- GET /jobs/{jobId}/partial-results ----------

class PartialResultsResponse(BaseModel):
    """Intermediate pipeline data available before full analysis completes."""
    schema_version: str = "1.0"
    job_id: str
    completed_stages: list[str] = Field(default_factory=list)
    current_stage: str | None = None
    partial_data: dict = Field(default_factory=dict)


@router.get("/jobs/{job_id}/partial-results", response_model=PartialResultsResponse)
async def get_partial_results(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Return current partial results for a running job.

    Allows the frontend to fetch intermediate pipeline data on page load
    without waiting for the next SSE event.
    """
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.partial_results import get_partial_result
    data = get_partial_result(job_id)
    if data is None:
        return PartialResultsResponse(job_id=job_id)
    return PartialResultsResponse(
        job_id=job_id,
        completed_stages=data.get("completed_stages", []),
        current_stage=data.get("current_stage"),
        partial_data=data.get("partial_data", {}),
    )


# ---------- GET /jobs/{jobId}/sensors ----------

@router.get("/jobs/{job_id}/sensors", response_model=SensorListResponse)
async def list_sensors(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List sensors and their status for a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    rows = db.execute(
        select(JobSensor).where(JobSensor.job_id == job_id).order_by(JobSensor.id)
    ).scalars().all()

    items = []
    for s in rows:
        prov_data = json.loads(s.provenance_json) if s.provenance_json else {}
        stats_data = json.loads(s.stats_json) if s.stats_json else {}
        items.append(SensorItem(
            sensor=s.sensor,
            status=s.status,
            meta=SensorProvenance(
                sensor_name=s.sensor,
                sensor_version=prov_data.get("sensor_version"),
                image_digest=prov_data.get("image_digest"),
                host_hostname=prov_data.get("host_hostname"),
                aipam_version=prov_data.get("aipam_version"),
                tool_versions=prov_data.get("tool_versions", {}),
            ),
            stats=SensorStats(
                runtime_seconds=stats_data.get("runtime_seconds"),
                output_bytes=stats_data.get("output_bytes"),
                findings_count=stats_data.get("findings_count"),
            ) if stats_data else None,
            started_at=s.started_at,
            completed_at=s.completed_at,
            timeout_seconds=s.timeout_seconds,
            error=s.error,
        ))

    return SensorListResponse(items=items)



# ---------- GET /jobs/{jobId}/timeline ----------

@router.get("/jobs/{job_id}/timeline", response_model=TimelineListResponse)
async def job_timeline(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    order: str = Query("asc"),
    type_filter: str | None = Query(None, alias="type"),
):
    """Timeline of events for a job, ordered chronologically."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(TimelineEvent).where(TimelineEvent.job_id == job_id)
    if type_filter:
        q = q.where(TimelineEvent.type == type_filter)

    items, page = paginate(db, q, TimelineEvent.ts, TimelineEvent.id, cursor, limit, order)

    result_items = []
    for t in items:
        details = json.loads(t.details_json) if t.details_json else {}
        result_items.append(TimelineItem(
            ts=t.ts,
            type=t.type,
            title=t.title,
            description=details.get("description"),
            severity=t.severity,
            entities=details.get("entities"),
            refs=details.get("refs"),
        ))

    return TimelineListResponse(items=result_items, page=page)


# ---------- GET /jobs/{jobId}/iocs ----------

@router.get("/jobs/{job_id}/iocs", response_model=IocListResponse)
async def job_iocs(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ioc_type: str | None = Query(None, alias="type"),
    pcap_label: str | None = Query(None, description="Filter by PCAP label (before/after)"),
):
    """List IOCs extracted from a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(Ioc).where(Ioc.job_id == job_id)
    if ioc_type:
        q = q.where(Ioc.ioc_type == ioc_type)
    if pcap_label:
        q = q.where(Ioc.pcap_label == pcap_label)

    items, page = paginate(db, q, Ioc.id, Ioc.id, cursor, limit)

    return IocListResponse(
        items=[IocItem(
            ioc_id=i.ioc_id, type=i.ioc_type, value=i.value,
            severity=i.severity,
            confidence=i.confidence,
            sources=_safe_json_list(i.sources_json),
            context=i.context,
        ) for i in items],
        page=page,
    )


# ---------- GET /jobs/{jobId}/files ----------

@router.get("/jobs/{job_id}/files", response_model=FileListResponse)
async def job_files(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """List all files extracted from a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    q = select(File).where(File.job_id == job_id)
    items, page = paginate(db, q, File.id, File.id, cursor, limit)

    return FileListResponse(
        items=[FileItem.model_validate(f) for f in items],
        page=page,
    )


# ---------- GET /jobs/{jobId}/files/{fileId}/download ----------

@router.get("/jobs/{job_id}/files/{file_id}/download")
async def download_extracted_file(
    job_id: str,
    file_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Download an extracted file by its file_id (Zeek extract filename)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    # Verify the file exists in DB
    file_row = db.execute(
        select(File).where(File.job_id == job_id, File.file_id == file_id)
    ).scalar_one_or_none()
    if not file_row:
        raise HTTPException(status_code=404, detail="File not found in database")

    # Search for the actual file on disk under the Zeek extraction directories
    job_dir = settings.aipam_job_root / job_id
    zeek_raw = job_dir / "sensors" / "zeek" / "raw"
    disk_path = None
    if zeek_raw.exists():
        for candidate in zeek_raw.rglob(file_id):
            if candidate.is_file():
                disk_path = candidate
                break

    if not disk_path or not disk_path.exists():
        raise HTTPException(status_code=404, detail="Extracted file not found on disk")

    # Determine a download filename with extension hint from mime
    dl_name = file_id
    mime = file_row.mime or "application/octet-stream"
    ext_map = {
        "text/html": ".html", "text/plain": ".txt", "text/css": ".css",
        "text/javascript": ".js", "application/javascript": ".js",
        "application/json": ".json", "application/xml": ".xml",
        "application/pdf": ".pdf", "application/zip": ".zip",
        "application/gzip": ".gz", "image/png": ".png",
        "image/jpeg": ".jpg", "image/gif": ".gif",
        "application/x-executable": ".bin", "application/x-dosexec": ".exe",
    }
    ext = ext_map.get(mime, "")
    if ext and not dl_name.endswith(ext):
        dl_name = dl_name + ext

    return FileResponse(
        path=str(disk_path),
        filename=dl_name,
        media_type=mime,
    )


# ---------- GET /jobs/{jobId}/graph ----------

@router.get("/jobs/{job_id}/graph", response_model=JobGraphResponse)
async def job_graph(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Generate a graph of network activity for the job."""
    from backend.app.models.host import Host
    from backend.app.models.connection import Connection
    from backend.app.schemas.job import GraphNode, GraphEdge

    _require_job(db, job_id)

    # 1. Collect nodes (hosts)
    hosts = db.execute(select(Host).where(Host.job_id == job_id)).scalars().all()
    nodes = []
    seen_ips = set()

    for h in hosts:
        nodes.append(GraphNode(
            id=h.ip,
            label=h.ip,
            type="host",
            severity="high" if h.alert_count > 0 else "info"
        ))
        seen_ips.add(h.ip)

    # 2. Collect edges (connections)
    # Group by src/dst to avoid too many duplicate lines
    conns = db.execute(
        select(Connection.src_ip, Connection.dest_ip)
        .where(Connection.job_id == job_id)
        .group_by(Connection.src_ip, Connection.dest_ip)
    ).all()

    edges = []
    for src, dst in conns:
        # Add external nodes if not seen
        for ip in (src, dst):
            if ip not in seen_ips:
                nodes.append(GraphNode(id=ip, label=ip, type="external"))
                seen_ips.add(ip)
        
        edges.append(GraphEdge(source=src, target=dst, type="connection"))

    # 3. Add alerts as weighted edges or highlight existing
    # For now, let's just use connection data for topology
    
    return JobGraphResponse(nodes=nodes, edges=edges)


# ---------- GET /jobs/{jobId}/evidence-graph ----------

@router.get("/jobs/{job_id}/evidence-graph", response_model=EvidenceGraphResponse)
async def job_evidence_graph(
    job_id: str,
    db: Session = Depends(get_db),
    include: str | None = Query(None, description="Comma-separated node types to include"),
):
    """Build the full evidence relationship graph for a job.

    Returns nodes for all evidence entity types (hosts, alerts, findings,
    theories, slices, IOCs, annotations) and edges showing their relationships.

    Use ``include`` to filter: e.g. ``?include=host,alert,theory``
    """
    from backend.app.services.evidence_graph import build_evidence_graph

    _require_job(db, job_id)

    include_types = None
    if include:
        include_types = {t.strip() for t in include.split(",") if t.strip()}

    try:
        graph = build_evidence_graph(db, job_id, include_types=include_types)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    nodes = [GraphNode(**n) for n in graph["nodes"]]
    edges = [GraphEdge(**e) for e in graph["edges"]]

    return EvidenceGraphResponse(
        nodes=nodes,
        edges=edges,
        node_count=len(nodes),
        edge_count=len(edges),
    )


# ---------- GET /jobs/{jobId}/events (SSE) ----------

async def _sse_generator(job_id: str, db_factory):
    """Server-Sent Events generator with Redis pub/sub + DB polling fallback.

    Subscribes to the job's Redis event channel for low-latency pipeline
    events (sensor start/complete, high-severity findings).  Falls back to
    DB polling every 2 s to detect status changes even if Redis is down.
    """
    from backend.app.events import subscribe_job_events

    pubsub = subscribe_job_events(job_id)
    last_status = None
    retry_count = 0
    max_retries = 3600  # ~1 hour at 1 s intervals
    _event_id = 0

    try:
        while retry_count < max_retries:
            # ── 1. Drain any queued Redis pub/sub messages ──────────
            if pubsub is not None:
                try:
                    for _ in range(50):  # batch up to 50 messages per tick
                        msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.0)
                        if msg is None:
                            break
                        if msg["type"] == "message":
                            raw = msg["data"]
                            # Forward the envelope directly — it matches SseEnvelope
                            yield f"data: {raw}\n\n"
                except Exception:
                    pass  # Redis hiccup — fall through to DB poll

            # ── 2. DB status poll (authoritative, every tick) ───────
            try:
                db = db_factory()
                try:
                    job = db.get(Job, job_id)
                    if not job:
                        yield "event: error\ndata: {\"message\": \"Job not found\"}\n\n"
                        return

                    current_status = job.status
                    if current_status != last_status:
                        _event_id += 1
                        envelope = json.dumps({
                            "id": _event_id,
                            "type": "job.status",
                            "ts": job.started_at or "",
                            "data": {
                                "job_id": job_id,
                                "status": current_status,
                                "started_at": job.started_at,
                                "completed_at": job.completed_at,
                                "error_summary": job.error_summary,
                            },
                        })
                        yield f"data: {envelope}\n\n"
                        last_status = current_status

                    # Terminal states
                    if current_status in ("completed", "completed_with_errors",
                                          "failed", "canceled", "deleted"):
                        _event_id += 1
                        done_envelope = json.dumps({
                            "id": _event_id,
                            "type": "job.complete",
                            "ts": job.completed_at or "",
                            "data": {
                                "job_id": job_id,
                                "status": current_status,
                            },
                        })
                        yield f"data: {done_envelope}\n\n"
                        return
                finally:
                    db.close()
            except Exception as e:
                yield f"event: error\ndata: {{\"message\": \"{str(e)}\"}}\n\n"

            await asyncio.sleep(1.0)
            retry_count += 1
    finally:
        # Clean up Redis subscription
        if pubsub is not None:
            try:
                pubsub.unsubscribe()
                pubsub.close()
            except Exception:
                pass

    yield "event: timeout\ndata: {\"message\": \"SSE stream timed out\"}\n\n"


@sse_router.get("/jobs/{job_id}/events")
async def job_events(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    _token: str = Depends(verify_token_or_query),
):
    """Server-Sent Events stream for real-time job progress.

    Accepts auth via ``Authorization: Bearer <token>`` header **or**
    ``?token=<token>`` query parameter (needed for ``EventSource``).
    """
    job = _require_job(db, job_id)

    # For terminal states, return immediately without long-polling
    terminal = ("completed", "completed_with_errors", "failed", "canceled", "deleted")
    if job.status in terminal:
        async def _immediate():
            status_env = json.dumps({
                "id": 1, "type": "job.status",
                "ts": job.started_at or "",
                "data": {
                    "job_id": job_id, "status": job.status,
                    "started_at": job.started_at, "completed_at": job.completed_at,
                    "error_summary": job.error_summary,
                },
            })
            yield f"data: {status_env}\n\n"
            done_env = json.dumps({
                "id": 2, "type": "job.complete",
                "ts": job.completed_at or "",
                "data": {"job_id": job_id, "status": job.status},
            })
            yield f"data: {done_env}\n\n"
        gen = _immediate()
    else:
        from backend.app.database_v2 import get_session_factory
        gen = _sse_generator(job_id, get_session_factory())

    return StreamingResponse(
        gen,
        media_type="text/event-stream",
        headers={
            "X-Request-Id": request_id,
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


# ---------- GET /jobs/{jobId}/export ----------

@sse_router.get("/jobs/{job_id}/export")
async def export_job_package(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(verify_token_or_query),
):
    """Export all job artifacts (PCAPs, sensors, findings, report) as a ZIP PACKAGE (§12.5)."""
    job = _require_job(db, job_id)
    job_dir = settings.aipam_job_root / job_id

    if not job_dir.exists():
        raise HTTPException(status_code=404, detail="Job directory not found on disk")

    # Use a generator to stream the zip data
    def _create_zip_generator():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # zip input/
            for pcap in (job_dir / "input").glob("*"):
                if pcap.is_file():
                    zf.write(pcap, arcname=f"input/{pcap.name}")

            # zip sensors/ results
            for res in (job_dir / "sensors").rglob("sensor.results.jsonl"):
                rel = res.relative_to(job_dir)
                zf.write(res, arcname=str(rel))

            # zip report/ if exists
            report_dir = job_dir / "report"
            if report_dir.exists():
                for f in report_dir.iterdir():
                    if f.is_file():
                        zf.write(f, arcname=f"report/{f.name}")

            # query findings and serialize
            from backend.app.api.findings import _finding_to_item
            findings_q = select(Finding).where(Finding.job_id == job_id)
            findings = db.execute(findings_q).scalars().all()
            findings_data = [
                _finding_to_item(f).model_dump() for f in findings
            ]
            zf.writestr("findings.json", json.dumps(findings_data, indent=2))

            # metadata
            meta = {
                "job_id": job_id,
                "job_name": job.job_name,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "status": job.status,
            }
            zf.writestr("export_metadata.json", json.dumps(meta, indent=2))

        yield buf.getvalue()

    filename = f"aipam_export_{job_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return StreamingResponse(
        _create_zip_generator(),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
