"""
Job endpoints (§1.3 + §3.3 + §3.4 + §3.8).

POST /jobs                     – create a job from an upload
POST /jobs/from_arkime         – create a job from Arkime session export
POST /jobs/from_security_onion – create a job from Security Onion PCAP export
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
POST /jobs/{id}/arkime/import  – queue PCAPs for Arkime import
GET  /jobs/{id}/arkime/status  – Arkime import status
POST /jobs/{id}/security_onion/import – push PCAPs to Security Onion
"""

import hashlib
import json
import logging as _logging
import uuid
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
from backend.app.models.file import File
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.job_log_source import JobLogSource
from backend.app.models.sensor import JobSensor
from backend.app.models.timeline import TimelineEvent
from backend.app.models.upload import Upload
from backend.app.schemas.common import (
    ExecutionProfile,
    JobStatus,
    PageInfo,
    SourceType,
)
from backend.app.schemas.file import FileItem, FileListResponse
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
    JobLogSourceItem,
    JobPcapItem,
    PcapUploadItem,
    SensorItem,
    SensorListResponse,
    SensorProvenance,
    SensorStats,
    StorylineResponse,
    StorylineStage,
    TemporalCorrelationItem,
    TemporalCorrelationsResponse,
)
from backend.app.schemas.arkime import ArkimeImportResponse, ArkimeStatusResponse
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
    """Create a new analysis job from one or more validated uploads.

    Supports:
      - PCAP-only jobs (upload PCAPs)
      - Bundle-only jobs (upload log/C2/netflow archive, source_type != pcap)
      - Hybrid jobs (PCAPs + bundle_upload_id in same request for fused analysis)
    """
    response.headers["X-Request-Id"] = request_id

    # ── Bundle-only path (no PCAPs) ──
    if body.source_type != SourceType.pcap and not body.uploads and not body.bundle_upload_id:
        return _create_bundle_job(body, db, settings)

    # ── PCAP path (optionally with attached log bundle) ──
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

    # ── Stage log bundle(s) if attached (hybrid PCAP + logs job) ──
    manifest_json: str | None = None
    has_bundle = False
    merged_manifest = None
    if body.bundle_uploads:
        from backend.app.pipeline.bundle_stager import stage_bundle

        bundle_hints = None
        if body.bundle_entries:
            bundle_hints = [e.model_dump() for e in body.bundle_entries]

        for b_item in body.bundle_uploads:
            bundle_upload: Upload | None = db.get(Upload, b_item.upload_id)
            if bundle_upload is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"Bundle upload {b_item.upload_id} not found",
                )

            archive_path = settings.aipam_upload_root / b_item.upload_id / bundle_upload.filename
            if not archive_path.exists():
                raise HTTPException(status_code=400, detail="Bundle archive file missing from disk")

            try:
                manifest = stage_bundle(
                    archive_path=archive_path,
                    job_dir=job_dir,
                    job_id=job_id,
                    source_type=SourceType.log_bundle,
                    exercise_id=body.exercise_id,
                    bundle_entries=bundle_hints,
                    label=b_item.label,
                )
                if merged_manifest is None:
                    merged_manifest = manifest
                else:
                    # Merge entries from additional bundles into the first manifest
                    merged_manifest.entries.extend(manifest.entries)
                has_bundle = True
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Bundle staging failed: {exc}")

        if merged_manifest is not None:
            # Re-persist the merged manifest
            manifest_path = job_dir / "source_manifest.json"
            manifest_path.write_text(
                merged_manifest.model_dump_json(indent=2),
                encoding="utf-8",
            )
            manifest_json = merged_manifest.model_dump_json()

    # Determine source_type for the job
    source_type = "pcap+logs" if has_bundle else SourceType.pcap.value

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
        source_type=source_type,
        exercise_id=body.exercise_id,
        source_manifest_json=manifest_json,
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

    # Create JobLogSource records from manifest entries (traceability)
    if merged_manifest is not None:
        for ordinal, entry in enumerate(merged_manifest.entries):
            log_rec = JobLogSource(
                job_id=job_id,
                upload_id=None,  # bundle uploads don't map 1:1 to log files
                label=entry.label,
                filename=entry.filename,
                source_system=entry.source_system,
                parser_hint=entry.parser_hint,
                ordinal=ordinal,
                size_bytes=entry.size_bytes,
                sha256=entry.sha256,
            )
            db.add(log_rec)

    db.commit()

    # Dispatch the pipeline to the Celery worker
    _dispatch_job(job_id)

    return JobCreateResponse(schema_version="1.0", job_id=job_id)


def _create_bundle_job(
    body: JobCreateRequest,
    db: Session,
    settings: Settings,
) -> JobCreateResponse:
    """Create a job from a telemetry bundle (log/C2/netflow/exercise).

    The bundle archive must have been uploaded via ``POST /uploads/bundle``
    first.  The ``upload_id`` in the request body references that upload.
    """
    from backend.app.pipeline.bundle_stager import stage_bundle

    if not body.upload_id:
        raise HTTPException(status_code=400, detail="upload_id required for bundle jobs")

    upload: Upload | None = db.get(Upload, body.upload_id)
    if upload is None:
        raise HTTPException(status_code=400, detail=f"Upload {body.upload_id} not found")

    archive_path = settings.aipam_upload_root / body.upload_id / upload.filename
    if not archive_path.exists():
        raise HTTPException(status_code=400, detail="Upload file missing from disk")

    job_id = str(uuid.uuid4())

    # Create job directory with telemetry sub-tree
    job_dir: Path = settings.aipam_job_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "input").mkdir(exist_ok=True)
    (job_dir / "normalized").mkdir(exist_ok=True)
    (job_dir / "sensors").mkdir(exist_ok=True)
    (job_dir / "report").mkdir(exist_ok=True)

    # Extract bundle and build manifest
    bundle_hints = None
    if body.bundle_entries:
        bundle_hints = [e.model_dump() for e in body.bundle_entries]

    try:
        manifest = stage_bundle(
            archive_path=archive_path,
            job_dir=job_dir,
            job_id=job_id,
            source_type=body.source_type,
            exercise_id=body.exercise_id,
            bundle_entries=bundle_hints,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job = Job(
        job_id=job_id,
        job_name=body.job_name or f"{body.source_type.value} analysis",
        notes=body.notes,
        status="queued",
        execution_profile=body.execution_profile.value,
        priority=body.priority.value,
        upload_id=body.upload_id,
        pcap_filename=None,
        pcap_size_bytes=upload.size_bytes,
        source_type=body.source_type.value,
        exercise_id=body.exercise_id,
        source_manifest_json=manifest.model_dump_json(),
        created_at=_now_iso(),
    )
    db.add(job)

    # Create JobLogSource records from manifest entries (traceability)
    for ordinal, entry in enumerate(manifest.entries):
        log_rec = JobLogSource(
            job_id=job_id,
            upload_id=body.upload_id,
            label=entry.label,
            filename=entry.filename,
            source_system=entry.source_system,
            parser_hint=entry.parser_hint,
            ordinal=ordinal,
            size_bytes=entry.size_bytes,
            sha256=entry.sha256,
        )
        db.add(log_rec)

    db.commit()

    # Dispatch the pipeline to the Celery worker
    _dispatch_job(job_id)

    return JobCreateResponse(schema_version="1.0", job_id=job_id)


# ---------- POST /jobs/from_arkime ----------

class ArkimeJobRequest(BaseModel):
    """Request to create a job by exporting sessions from Arkime."""
    source: str = "arkime"
    filter: str
    time_range: dict = Field(..., description="Dict with 'start' and 'end' ISO timestamps")
    mode: str = "single_window"
    metadata: dict = Field(default_factory=dict)


@router.post("/jobs/from_arkime", status_code=status.HTTP_201_CREATED, response_model=JobCreateResponse)
async def create_job_from_arkime(
    body: ArkimeJobRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Create a new analysis job by exporting matching sessions from Arkime as PCAP."""
    response.headers["X-Request-Id"] = request_id

    from backend.app.connectors import ArkimeConnector
    connector = ArkimeConnector()

    if not connector.enabled:
        raise HTTPException(status_code=400, detail="Arkime integration is not enabled. Set ARKIME_ENABLED=true.")

    # Export PCAP from Arkime Viewer
    try:
        pcap_data = await connector.export_pcap(body.filter, body.time_range)
    except Exception as exc:
        _logger.error("Arkime PCAP export failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"Failed to export PCAP from Arkime: {exc}")

    if not pcap_data:
        raise HTTPException(status_code=404, detail="No matching sessions found in Arkime for the given filter/time range.")

    job_id = str(uuid.uuid4())
    upload_id = str(uuid.uuid4())
    pcap_filename = f"arkime_export_{job_id[:8]}.pcap"
    pcap_sha256 = hashlib.sha256(pcap_data).hexdigest()

    # Save the exported PCAP to the upload staging area so the
    # pipeline can find it via the standard upload_id lookup.
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / pcap_filename).write_bytes(pcap_data)

    # Create an Upload DB record
    upload = Upload(
        upload_id=upload_id,
        filename=pcap_filename,
        size_bytes=len(pcap_data),
        sha256=pcap_sha256,
        is_valid=1,
        format="pcap",
        created_at=_now_iso(),
    )
    db.add(upload)

    # Create the Job record linked to the upload
    job = Job(
        job_id=job_id,
        job_name=body.metadata.get("exercise_id", f"Arkime: {body.filter[:60]}"),
        notes=body.metadata.get("notes", ""),
        status="queued",
        execution_profile="standard",
        priority="normal",
        upload_id=upload_id,
        pcap_filename=pcap_filename,
        pcap_size_bytes=len(pcap_data),
        pcap_sha256=pcap_sha256,
        created_at=_now_iso(),
    )
    db.add(job)
    db.commit()

    # Dispatch the pipeline to the Celery worker
    _dispatch_job(job_id)

    return JobCreateResponse(schema_version="1.0", job_id=job_id)


# ---------- POST /jobs/from_security_onion ----------

class SecurityOnionJobRequest(BaseModel):
    """Request to create a job by exporting PCAP from Security Onion."""
    source: str = "security_onion"
    time_range: dict = Field(..., description="Dict with 'start' and 'end' ISO timestamps")
    sensors: list = Field(default_factory=list, description="List of sensor names to filter by")
    filter_fields: dict = Field(default_factory=dict, description="Optional packet filters: protocol, srcIp, dstIp, srcPort, dstPort")
    mode: str = "single_window"
    metadata: dict = Field(default_factory=dict)


@router.post("/jobs/from_security_onion", status_code=status.HTTP_201_CREATED, response_model=JobCreateResponse)
async def create_job_from_security_onion(
    body: SecurityOnionJobRequest,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Create a new analysis job by exporting matching PCAP from Security Onion."""
    response.headers["X-Request-Id"] = request_id

    from backend.app.connectors import SecurityOnionConnector
    connector = SecurityOnionConnector()

    if not connector.enabled:
        raise HTTPException(status_code=400, detail="Security Onion integration is not enabled. Set SECURITY_ONION_ENABLED=true.")

    # Export PCAP from Security Onion
    try:
        pcap_data = await connector.export_pcap(body.time_range, body.sensors, body.filter_fields)
    except Exception as exc:
        _logger.error("Security Onion PCAP export failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"Failed to export PCAP from Security Onion: {exc}")

    if not pcap_data:
        raise HTTPException(status_code=404, detail="No matching packets found in Security Onion for the given time range/sensors.")

    job_id = str(uuid.uuid4())
    upload_id = str(uuid.uuid4())
    pcap_filename = f"so_export_{job_id[:8]}.pcap"
    pcap_sha256 = hashlib.sha256(pcap_data).hexdigest()

    # Save the exported PCAP to the upload staging area
    upload_dir: Path = settings.aipam_upload_root / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / pcap_filename).write_bytes(pcap_data)

    # Create an Upload DB record
    upload = Upload(
        upload_id=upload_id,
        filename=pcap_filename,
        size_bytes=len(pcap_data),
        sha256=pcap_sha256,
        is_valid=1,
        format="pcap",
        created_at=_now_iso(),
    )
    db.add(upload)

    # Create the Job record linked to the upload
    sensor_names = ", ".join(body.sensors) if body.sensors else "all"
    job = Job(
        job_id=job_id,
        job_name=body.metadata.get("exercise_id", f"SO: {sensor_names}"),
        notes=body.metadata.get("notes", ""),
        status="queued",
        execution_profile="standard",
        priority="normal",
        upload_id=upload_id,
        pcap_filename=pcap_filename,
        pcap_size_bytes=len(pcap_data),
        pcap_sha256=pcap_sha256,
        created_at=_now_iso(),
    )
    db.add(job)
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

    # Attach per-job log source records (traceability) + parse diagnostics
    log_rows = db.execute(
        select(JobLogSource).where(JobLogSource.job_id == job_id).order_by(JobLogSource.ordinal)
    ).scalars().all()

    # Load telemetry parse diagnostics (if available)
    diag_map: dict[str, dict] = {}
    try:
        from backend.app.config_v2 import get_settings
        job_dir = get_settings().aipam_job_root / job_id
        diag_path = job_dir / "telemetry_diagnostics.json"
        if diag_path.exists():
            import json as _json
            diag_data = _json.loads(diag_path.read_text(encoding="utf-8"))
            for fd in diag_data.get("files", []):
                diag_map[fd["filename"]] = fd
    except Exception:
        pass  # diagnostics are best-effort

    log_items: list[JobLogSourceItem] = []
    for r in log_rows:
        item = JobLogSourceItem.model_validate(r)
        diag = diag_map.get(item.filename)
        if diag:
            item.parse_status = diag.get("status")
            item.parse_parser = diag.get("parser_name")
            item.parse_events = diag.get("events_produced", 0)
            item.parse_error = diag.get("error")
        log_items.append(item)
    detail.log_sources = log_items

    # Attach temporal correlations (log ↔ PCAP matches)
    try:
        from backend.app.models.temporal_correlation import TemporalCorrelation
        tc_rows = db.execute(
            select(TemporalCorrelation)
            .where(TemporalCorrelation.job_id == job_id)
            .order_by(TemporalCorrelation.match_score.desc())
            .limit(200)
        ).scalars().all()
        detail.temporal_correlations = [TemporalCorrelationItem.model_validate(r) for r in tc_rows]
    except Exception:
        pass  # table may not exist yet

    return JobGetResponse(job=detail)


# ---------- GET /jobs/{jobId}/temporal-correlations ----------

@router.get("/jobs/{job_id}/temporal-correlations", response_model=TemporalCorrelationsResponse)
async def list_temporal_correlations(
    job_id: str,
    response: Response,
    offset: int = 0,
    limit: int = 200,
    min_score: float = 0.0,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Return the full paginated list of log ↔ PCAP temporal correlations.

    Supports offset/limit pagination so the dedicated UI tab can load more
    than the 200-row preview returned with the JobDetail response.
    """
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id

    from backend.app.models.temporal_correlation import TemporalCorrelation
    from sqlalchemy import func as sa_func

    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    total = db.execute(
        select(sa_func.count(TemporalCorrelation.id))
        .where(TemporalCorrelation.job_id == job_id)
        .where(TemporalCorrelation.match_score >= min_score)
    ).scalar_one()

    rows = db.execute(
        select(TemporalCorrelation)
        .where(TemporalCorrelation.job_id == job_id)
        .where(TemporalCorrelation.match_score >= min_score)
        .order_by(TemporalCorrelation.match_score.desc(), TemporalCorrelation.id.asc())
        .offset(offset)
        .limit(limit)
    ).scalars().all()

    items = [TemporalCorrelationItem.model_validate(r) for r in rows]
    has_more = (offset + len(items)) < total
    next_cursor = str(offset + limit) if has_more else None

    return TemporalCorrelationsResponse(
        items=items,
        page=PageInfo(next_cursor=next_cursor, has_more=has_more),
        total=total,
    )


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

    from backend.app.services.job_service import compute_job_summary
    summary = compute_job_summary(db, job_id)
    return JobSummaryResponse(**summary)


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
            evidence_status=details.get("evidence_status"),
            sensor=details.get("sensor"),
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


# ---------- GET /jobs/{jobId}/storyline ----------

@router.get("/jobs/{job_id}/storyline", response_model=StorylineResponse)
async def job_storyline(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Reconstruct the attack storyline for a job.

    Returns kill-chain-aligned stages with confidence scores, host timelines,
    and a human-readable narrative.
    """
    from backend.app.services.storyline import reconstruct_storyline

    _require_job(db, job_id)

    try:
        result = reconstruct_storyline(db, job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    d = result.to_dict()
    stages = [StorylineStage(**s) for s in d["stages"]]

    return StorylineResponse(
        job_id=d["job_id"],
        stages=stages,
        host_timelines=d["host_timelines"],
        narrative=d["narrative"],
        total_nodes=d["total_nodes"],
        total_edges=d["total_edges"],
        unclassified_count=d["unclassified_count"],
    )


# ---------- GET /jobs/{jobId}/events (SSE) ----------

    # SSE generator logic moved to backend.app.services.job_service.sse_generator


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
        from backend.app.services.job_service import sse_generator
        gen = sse_generator(job_id, get_session_factory())

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

    from backend.app.services.job_service import create_export_zip
    zip_bytes = create_export_zip(db, job, job_dir)

    filename = f"aipam_export_{job_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return StreamingResponse(
        iter([zip_bytes]),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )



# ---------- POST /jobs/{jobId}/arkime/import ----------

@router.post("/jobs/{job_id}/arkime/import", response_model=ArkimeImportResponse)
async def arkime_import(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Queue the job's PCAPs for import into Arkime.

    Writes a manifest for each PCAP to the shared import-queue volume so the
    ``arkime-importer`` sidecar picks them up asynchronously.
    """
    response.headers["X-Request-Id"] = request_id

    from backend.app.connectors import ArkimeConnector
    connector = ArkimeConnector()

    if not connector.enabled:
        return ArkimeImportResponse(
            job_id=job_id,
            enabled=False,
            import_status="not_imported",
            message="Arkime integration is not enabled.",
        )

    if not connector.import_enabled:
        return ArkimeImportResponse(
            job_id=job_id,
            enabled=True,
            import_status="not_imported",
            message="Arkime import is disabled in settings.",
        )

    _require_job(db, job_id)

    job_dir = settings.aipam_job_root / job_id
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail="Job directory not found on disk")

    # Collect PCAP files from the job's input directory
    input_dir = job_dir / "input"
    pcap_paths: list[Path] = []
    if input_dir.exists():
        for ext in ("*.pcap", "*.pcapng", "*.cap"):
            pcap_paths.extend(input_dir.glob(ext))

    if not pcap_paths:
        return ArkimeImportResponse(
            job_id=job_id,
            enabled=True,
            import_status="not_imported",
            message="No PCAP files found in job input directory.",
        )

    # Check if already imported/queued
    current_status = connector.get_import_status(job_dir)
    if current_status.get("status") in ("queued", "running", "imported"):
        return ArkimeImportResponse(
            job_id=job_id,
            enabled=True,
            import_status=current_status["status"],
            message=f"Import already {current_status['status']}.",
        )

    state = connector.queue_import(job_id, pcap_paths, job_dir)
    return ArkimeImportResponse(
        job_id=job_id,
        enabled=True,
        import_status=state,
        message=f"Queued {len(pcap_paths)} PCAP(s) for Arkime import.",
    )


# ---------- GET /jobs/{jobId}/arkime/status ----------

@router.get("/jobs/{job_id}/arkime/status", response_model=ArkimeStatusResponse)
async def arkime_status(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Return the current Arkime import status for a job."""
    response.headers["X-Request-Id"] = request_id

    from backend.app.connectors import ArkimeConnector
    connector = ArkimeConnector()

    if not connector.enabled:
        return ArkimeStatusResponse(
            job_id=job_id,
            enabled=False,
            message="Arkime integration is not enabled.",
        )

    _require_job(db, job_id)

    job_dir = settings.aipam_job_root / job_id
    status_data = connector.get_import_status(job_dir)

    return ArkimeStatusResponse(
        job_id=job_id,
        enabled=True,
        import_status=status_data.get("status", "not_imported"),
        imported_at=status_data.get("imported_at"),
        pcap_count=status_data.get("pcap_count", 0),
    )


# ---------- POST /jobs/{jobId}/security_onion/import ----------

class SecurityOnionImportResponse(BaseModel):
    """Response after requesting a PCAP import into Security Onion."""
    schema_version: str = "1.0"
    job_id: str
    enabled: bool = True
    status: str = "accepted"
    message: str | None = None
    node_id: str | None = None


@router.post("/jobs/{job_id}/security_onion/import", response_model=SecurityOnionImportResponse)
async def security_onion_import(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Push the job's PCAPs to Security Onion for ingestion via so-import-pcap.

    Uploads each PCAP via ``POST /api/gridmembers/{nodeId}/import`` so that
    Security Onion runs Suricata + Zeek against the traffic and indexes
    alerts/logs into Elasticsearch with original timestamps.
    """
    response.headers["X-Request-Id"] = request_id

    from backend.app.connectors import SecurityOnionConnector
    connector = SecurityOnionConnector()

    if not connector.enabled:
        return SecurityOnionImportResponse(
            job_id=job_id,
            enabled=False,
            status="disabled",
            message="Security Onion integration is not enabled.",
        )

    _require_job(db, job_id)

    job_dir = settings.aipam_job_root / job_id
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail="Job directory not found on disk")

    # Collect PCAP files from the job's input directory
    input_dir = job_dir / "input"
    pcap_paths: list[Path] = []
    if input_dir.exists():
        for ext in ("*.pcap", "*.pcapng", "*.cap"):
            pcap_paths.extend(input_dir.glob(ext))

    if not pcap_paths:
        return SecurityOnionImportResponse(
            job_id=job_id,
            enabled=True,
            status="no_pcaps",
            message="No PCAP files found in job input directory.",
        )

    # Upload each PCAP to Security Onion
    results = []
    for pcap_path in pcap_paths:
        try:
            pcap_bytes = pcap_path.read_bytes()
            result = await connector.import_pcap(pcap_bytes, pcap_path.name)
            results.append(result)
        except Exception as exc:
            _logger.error("SO import failed for %s: %s", pcap_path.name, exc)
            raise HTTPException(
                status_code=502,
                detail=f"Failed to import {pcap_path.name} into Security Onion: {exc}",
            )

    node_id = results[0].get("node_id", "") if results else None
    return SecurityOnionImportResponse(
        job_id=job_id,
        enabled=True,
        status="accepted",
        message=f"Uploaded {len(pcap_paths)} PCAP(s) to Security Onion. Import is processing asynchronously.",
        node_id=node_id,
    )