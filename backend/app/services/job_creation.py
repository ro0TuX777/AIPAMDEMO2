"""Create uploaded jobs and commit their input metadata before dispatch.

The API owns request/response headers, maps JobCreationError to HTTP errors,
and dispatches only after a creation function returns successfully.
"""

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.config_v2 import Settings
from backend.app.models.job import Job
from backend.app.models.job_log_source import JobLogSource
from backend.app.models.job_pcap import JobPcap
from backend.app.models.upload import Upload
from backend.app.schemas.common import SourceType
from backend.app.schemas.job import (
    BundleUploadItem,
    JobCreateRequest,
    JobCreateResponse,
    PcapUploadItem,
)


class JobCreationError(Exception):
    """A creation failure whose status and detail are exposed by the API."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")



MAX_PCAPS_PER_JOB = 10
MAX_PCAP_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB per file
MAX_TOTAL_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB total per job

# Log bundles are capped by total bytes, not by file count — attach as many
# perspectives as the investigation needs. Per-file limit lives in api/uploads.py.
MAX_LOG_BYTES_PER_JOB = 10 * 1024 * 1024 * 1024  # 10 GB of logs per job


def _enforce_log_budget(uploads: list[Upload]) -> None:
    """Reject a job whose attached log bundles exceed the per-job byte budget."""
    total = sum(u.size_bytes or 0 for u in uploads)
    if total > MAX_LOG_BYTES_PER_JOB:
        raise JobCreationError(
            status_code=400,
            detail=(
                f"Attached logs total {total / 1024**3:.1f} GB, over the "
                f"{MAX_LOG_BYTES_PER_JOB // 1024**3} GB per-job limit. "
                "There is no limit on how many log files you attach — only on their combined size."
            ),
        )



def _resolve_upload_list(body: JobCreateRequest) -> list[PcapUploadItem]:
    """Normalize old single-upload and new multi-upload request formats."""
    if body.uploads:
        return body.uploads
    if body.upload_id:
        return [PcapUploadItem(upload_id=body.upload_id)]
    raise JobCreationError(status_code=400, detail="Provide upload_id or uploads[]")



def create_job_from_upload(
    body: JobCreateRequest,
    db: Session,
    settings: Settings,
) -> JobCreateResponse:
    """Stage and persist a PCAP, hybrid, telemetry, binary, or code-artifact job."""
    # ── BlueScrub code-artifact path: source archives and standalone binaries
    # audited along the DACV+R pillars. Never enters the PCAP pipeline. ──
    if body.source_type == SourceType.code_artifact:
        return _create_code_artifact_job(body, db, settings)

    # ── Bundle-only path (no PCAPs) ──
    if body.source_type != SourceType.pcap and not body.uploads and not body.bundle_uploads:
        return _create_bundle_job(body, db, settings)

    # ── PCAP path (optionally with attached log bundle) ──
    upload_items = _resolve_upload_list(body)

    # ── Binary artifact path: a single upload classified as "binary" is
    # routed to a binary/YARA analysis job instead of the PCAP pipeline. ──
    if len(upload_items) == 1:
        single = db.get(Upload, upload_items[0].upload_id)
        if single is not None and single.artifact_class == "binary":
            return _create_binary_job(body, single, db, settings)

    if len(upload_items) > MAX_PCAPS_PER_JOB:
        raise JobCreationError(status_code=400, detail=f"Max {MAX_PCAPS_PER_JOB} PCAPs per job")

    # Verify all uploads exist and accumulate total size
    uploads: list[Upload] = []
    total_size = 0
    for item in upload_items:
        upload: Upload | None = db.get(Upload, item.upload_id)
        if upload is None:
            raise JobCreationError(status_code=400, detail=f"Upload {item.upload_id} not found")
        total_size += upload.size_bytes or 0
        uploads.append(upload)

    if total_size > MAX_TOTAL_SIZE_BYTES:
        raise JobCreationError(status_code=400, detail=f"Total PCAP size exceeds {MAX_TOTAL_SIZE_BYTES // (1024**3)} GB limit")

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

        # Resolve every bundle up front so the byte budget is checked before any
        # extraction happens — no partial staging left behind on rejection.
        resolved_bundles: list[tuple[BundleUploadItem, Upload]] = []
        for b_item in body.bundle_uploads:
            bundle_upload: Upload | None = db.get(Upload, b_item.upload_id)
            if bundle_upload is None:
                raise JobCreationError(
                    status_code=400,
                    detail=f"Bundle upload {b_item.upload_id} not found",
                )
            resolved_bundles.append((b_item, bundle_upload))

        _enforce_log_budget([u for _, u in resolved_bundles])

        for b_item, bundle_upload in resolved_bundles:
            archive_path = settings.aipam_upload_root / b_item.upload_id / bundle_upload.filename
            if not archive_path.exists():
                raise JobCreationError(status_code=400, detail="Bundle archive file missing from disk")

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
                raise JobCreationError(status_code=400, detail=f"Bundle staging failed: {exc}")

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


    return JobCreateResponse(schema_version="1.0", job_id=job_id)



def _create_binary_job(
    body: JobCreateRequest,
    upload: Upload,
    db: Session,
    settings: Settings,
) -> JobCreateResponse:
    """Create a binary/YARA analysis job from a single ``binary`` upload.

    The artifact must have been uploaded via ``POST /uploads/artifact`` and
    classified as ``binary``. It is copied into the job input directory and
    the pipeline runs YARA/binary analysis on job start.
    """
    import shutil

    src = settings.aipam_upload_root / upload.upload_id / upload.filename
    if not src.exists():
        raise JobCreationError(status_code=400, detail="Binary upload file missing from disk")

    job_id = str(uuid.uuid4())
    input_dir: Path = settings.aipam_job_root / job_id / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, input_dir / upload.filename)

    job = Job(
        job_id=job_id,
        job_name=body.job_name or f"Binary analysis: {upload.filename}",
        notes=body.notes,
        status="queued",
        execution_profile=body.execution_profile.value,
        priority=body.priority.value,
        upload_id=upload.upload_id,
        pcap_filename=None,
        pcap_size_bytes=upload.size_bytes,
        source_type=SourceType.binary.value,
        exercise_id=body.exercise_id,
        created_at=_now_iso(),
    )
    db.add(job)
    db.commit()


    return JobCreateResponse(schema_version="1.0", job_id=job_id)



def _create_code_artifact_job(
    body: JobCreateRequest,
    db: Session,
    settings: Settings,
) -> JobCreateResponse:
    """Create a BlueScrub job from an uploaded source archive or binary.

    The archive is staged through the hardened extractor, which rejects hostile
    archives outright rather than sanitising them. Project binding is optional:
    an unbound job still scans, but triage will not carry forward until it is
    bound (``PUT /bluescrub/jobs/{id}/project``).
    """
    from backend.app.bluescrub.ingest import IngestError, IngestLimits, stage_archive
    from backend.app.models.bluescrub import BlueScrubJobLineage, BlueScrubProject

    upload_id = body.upload_id or (body.uploads[0].upload_id if body.uploads else None)
    if not upload_id:
        raise JobCreationError(status_code=400, detail="code_artifact job requires an upload")

    upload: Upload | None = db.get(Upload, upload_id)
    if upload is None:
        raise JobCreationError(status_code=400, detail=f"Upload {upload_id} not found")

    src = settings.aipam_upload_root / upload.upload_id / upload.filename
    if not src.exists():
        raise JobCreationError(status_code=400, detail="Upload file missing from disk")

    job_id = str(uuid.uuid4())
    job_dir: Path = settings.aipam_job_root / job_id
    source_root = job_dir / "input" / "source"

    limits = IngestLimits(
        max_files=int(os.getenv("AIPAM_BLUESCRUB_MAX_EXTRACT_FILES", "50000")),
        max_total_bytes=int(os.getenv("AIPAM_BLUESCRUB_MAX_ARCHIVE_MB", "512")) * 1024 * 1024,
    )
    try:
        stage_archive(src, source_root, limits)
    except IngestError as exc:
        # A rejected archive is a finding about the artifact, not a server
        # error: report the reason so the operator knows what was refused.
        raise JobCreationError(
            status_code=400,
            detail=f"Rejected code artifact ({exc.reason}): {exc.detail}",
        ) from exc

    project_id = getattr(body, "project_id", None)
    if project_id and db.get(BlueScrubProject, project_id) is None:
        raise JobCreationError(status_code=400, detail=f"Unknown project {project_id}")

    job = Job(
        job_id=job_id,
        job_name=body.job_name or f"Code artifact: {upload.filename}",
        notes=body.notes,
        status="queued",
        execution_profile=body.execution_profile.value,
        priority=body.priority.value,
        upload_id=upload.upload_id,
        pcap_filename=None,
        pcap_size_bytes=upload.size_bytes,
        source_type=SourceType.code_artifact.value,
        exercise_id=body.exercise_id,
        created_at=_now_iso(),
    )
    db.add(job)

    # Lineage is bound at creation, not resolved at persist time: two
    # concurrent scans of one project must inherit from the same parent rather
    # than racing on whichever finishes last.
    parent = None
    if project_id:
        parent = db.execute(
            select(Job.job_id)
            .join(BlueScrubJobLineage, BlueScrubJobLineage.job_id == Job.job_id)
            .where(
                BlueScrubJobLineage.project_id == project_id,
                Job.status.in_(("completed", "completed_with_errors")),
            )
            .order_by(Job.completed_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    db.add(BlueScrubJobLineage(
        job_id=job_id,
        project_id=project_id,
        lineage_parent_job_id=parent,
        analysis_kind="source_audit",
        compatibility_signature="",   # filled in by the pipeline once known
    ))
    db.commit()

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
        raise JobCreationError(status_code=400, detail="upload_id required for bundle jobs")

    upload: Upload | None = db.get(Upload, body.upload_id)
    if upload is None:
        raise JobCreationError(status_code=400, detail=f"Upload {body.upload_id} not found")

    archive_path = settings.aipam_upload_root / body.upload_id / upload.filename
    if not archive_path.exists():
        raise JobCreationError(status_code=400, detail="Upload file missing from disk")

    _enforce_log_budget([upload])

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
        raise JobCreationError(status_code=400, detail=str(exc))

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


    return JobCreateResponse(schema_version="1.0", job_id=job_id)
