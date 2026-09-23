"""State transitions and data cloning for existing analysis jobs."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone
import logging
from pathlib import Path

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from backend.app.config_v2 import Settings
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.schemas.job import JobCreateResponse

_logger = logging.getLogger("aipam.api.jobs")


class JobLifecycleError(Exception):
    """A lifecycle failure whose status and detail are exposed by the API."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cancel_job(job: Job, db: Session) -> Job:
    """Cancel an active job and persist its terminal timestamp."""
    if job.status not in ("queued", "running"):
        raise JobLifecycleError(409, f"Cannot cancel job in '{job.status}' state")

    job.status = "canceled"
    job.completed_at = _now_iso()
    db.commit()
    db.refresh(job)
    return job


def rerun_job(
    old: Job,
    db: Session,
    settings: Settings,
    *,
    job_id_factory: Callable[[], str | uuid.UUID] = uuid.uuid4,
) -> JobCreateResponse:
    """Create a queued rerun with the original PCAP associations."""
    new_id = str(job_id_factory())
    job_dir: Path = settings.aipam_job_root / new_id
    job_dir.mkdir(parents=True, exist_ok=True)

    new_job = Job(
        job_id=new_id,
        job_name=f"Rerun of {old.job_name or old.job_id}",
        notes=f"Rerun of job {old.job_id}",
        status="queued",
        artifact_layout_version=2,
        execution_profile=old.execution_profile,
        priority=old.priority,
        upload_id=old.upload_id,
        pcap_filename=old.pcap_filename,
        pcap_size_bytes=old.pcap_size_bytes,
        pcap_sha256=old.pcap_sha256,
        created_at=_now_iso(),
    )
    db.add(new_job)

    old_pcaps = db.execute(
        select(JobPcap).where(JobPcap.job_id == old.job_id).order_by(JobPcap.ordinal)
    ).scalars().all()
    for pcap in old_pcaps:
        db.add(JobPcap(
            job_id=new_id,
            upload_id=pcap.upload_id,
            label=pcap.label,
            filename=pcap.filename,
            ordinal=pcap.ordinal,
            size_bytes=pcap.size_bytes,
            sha256=pcap.sha256,
        ))

    db.commit()
    return JobCreateResponse(schema_version="1.0", job_id=new_id)


def reanalyze_job(
    job: Job,
    db: Session,
    pcap_label: str,
    dispatch_phase: Callable[[str, str], None],
) -> dict[str, str | int]:
    """Queue a phase-specific rerun with a fresh dispatch/ownership identity."""
    if job.status not in ("completed", "completed_with_errors", "failed"):
        raise JobLifecycleError(
            409,
            f"Can only re-analyze completed or failed jobs (current: {job.status})",
        )

    label_count = db.execute(
        select(func.count()).select_from(JobPcap).where(
            JobPcap.job_id == job.job_id,
            JobPcap.label == pcap_label,
        )
    ).scalar() or 0
    if label_count == 0:
        raise JobLifecycleError(400, f"No PCAPs with label '{pcap_label}' found for this job")

    # Queue a new delivery identity; a worker claim alone enters running.
    # Keep the accepted manifest so a phase replacement preserves other phases.
    job_id = job.job_id
    changed = db.execute(
        update(Job).where(Job.job_id == job_id, Job.status.in_(
            ("completed", "completed_with_errors", "failed")
        )).values(
            status="queued", artifact_layout_version=2, error_summary=None,
            celery_task_id=None, run_token=None, dispatched_at=None,
            started_at=None, completed_at=None, heartbeat_at=None,
            cancel_requested_at=None, cancel_force_at=None, cancel_deadline_at=None,
            cancel_escalation_token=None, cancel_escalation_started_at=None,
            worker_id=None, worker_container_id=None, executor_pid=None,
            executor_pid_start_ticks=None, executor_boot_id=None,
        )
    ).rowcount
    db.commit()
    if changed != 1:
        raise JobLifecycleError(409, "Job state changed before re-analysis")

    try:
        dispatch_phase(job.job_id, pcap_label)
    except Exception as exc:
        _logger.warning("Failed to dispatch reanalyze for job %s: %s", job.job_id, exc)
        # The dispatcher owns dispatch-failure CAS; do not overwrite a worker.
        db.rollback()
        raise JobLifecycleError(500, "Failed to dispatch re-analysis task") from exc

    return {
        "job_id": job.job_id,
        "pcap_label": pcap_label,
        "status": "queued",
        "pcap_count": label_count,
    }
