import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from typing import Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.config_v2 import Settings, get_settings
from backend.app.models.job import Job

_logger = logging.getLogger("aipam.services.cleanup")

def cleanup_old_jobs(db: Session, settings: Optional[Settings] = None) -> int:
    """
    Delete jobs older than settings.aipam_job_retention_days.
    Returns the number of jobs deleted.
    """
    if settings is None:
        settings = get_settings()

    retention_days = settings.aipam_job_retention_days
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_str = cutoff_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Find jobs to delete
    stmt = select(Job).where(Job.created_at < cutoff_str)
    jobs_to_delete = db.execute(stmt).scalars().all()

    if not jobs_to_delete:
        return 0

    job_directories: list[Path] = []
    for job in jobs_to_delete:
        job_id = job.job_id
        _logger.info("Cleaning up job %s (created %s)", job_id, job.created_at)

        job_dir = (settings.aipam_job_root / job_id).resolve()
        if not job_dir.is_relative_to(settings.aipam_job_root.resolve()) or job_dir == settings.aipam_job_root.resolve():
            raise ValueError("job directory is outside the configured job root")
        job_directories.append(job_dir)
        db.delete(job)

    # Evidence stays intact if any constraint or commit fails.
    db.commit()
    for job_dir in job_directories:
        try:
            if job_dir.exists():
                shutil.rmtree(job_dir)
                _logger.debug("Deleted job directory: %s", job_dir)
        except Exception as exc:
            _logger.error("Failed to delete job directory %s: %s", job_dir, exc)

    deleted_count = len(job_directories)
    _logger.info("Auto-cleanup complete. Deleted %d jobs.", deleted_count)
    return deleted_count
