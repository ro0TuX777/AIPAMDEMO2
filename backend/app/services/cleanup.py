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

    deleted_count = 0
    for job in jobs_to_delete:
        job_id = job.job_id
        _logger.info("Cleaning up job %s (created %s)", job_id, job.created_at)

        # 1. Delete job directory
        job_dir: Path = settings.aipam_job_root / job_id
        try:
            if job_dir.exists():
                shutil.rmtree(job_dir)
                _logger.debug("Deleted job directory: %s", job_dir)
        except Exception as exc:
            _logger.error("Failed to delete job directory %s: %s", job_dir, exc)

        # 2. Delete DB record (Cascades automatically if configured)
        try:
            db.delete(job)
            deleted_count += 1
        except Exception as exc:
            _logger.error("Failed to delete job record %s: %s", job_id, exc)

    db.commit()
    _logger.info("Auto-cleanup complete. Deleted %d jobs.", deleted_count)
    return deleted_count
