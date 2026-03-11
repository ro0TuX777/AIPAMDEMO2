"""
Startup Recovery (§1.3) — detect and clean up interrupted jobs.

On worker startup, scan for jobs stuck in running/queued states
and transition them to failed with an appropriate error message.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.app.models.job import Job

logger = logging.getLogger("aipam.recovery")


def recover_interrupted_jobs(db: Session) -> int:
    """Scan for jobs left in running/queued state and mark them as failed.

    Called once at worker startup. Returns the number of recovered jobs.

    Per §1.3:
      - running → failed with error "interrupted_by_restart"
      - queued  → re-queued (left as-is so they can be picked up again)
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    recovered = 0

    # Find running jobs — these were interrupted mid-pipeline
    running_jobs = db.query(Job).filter(Job.status == "running").all()
    for job in running_jobs:
        logger.warning(
            "Recovering interrupted job %s (was running since %s)",
            job.job_id, job.started_at,
        )
        job.status = "failed"
        job.error_summary = "interrupted_by_restart"
        job.completed_at = now
        recovered += 1

    if recovered:
        db.commit()
        logger.info("Recovered %d interrupted job(s)", recovered)

    # Log queued jobs (they'll be picked up naturally)
    queued_count = db.query(Job).filter(Job.status == "queued").count()
    if queued_count:
        logger.info("%d queued job(s) found — will be processed normally", queued_count)

    return recovered

