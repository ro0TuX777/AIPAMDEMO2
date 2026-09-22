"""Best-effort dispatch for newly queued and rerun jobs."""

import logging

_logger = logging.getLogger("aipam.api.jobs")


def dispatch_job(job_id: str) -> None:
    """Send the job to the Celery worker. Logs a warning on failure (e.g. no Redis)."""
    try:
        from backend.app.worker import run_job
        run_job.delay(job_id)
    except Exception as exc:
        _logger.warning("Failed to dispatch job %s to Celery: %s", job_id, exc)


def dispatch_job_phase(job_id: str, pcap_label: str) -> None:
    """Send a phase-specific re-analysis task to the Celery worker."""
    from backend.app.worker import run_job_phase

    run_job_phase.delay(job_id, pcap_label)
