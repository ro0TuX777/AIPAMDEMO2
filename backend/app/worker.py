"""
AIPAM V2 Celery worker entry point.

Usage:
    celery -A backend.app.worker worker --loglevel=info --concurrency=1

This module creates the Celery app instance and defines the ``run_job``
task that wraps the V2 pipeline orchestrator.
"""

from __future__ import annotations

import logging
import os

from celery import Celery

from backend.app.config_v2 import get_settings

logger = logging.getLogger("aipam.worker")

# ---------------------------------------------------------------------------
# Celery application
# ---------------------------------------------------------------------------

_redis_url = os.getenv("AIPAM_REDIS_URL", "redis://redis:6379/0")

celery_app = Celery(
    "aipam_v2",
    broker=_redis_url,
    backend=_redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
)

celery_app.conf.beat_schedule = {
    "prune-old-jobs-daily": {
        "task": "aipam.prune_old_jobs",
        "schedule": 86400.0,  # Once per day
    },
}


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="aipam.run_job", max_retries=0)
def run_job(self, job_id: str) -> str:
    """Execute the V2 pipeline orchestrator for a single job.

    This is the main Celery task dispatched when a user creates a new
    analysis job via the API.

    Returns:
        Final job status string (``completed``, ``completed_with_errors``,
        ``failed``).
    """
    import docker

    from backend.app.database_v2 import get_session_factory, init_v2_db
    from backend.app.pipeline.orchestrator import run_pipeline

    logger.info("Worker received job %s", job_id)

    settings = get_settings()

    # Ensure tables exist (idempotent)
    init_v2_db()

    session_factory = get_session_factory()
    db = session_factory()

    try:
        docker_client = docker.from_env()
    except Exception:
        logger.warning("Docker not available — sensor containers will fail")
        docker_client = None  # type: ignore[assignment]

    try:
        status = run_pipeline(
            job_id=job_id,
            db=db,
            docker_client=docker_client,
            job_root=settings.aipam_job_root,
            upload_root=settings.aipam_upload_root,
            sensor_config_dir=settings.aipam_sensor_config_dir,
            max_job_disk_bytes=settings.aipam_max_job_disk_bytes,
            preflight_multiplier=settings.aipam_preflight_multiplier,
        )
        logger.info("Job %s finished with status: %s", job_id, status)
        return status
    except Exception:
        logger.exception("Job %s failed with unhandled exception", job_id)
        raise
    finally:
        db.close()


@celery_app.task(bind=True, name="aipam.run_job_phase", max_retries=0)
def run_job_phase(self, job_id: str, pcap_label: str) -> str:
    """Re-run the pipeline for a specific PCAP label (temporal phase).

    This allows "Before/After" analysis: only PCAPs with the given label
    are processed, and all resulting evidence is tagged with pcap_label.

    Returns:
        Final job status string.
    """
    import docker

    from backend.app.database_v2 import get_session_factory, init_v2_db
    from backend.app.pipeline.orchestrator import run_pipeline

    logger.info("Worker received phase re-analysis: job=%s label=%s", job_id, pcap_label)

    settings = get_settings()
    init_v2_db()

    session_factory = get_session_factory()
    db = session_factory()

    try:
        docker_client = docker.from_env()
    except Exception:
        logger.warning("Docker not available — sensor containers will fail")
        docker_client = None  # type: ignore[assignment]

    try:
        status = run_pipeline(
            job_id=job_id,
            db=db,
            docker_client=docker_client,
            job_root=settings.aipam_job_root,
            upload_root=settings.aipam_upload_root,
            sensor_config_dir=settings.aipam_sensor_config_dir,
            max_job_disk_bytes=settings.aipam_max_job_disk_bytes,
            preflight_multiplier=settings.aipam_preflight_multiplier,
            pcap_label=pcap_label,
        )
        logger.info("Phase re-analysis job=%s label=%s finished: %s", job_id, pcap_label, status)
        return status
    except Exception:
        logger.exception("Phase re-analysis job=%s label=%s failed", job_id, pcap_label)
        raise
    finally:
        db.close()


@celery_app.task(name="aipam.prune_old_jobs")
def prune_old_jobs() -> dict:
    """Scheduled task to delete jobs older than the retention period (§1.6)."""
    from backend.app.database_v2 import get_session_factory
    from backend.app.services.cleanup import cleanup_old_jobs

    session_factory = get_session_factory()
    db = session_factory()
    try:
        deleted_count = cleanup_old_jobs(db)
        return {
            "status": "success",
            "pruned_count": deleted_count,
        }
    except Exception as e:
        logger.exception("Prune task failed with unhandled error")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

