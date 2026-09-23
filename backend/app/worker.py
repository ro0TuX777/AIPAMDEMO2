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


def _emit_complete(job_id: str, status: str) -> None:
    from backend.app.events import publish_job_event
    try:
        publish_job_event(job_id, "job.complete", {"job_id": job_id, "status": status})
    except Exception:
        logger.warning("Could not publish terminal event for %s", job_id, exc_info=True)


def _cleanup_private_run(settings, handle, job) -> None:
    """Never enumerate/delete another attempt or accepted output."""
    import json
    import shutil
    from backend.app.pipeline.run_artifacts import safe_artifact_path
    try:
        accepted = json.loads(job.accepted_run_manifest_json or "[]") if job else []
        if any(item["run_token"] == handle.run_token for item in accepted):
            return
        root = safe_artifact_path(settings.aipam_job_root, handle.job_id)
        path = safe_artifact_path(root, f".runs/{handle.run_token}")
        if path.is_dir():
            shutil.rmtree(path)
    except (ValueError, TypeError, KeyError, OSError):
        logger.warning("Could not clean private run for %s", handle.job_id, exc_info=True)


def _resolve_interrupted(factory, settings, handle, error=None) -> str:
    from backend.app.models.job import Job
    from backend.app.services.job_runtime import finalize_owned_job
    with factory() as db:
        job = db.get(Job, handle.job_id)
        owned = job is not None and (job.celery_task_id, job.run_token, job.execution_attempt) == (
            handle.task_id, handle.run_token, handle.execution_attempt)
        status = "superseded"
        if owned and job.status in ("running", "canceling"):
            status = "canceled" if job.status == "canceling" else "failed"
            if finalize_owned_job(db, handle, status, error_summary=str(error) if error else None):
                _emit_complete(handle.job_id, status)
            else:
                status = "superseded"
        db.expire_all()
        _cleanup_private_run(settings, handle, db.get(Job, handle.job_id))
        return status


def execute_job(job_id: str, task_id: str, pcap_label: str | None = None) -> str:
    """Own exactly one run; terminal persistence occurs only through Task 1 CAS."""
    import json
    import socket
    import uuid
    import docker
    from backend.app.database_v2 import get_session_factory, init_v2_db
    from backend.app.pipeline.orchestrator import run_pipeline
    from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost
    from backend.app.pipeline.run_artifacts import create_run_output_dir
    from backend.app.services.job_runtime import claim_job, finalize_owned_job

    settings = get_settings()
    init_v2_db()
    factory = get_session_factory()
    with factory() as lifecycle:
        claim = claim_job(lifecycle, job_id, task_id, str(uuid.uuid4()), socket.gethostname())
    if claim.handle is None:
        return claim.disposition.value
    handle = claim.handle
    db = None
    try:
        run_output_dir = create_run_output_dir(settings.aipam_job_root, job_id, handle.run_token)
        try:
            docker_client = docker.from_env()
        except Exception:
            logger.warning("Docker unavailable; container sensors may fail")
            docker_client = None
        db = factory()
        outcome = run_pipeline(
            job_id=job_id, db=db, docker_client=docker_client,
            job_root=settings.aipam_job_root, upload_root=settings.aipam_upload_root,
            sensor_config_dir=settings.aipam_sensor_config_dir,
            max_job_disk_bytes=settings.aipam_max_job_disk_bytes,
            preflight_multiplier=settings.aipam_preflight_multiplier,
            pcap_label=pcap_label, run_output_dir=run_output_dir,
        )
        db.commit()
        db.close()
        db = None
        with factory() as lifecycle:
            finalized = finalize_owned_job(
                lifecycle, handle, outcome.status,
                metrics_json=json.dumps(outcome.metrics),
                error_summary="; ".join(f"{f.stage}: {f.error}" for f in (*outcome.required_failures, *outcome.optional_failures)) or None,
                accepted_manifest_json=outcome.accepted_manifest_json,
            )
    except BaseException as exc:
        if db is not None:
            try:
                db.rollback()
            except Exception:
                logger.exception("Pipeline rollback failed for %s", job_id)
            finally:
                try:
                    db.close()
                except Exception:
                    logger.exception("Pipeline session close failed for %s", job_id)
        status = _resolve_interrupted(factory, settings, handle, exc)
        if isinstance(exc, (PipelineCanceled, OwnershipLost)):
            return status
        raise

    if not finalized:
        return _resolve_interrupted(factory, settings, handle)
    _emit_complete(job_id, outcome.status)
    if outcome.status in ("completed", "completed_with_errors"):
        try:
            distill_job.delay(job_id)
        except Exception:
            logger.warning("Distillation dispatch failed for %s", job_id, exc_info=True)
    else:
        from backend.app.models.job import Job
        with factory() as lifecycle:
            _cleanup_private_run(settings, handle, lifecycle.get(Job, job_id))
    return outcome.status


@celery_app.task(bind=True, name="aipam.run_job", max_retries=0)
def run_job(self, job_id: str) -> str:
    return execute_job(job_id, self.request.id)


@celery_app.task(bind=True, name="aipam.run_job_phase", max_retries=0)
def run_job_phase(self, job_id: str, pcap_label: str) -> str:
    return execute_job(job_id, self.request.id, pcap_label)


@celery_app.task(name="aipam.distill_job", max_retries=0)
def distill_job(job_id: str) -> dict:
    """Post-terminal enrichment has no authority to change analysis status."""
    import asyncio
    from backend.app.database_v2 import get_session_factory
    from backend.app.distillation import reload_teacher_config, distill_v2
    from backend.app.models.job import Job
    factory = get_session_factory()
    with factory() as db:
        job = db.get(Job, job_id)
        if job is None or job.status not in ("completed", "completed_with_errors"):
            return {"status": "skipped"}
    try:
        teacher = reload_teacher_config()
        if not teacher.enabled or not teacher.is_configured():
            return {"status": "skipped"}
        result = asyncio.run(distill_v2(db_session_factory=factory, job_id=job_id, teacher=teacher))
        logger.info("Distillation job=%s result=%s", job_id, result)
        return {"status": "completed", "result": result}
    except Exception:
        logger.exception("Distillation failed for %s", job_id)
        return {"status": "failed"}


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

