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
import sys

from celery import Celery
from celery.signals import worker_process_init, worker_process_shutdown

from backend.app.config_v2 import get_settings
from backend.app.pipeline.outcomes import public_failure, public_failure_summary

logger = logging.getLogger("aipam.worker")
_schema_lock_context = None


@worker_process_init.connect(weak=False)
def _acquire_schema_lock(**_kwargs):
    global _schema_lock_context
    from pathlib import Path
    from backend.app.schema_bootstrap import assert_schema_current, schema_lock
    path = Path(os.environ.get("AIPAM_DB_PATH", "/data/aipam.db"))
    context = schema_lock(path, exclusive=False)
    context.__enter__()
    try:
        assert_schema_current(path)
    except BaseException:
        context.__exit__(*sys.exc_info())
        raise
    _schema_lock_context = context


@worker_process_shutdown.connect(weak=False)
def _release_schema_lock(**_kwargs):
    global _schema_lock_context
    if _schema_lock_context is not None:
        _schema_lock_context.__exit__(None, None, None)
        _schema_lock_context = None

# ---------------------------------------------------------------------------
# Celery application
# ---------------------------------------------------------------------------

_redis_url = os.getenv("AIPAM_REDIS_URL", "redis://redis:6379/0")

celery_app = Celery(
    "aipam_v2",
    broker=_redis_url,
    backend=_redis_url,
)

_runtime_settings = get_settings()

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_concurrency=1,
    worker_max_tasks_per_child=1,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=_runtime_settings.aipam_task_soft_time_limit,
    task_time_limit=_runtime_settings.aipam_task_time_limit,
    broker_transport_options={"visibility_timeout": _runtime_settings.aipam_visibility_timeout},
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
        logger.warning("Could not publish terminal event for %s", job_id)


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
        logger.warning("Could not clean private run for %s", handle.job_id)


def _require_cleanup_complete(control) -> None:
    # None is possible only before the run control is constructed, before
    # executor registration or pipeline work can create execution resources.
    if control is not None and not control.cleanup_complete:
        from backend.app.bluescrub.isolation.runner import ProcessCleanupIncomplete
        raise ProcessCleanupIncomplete('JOB_CLEANUP_INCOMPLETE')


def _stop_interrupted_execution(control, job_id) -> bool:
    """Retry interrupted cleanup without replacing the original task error."""
    for _ in range(2):
        try:
            if control is not None:
                control.stop()
            _require_cleanup_complete(control)
            return True
        except BaseException:
            # Includes Celery soft timeouts. No provider/OS exception payloads.
            logger.warning('JOB_CLEANUP_INCOMPLETE for job %s; retrying cleanup', job_id)
    logger.error('JOB_CLEANUP_INCOMPLETE for job %s; receipts retained for recovery', job_id)
    return False


def _resolve_interrupted(factory, settings, handle, error=None, *, control) -> str:
    _require_cleanup_complete(control)
    from backend.app.models.job import Job
    from backend.app.services.job_runtime import finalize_owned_job
    from backend.app.pipeline.outcomes import OwnershipLost
    with factory() as db:
        job = db.get(Job, handle.job_id)
        owned = job is not None and (job.celery_task_id, job.run_token, job.execution_attempt) == (
            handle.task_id, handle.run_token, handle.execution_attempt)
        status = "superseded"
        if owned and (job.status == "canceling" or (job.status == "running" and not isinstance(error, OwnershipLost))):
            status = "canceled" if job.status == "canceling" else "failed"
            if finalize_owned_job(db, handle, status, error_summary=public_failure(error) if error else None):
                _emit_complete(handle.job_id, status)
            else:
                # Exactly one recovery re-read: cancellation may have won the
                # failed-CAS race without changing the execution identity.
                db.expire_all()
                current = db.get(Job, handle.job_id)
                same_owner = current is not None and (
                    current.celery_task_id, current.run_token, current.execution_attempt
                ) == (handle.task_id, handle.run_token, handle.execution_attempt)
                status = "superseded"
                if same_owner and current.status == "canceling":
                    if finalize_owned_job(db, handle, "canceled"):
                        status = "canceled"
                        _emit_complete(handle.job_id, status)
        db.expire_all()
        _cleanup_private_run(settings, handle, db.get(Job, handle.job_id))
        return status


def execute_job(job_id: str, task_id: str, pcap_label: str | None = None, *, worker_node: str | None = None) -> str:
    """Own exactly one run; terminal persistence occurs only through Task 1 CAS."""
    import json
    import socket
    import uuid
    import docker
    from backend.app.database_v2 import get_session_factory, get_fenced_session_factory
    from backend.app.pipeline.orchestrator import run_pipeline
    from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost
    from backend.app.pipeline.run_artifacts import create_run_output_dir
    from backend.app.services.job_runtime import claim_job, finalize_owned_job, register_executor
    from backend.app.pipeline.runtime_control import ExecutionControl, current_executor, JobOwnershipLost, atomic_json

    settings = get_settings()
    factory = get_session_factory()
    with factory() as lifecycle:
        claim = claim_job(lifecycle, job_id, task_id, str(uuid.uuid4()), worker_node or socket.gethostname())
    if claim.handle is None:
        return claim.disposition.value
    handle = claim.handle
    db = None
    control = None
    old_control_dir = os.environ.get('AIPAM_RUN_CONTROL_DIR')
    try:
        run_output_dir = create_run_output_dir(settings.aipam_job_root, job_id, handle.run_token)
        control = ExecutionControl(handle, run_output_dir, factory,
                                   heartbeat_seconds=settings.aipam_heartbeat_seconds)
        try:
            docker_client = docker.from_env(timeout=3)
        except Exception:
            logger.warning("Docker unavailable; container sensors may fail")
            docker_client = None
        identity = current_executor(worker_node or socket.gethostname(), docker_client)
        from dataclasses import asdict
        atomic_json(run_output_dir / "control" / "executor.json",
                    {"handle": asdict(handle), "identity": asdict(identity), "resource_protocol": 1})
        with factory() as lifecycle:
            if not register_executor(lifecycle, handle, identity):
                raise JobOwnershipLost()
        os.environ['AIPAM_RUN_CONTROL_DIR'] = str((run_output_dir / 'control').resolve())
        control.start()
        db = get_fenced_session_factory(handle)()
        outcome = run_pipeline(
            job_id=job_id, db=db, docker_client=docker_client,
            job_root=settings.aipam_job_root, upload_root=settings.aipam_upload_root,
            sensor_config_dir=settings.aipam_sensor_config_dir,
            max_job_disk_bytes=settings.aipam_max_job_disk_bytes,
            preflight_multiplier=settings.aipam_preflight_multiplier,
            pcap_label=pcap_label, run_output_dir=run_output_dir,
            control=control,
        )
        db.commit()
        db.close()
        db = None
        # Receipt cleanup must win before any terminal CAS, including success.
        control.stop()
        _require_cleanup_complete(control)
        with factory() as lifecycle:
            finalized = finalize_owned_job(
                lifecycle, handle, outcome.status,
                metrics_json=json.dumps(outcome.metrics),
                error_summary=public_failure_summary((*outcome.required_failures, *outcome.optional_failures)),
                accepted_manifest_json=outcome.accepted_manifest_json,
            )
    except BaseException as exc:
        if db is not None:
            try:
                db.rollback()
            except BaseException:
                logger.warning("Pipeline rollback failed for %s", job_id)
            finally:
                try:
                    db.close()
                except BaseException:
                    logger.warning("Pipeline session close failed for %s", job_id)
        if not _stop_interrupted_execution(control, job_id):
            raise
        status = _resolve_interrupted(factory, settings, handle, exc, control=control)
        if isinstance(exc, (PipelineCanceled, OwnershipLost)):
            return status
        raise
    finally:
        if old_control_dir is None:
            os.environ.pop('AIPAM_RUN_CONTROL_DIR', None)
        else:
            os.environ['AIPAM_RUN_CONTROL_DIR'] = old_control_dir

    if not finalized:
        return _resolve_interrupted(factory, settings, handle, control=control)
    _emit_complete(job_id, outcome.status)
    if outcome.status in ("completed", "completed_with_errors"):
        try:
            distill_job.delay(job_id)
        except Exception:
            logger.warning("Distillation dispatch failed for %s", job_id)
    else:
        from backend.app.models.job import Job
        with factory() as lifecycle:
            _cleanup_private_run(settings, handle, lifecycle.get(Job, job_id))
    return outcome.status


@celery_app.task(bind=True, name="aipam.run_job", max_retries=0)
def run_job(self, job_id: str) -> str:
    return execute_job(job_id, self.request.id, worker_node=self.request.hostname)


@celery_app.task(bind=True, name="aipam.run_job_phase", max_retries=0)
def run_job_phase(self, job_id: str, pcap_label: str) -> str:
    return execute_job(job_id, self.request.id, pcap_label, worker_node=self.request.hostname)


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
        logger.info("Distillation completed for job %s", job_id)
        return {"status": "completed", "result": result}
    except Exception:
        logger.warning("Distillation failed for %s", job_id)
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
        logger.warning("Prune task failed with unhandled error")
        return {"status": "error", "message": public_failure(e)}
    finally:
        db.close()

