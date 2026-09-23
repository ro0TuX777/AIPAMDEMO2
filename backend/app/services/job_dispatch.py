"""Persist delivery identity before publishing analysis work."""
import logging
from uuid import uuid4

_logger = logging.getLogger("aipam.api.jobs")


def _dispatch(job_id: str, pcap_label: str | None = None) -> None:
    from backend.app.database_v2 import get_session_factory
    from backend.app.services.job_runtime import assign_task, mark_dispatched, mark_dispatch_failed
    from backend.app.worker import run_job, run_job_phase

    factory = get_session_factory()
    task_id = str(uuid4())
    with factory() as db:
        if not assign_task(db, job_id, task_id):
            return
    try:
        task = run_job if pcap_label is None else run_job_phase
        args = [job_id] if pcap_label is None else [job_id, pcap_label]
        task.apply_async(args=args, task_id=task_id)
    except Exception:
        with factory() as db:
            mark_dispatch_failed(db, job_id, task_id, "Failed to dispatch analysis task")
        raise
    with factory() as db:
        mark_dispatched(db, job_id, task_id)


def dispatch_job(job_id: str) -> None:
    try:
        _dispatch(job_id)
    except Exception:
        _logger.warning("Failed to dispatch job %s to Celery", job_id, exc_info=True)


def dispatch_job_phase(job_id: str, pcap_label: str) -> None:
    _dispatch(job_id, pcap_label)
