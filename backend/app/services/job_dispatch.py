"""Publication ambiguity cannot revoke a claimed job."""
from dataclasses import dataclass
import logging
from uuid import uuid4
from fastapi import HTTPException
from backend.app.models.job import Job
from backend.app.services.job_runtime import assign_task, mark_dispatched, mark_dispatch_failed

logger = logging.getLogger(__name__)

class JobDispatchFailed(HTTPException):
    def __init__(self, job_id):
        super().__init__(503, {'code': 'JOB_DISPATCH_FAILED', 'job_id': job_id})

@dataclass(frozen=True)
class DispatchResult:
    status: str

def dispatch_job(db, job_id: str, *, pcap_label=None, sender=None, task_id_factory=uuid4):
    task_id = str(task_id_factory())
    if not assign_task(db, job_id, task_id):
        job = db.get(Job, job_id)
        return DispatchResult(job.status if job else 'missing')
    try:
        if sender is None:
            from backend.app.worker import run_job, run_job_phase
            sender = (run_job if pcap_label is None else run_job_phase).apply_async
        sender(args=[job_id] if pcap_label is None else [job_id, pcap_label], task_id=task_id)
    except Exception:
        logger.warning('Job publication was not confirmed for %s', job_id)
        if mark_dispatch_failed(db, job_id, task_id, 'JOB_DISPATCH_FAILED'):
            try:
                from backend.app.worker import _emit_complete
                _emit_complete(job_id, 'failed')
            except Exception:
                logger.warning('Terminal event publication unavailable for %s', job_id)
            raise JobDispatchFailed(job_id) from None
    else:
        mark_dispatched(db, job_id, task_id)
    db.expire_all()
    return DispatchResult(db.get(Job, job_id).status)

def dispatch_job_phase(db, job_id: str, pcap_label: str):
    return dispatch_job(db, job_id, pcap_label=pcap_label)
