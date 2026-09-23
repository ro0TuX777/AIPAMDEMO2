"""Startup recovery shares database-time periodic reconciliation."""
from backend.app.services.job_runtime import reconcile_stale_jobs


def recover_interrupted_jobs(db):
    from backend.app.worker import _emit_complete
    stats = reconcile_stale_jobs(db, stale_seconds=120, undispatched_grace_seconds=30,
                                 emit=_emit_complete)
    return stats.failed_running + stats.canceled_canceling + stats.failed_undispatched
