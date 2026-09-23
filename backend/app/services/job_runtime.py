"""Durable job ownership and cancellation; all timestamps come from SQLite.

Every mutating operation commits its compare-and-set result before returning.
Callers must use a dedicated lifecycle session, not a session with pending
analysis writes. A failed predicate never changes the current owner's row.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from backend.app.models.job import Job, TERMINAL_JOB_STATUSES
from backend.app.services.job_lifecycle import JobLifecycleError

JobOutcome = Literal["completed", "completed_with_errors", "failed", "canceled"]


@dataclass(frozen=True)
class RunHandle:
    job_id: str
    task_id: str
    run_token: str
    execution_attempt: int


@dataclass(frozen=True)
class ExecutorIdentity:
    worker_node: str
    worker_container_id: str
    executor_pid: int
    executor_pid_start_ticks: int
    executor_boot_id: str


class ClaimDisposition(str, Enum):
    claimed = "claimed"
    superseded = "superseded"
    busy = "busy"
    terminal = "terminal"
    missing = "missing"


@dataclass(frozen=True)
class ClaimResult:
    disposition: ClaimDisposition
    handle: RunHandle | None = None


class HeartbeatDisposition(str, Enum):
    alive = "alive"
    cancel_requested = "cancel_requested"
    lost = "lost"


@dataclass(frozen=True)
class CancelResult:
    status: str
    changed: bool


@dataclass(frozen=True)
class EscalationClaim:
    claimed: bool
    handle: RunHandle | None = None
    identity: ExecutorIdentity | None = None
    cancel_deadline_at: str | None = None


@dataclass(frozen=True)
class ReconcileStats:
    failed_running: int = 0
    canceled_canceling: int = 0
    failed_undispatched: int = 0


def _now(offset_seconds: int = 0):
    modifiers = (f"{offset_seconds:+d} seconds",) if offset_seconds else ()
    return func.strftime("%Y-%m-%dT%H:%M:%fZ", "now", *modifiers)


def _owned(handle: RunHandle):
    return (
        Job.job_id == handle.job_id,
        Job.celery_task_id == handle.task_id,
        Job.run_token == handle.run_token,
        Job.execution_attempt == handle.execution_attempt,
    )


def _apply(db: Session, statement) -> bool:
    changed = (
        db.execute(statement.execution_options(synchronize_session=False)).rowcount == 1
    )
    db.commit()
    db.expire_all()
    return changed


def _read(db: Session, job_id: str):
    # Read column values, never an identity-map instance left stale by a rival.
    return (
        db.execute(select(Job.__table__).where(Job.job_id == job_id)).mappings().first()
    )


def _clear_executor():
    return dict(
        worker_id=None,
        worker_container_id=None,
        executor_pid=None,
        executor_pid_start_ticks=None,
        executor_boot_id=None,
        cancel_escalation_token=None,
        cancel_escalation_started_at=None,
    )


def assign_task(db: Session, job_id: str, task_id: str) -> int:
    """Assign exactly one dispatch identity; return 1 for the CAS winner."""
    return int(
        _apply(
            db,
            update(Job)
            .where(
                Job.job_id == job_id,
                Job.status == "queued",
                Job.celery_task_id.is_(None),
            )
            .values(celery_task_id=task_id),
        )
    )


def mark_dispatched(db: Session, job_id: str, task_id: str) -> bool:
    # A worker can claim (or even finish) before the publisher records success.
    return _apply(
        db,
        update(Job)
        .where(
            Job.job_id == job_id,
            Job.celery_task_id == task_id,
            Job.dispatched_at.is_(None),
            Job.status.in_(("queued", "running")),
        )
        .values(dispatched_at=_now()),
    )


def mark_dispatch_failed(
    db: Session, job_id: str, task_id: str, public_error: str
) -> bool:
    return _apply(
        db,
        update(Job)
        .where(
            Job.job_id == job_id,
            Job.celery_task_id == task_id,
            Job.status == "queued",
            Job.dispatched_at.is_(None),
        )
        .values(
            status="failed",
            error_summary=public_error,
            completed_at=func.coalesce(Job.completed_at, _now()),
        ),
    )


def claim_job(
    db: Session, job_id: str, task_id: str, run_token: str, worker_id: str
) -> ClaimResult:
    # Ownership is never inferred from elapsed time. Only queued work can claim.
    changed = (
        db.execute(
            update(Job)
            .where(
                Job.job_id == job_id,
                Job.celery_task_id == task_id,
                Job.status == "queued",
                Job.run_token.is_(None),
                Job.cancel_requested_at.is_(None),
            )
            .values(
                status="running",
                run_token=run_token,
                worker_id=worker_id,
                execution_attempt=Job.execution_attempt + 1,
                started_at=func.coalesce(Job.started_at, _now()),
                heartbeat_at=_now(),
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        == 1
    )
    # Capture the attempt while the write transaction still owns the row.
    # A deletion immediately after commit must not turn a winning claim into
    # an exception, or return a handle assembled from a subsequent job row.
    row = _read(db, job_id)
    handle = (
        RunHandle(job_id, task_id, run_token, row["execution_attempt"])
        if changed
        else None
    )
    db.commit()
    db.expire_all()
    if changed:
        return ClaimResult(ClaimDisposition.claimed, handle)
    if row is None:
        return ClaimResult(ClaimDisposition.missing)
    if row["celery_task_id"] != task_id:
        return ClaimResult(ClaimDisposition.superseded)
    if row["status"] in TERMINAL_JOB_STATUSES or row["status"] == "deleting":
        return ClaimResult(ClaimDisposition.terminal)
    return ClaimResult(ClaimDisposition.busy)


def register_executor(
    db: Session, handle: RunHandle, identity: ExecutorIdentity
) -> bool:
    return _apply(
        db,
        update(Job)
        .where(
            *_owned(handle),
            Job.status.in_(("running", "canceling")),
            Job.cancel_escalation_token.is_(None),
        )
        .values(
            worker_id=identity.worker_node,
            worker_container_id=identity.worker_container_id,
            executor_pid=identity.executor_pid,
            executor_pid_start_ticks=identity.executor_pid_start_ticks,
            executor_boot_id=identity.executor_boot_id,
        ),
    )


def heartbeat_job(db: Session, handle: RunHandle) -> HeartbeatDisposition:
    if not _apply(
        db,
        update(Job)
        .where(*_owned(handle), Job.status.in_(("running", "canceling")))
        .values(heartbeat_at=_now()),
    ):
        return HeartbeatDisposition.lost
    row = _read(db, handle.job_id)
    if row is None or row["status"] not in ("running", "canceling"):
        return HeartbeatDisposition.lost
    return (
        HeartbeatDisposition.cancel_requested
        if row["status"] == "canceling"
        else HeartbeatDisposition.alive
    )


def request_cancel(db: Session, job_id: str) -> CancelResult:
    if _apply(
        db,
        update(Job)
        .where(Job.job_id == job_id, Job.status == "queued")
        .values(
            status="canceled",
            cancel_requested_at=_now(),
            completed_at=func.coalesce(Job.completed_at, _now()),
            cancel_force_at=_now(45),
            cancel_deadline_at=_now(60),
        ),
    ):
        return CancelResult("canceled", True)
    if _apply(
        db,
        update(Job)
        .where(Job.job_id == job_id, Job.status == "running")
        .values(
            status="canceling",
            cancel_requested_at=_now(),
            cancel_force_at=_now(45),
            cancel_deadline_at=_now(60),
        ),
    ):
        return CancelResult("canceling", True)
    row = _read(db, job_id)
    if row is None:
        raise JobLifecycleError(404, "Job not found")
    if row["status"] in ("canceling", "canceled"):
        return CancelResult(row["status"], False)
    raise JobLifecycleError(409, f"Cannot cancel job in '{row['status']}' state")


def claim_cancel_escalation(
    db: Session, job_id: str, escalation_token: str, *, lease_seconds: int
) -> EscalationClaim:
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    row = _read(db, job_id)
    if (
        row is None
        or row["status"] != "canceling"
        or not row["celery_task_id"]
        or not row["run_token"]
    ):
        return EscalationClaim(False)
    handle = RunHandle(
        job_id, row["celery_task_id"], row["run_token"], row["execution_attempt"]
    )
    changed = _apply(
        db,
        update(Job)
        .where(
            *_owned(handle),
            Job.status == "canceling",
            Job.cancel_force_at == row["cancel_force_at"],
            *(
                getattr(Job, key) == row[key]
                for key in (
                    "worker_id",
                    "worker_container_id",
                    "executor_pid",
                    "executor_pid_start_ticks",
                    "executor_boot_id",
                )
            ),
            func.julianday(Job.cancel_force_at) <= func.julianday(_now()),
            Job.cancel_escalation_token == row["cancel_escalation_token"],
            Job.cancel_escalation_started_at == row["cancel_escalation_started_at"],
            or_(
                Job.cancel_escalation_token.is_(None),
                func.julianday(Job.cancel_escalation_started_at)
                <= func.julianday(_now(-lease_seconds)),
            ),
        )
        .values(
            cancel_escalation_token=escalation_token,
            cancel_escalation_started_at=_now(),
        ),
    )
    if not changed:
        return EscalationClaim(False)
    identity = None
    if all(
        row[k] is not None
        for k in (
            "worker_id",
            "worker_container_id",
            "executor_pid",
            "executor_pid_start_ticks",
            "executor_boot_id",
        )
    ):
        identity = ExecutorIdentity(
            row["worker_id"],
            row["worker_container_id"],
            row["executor_pid"],
            row["executor_pid_start_ticks"],
            row["executor_boot_id"],
        )
    return EscalationClaim(True, handle, identity, row["cancel_deadline_at"])


def complete_cancel_escalation(
    db: Session, handle: RunHandle, escalation_token: str
) -> bool:
    return _apply(
        db,
        update(Job)
        .where(
            *_owned(handle),
            Job.status == "canceling",
            Job.cancel_escalation_token == escalation_token,
        )
        .values(
            status="canceled",
            completed_at=func.coalesce(Job.completed_at, _now()),
            **_clear_executor(),
        ),
    )


def finalize_owned_job(
    db: Session,
    handle: RunHandle,
    outcome: JobOutcome,
    *,
    error_summary: str | None = None,
    metrics_json: str | None = None,
    accepted_manifest_json: str | None = None,
) -> bool:
    if outcome not in ("completed", "completed_with_errors", "failed", "canceled"):
        raise ValueError(f"Invalid job outcome: {outcome}")
    allowed = ("running", "canceling") if outcome == "canceled" else ("running",)
    return _apply(
        db,
        update(Job)
        .where(*_owned(handle), Job.status.in_(allowed))
        .values(
            status=outcome,
            completed_at=func.coalesce(Job.completed_at, _now()),
            error_summary=error_summary,
            metrics_json=metrics_json,
            accepted_run_manifest_json=accepted_manifest_json
            if outcome in ("completed", "completed_with_errors")
            else None,
            **_clear_executor(),
        ),
    )


def reconcile_stale_jobs(
    db: Session, *, stale_seconds: int, undispatched_grace_seconds: int, emit=None
) -> ReconcileStats:
    if stale_seconds <= 0 or undispatched_grace_seconds <= 0:
        raise ValueError("Reconciliation thresholds must be positive")
    counts = []
    terminal_rows = []
    for status, outcome, cutoff, age, error in (
        (
            "running",
            "failed",
            func.coalesce(Job.heartbeat_at, Job.started_at, Job.created_at),
            stale_seconds,
            "Worker heartbeat expired",
        ),
        (
            "canceling",
            "canceled",
            func.coalesce(Job.heartbeat_at, Job.started_at, Job.created_at),
            stale_seconds,
            None,
        ),
        (
            "queued",
            "failed",
            Job.created_at,
            undispatched_grace_seconds,
            "Job dispatch was not confirmed",
        ),
    ):
        conditions = [
            Job.status == status,
            func.julianday(cutoff) < func.julianday(_now(-age)),
        ]
        if status == "queued":
            conditions.append(Job.dispatched_at.is_(None))
        if status == "canceling":
            # The supervisor must prove any recorded writer has stopped.
            conditions.extend((Job.executor_pid.is_(None), Job.error_summary.is_(None)))
        result = db.execute(
            update(Job)
            .where(*conditions)
            .values(
                status=outcome,
                completed_at=func.coalesce(Job.completed_at, _now()),
                error_summary=error,
                accepted_run_manifest_json=None,
                **_clear_executor(),
            )
            .returning(Job.job_id, Job.status)
            .execution_options(synchronize_session=False)
        )
        rows = result.all()
        counts.append(len(rows))
        terminal_rows.extend(rows)
    db.commit()
    db.expire_all()
    if emit is not None:
        for job_id, status in terminal_rows:
            emit(job_id, status)
    return ReconcileStats(*counts)
