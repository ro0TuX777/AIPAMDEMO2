"""Runtime ownership and public model contracts."""
import importlib

from backend.app.models.job import Job
from backend.app.schemas.common import JobStatus
from backend.app.schemas.job import JobListItem


def test_canceling_is_active_not_terminal():
    assert "canceling" in JobStatus._value2member_map_
    runtime = importlib.import_module("backend.app.services.job_runtime")
    assert "canceling" not in runtime.TERMINAL_JOB_STATUSES


def test_job_response_exposes_liveness_but_not_ownership():
    public = JobListItem.model_fields
    assert {"heartbeat_at", "cancel_requested_at"} <= public.keys()
    assert (
        not {
            "run_token",
            "celery_task_id",
            "accepted_run_manifest_json",
            "executor_pid",
            "artifact_layout_version",
        }
        & public.keys()
    )
    assert Job.__table__.c.artifact_layout_version.default.arg == 2


import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session
from backend.app.database_v2 import Base


@pytest.fixture
def runtime():
    module = importlib.import_module("backend.app.services.job_runtime")
    return module


@pytest.fixture
def db(tmp_path):
    engine = sa.create_engine(f"sqlite:///{(tmp_path / 'runtime.db').as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            Job(
                job_id="job",
                status="queued",
                execution_profile="standard",
                created_at="2026-01-01T00:00:00Z",
            )
        )
        session.commit()
        yield session
    engine.dispose()


def claim(runtime, db):
    assert runtime.assign_task(db, "job", "task-a") == 1
    result = runtime.claim_job(db, "job", "task-a", "token-a", worker_id="worker-a")
    assert result.disposition == runtime.ClaimDisposition.claimed
    return result.handle


def test_only_matching_queued_task_can_claim(runtime, db):
    assert runtime.assign_task(db, "job", "task-a") == 1
    assert (
        runtime.claim_job(db, "job", "task-b", "token-b", worker_id="w1").disposition
        == runtime.ClaimDisposition.superseded
    )
    first = runtime.claim_job(db, "job", "task-a", "token-a", worker_id="w1")
    assert first.disposition == runtime.ClaimDisposition.claimed
    assert first.handle == runtime.RunHandle("job", "task-a", "token-a", 1)
    assert (
        runtime.claim_job(db, "job", "task-a", "token-c", worker_id="w2").disposition
        == runtime.ClaimDisposition.busy
    )
    assert db.get(Job, "job").run_token == "token-a"
    assert runtime.assign_task(db, "job", "replacement") == 0


def test_dispatch_compare_and_swap_and_fast_claim(runtime, db):
    runtime.assign_task(db, "job", "task-a")
    assert not runtime.mark_dispatched(db, "job", "old-task")
    assert not runtime.mark_dispatch_failed(db, "job", "old-task", "old error")
    handle = runtime.claim_job(db, "job", "task-a", "token-a", worker_id="w1").handle
    assert runtime.mark_dispatched(db, "job", "task-a")
    assert not runtime.mark_dispatch_failed(db, "job", "task-a", "late publisher error")
    assert db.get(Job, "job").status == "running"
    assert db.get(Job, "job").dispatched_at
    assert handle.execution_attempt == 1


def test_dispatch_failure_terminalizes_once(runtime, db):
    runtime.assign_task(db, "job", "task-a")
    assert runtime.mark_dispatch_failed(db, "job", "task-a", "Dispatch unavailable")
    job = db.get(Job, "job")
    assert (job.status, job.error_summary) == ("failed", "Dispatch unavailable")
    completed = job.completed_at
    assert not runtime.mark_dispatch_failed(db, "job", "task-a", "overwrite")
    assert db.get(Job, "job").completed_at == completed


def test_running_cancel_becomes_canceling_and_old_owner_cannot_complete(runtime, db):
    handle = claim(runtime, db)
    canceled = runtime.request_cancel(db, "job")
    assert canceled.status == "canceling"
    job = db.get(Job, "job")
    assert job.status == "canceling"
    assert job.completed_at is None
    assert db.scalar(
        sa.select(
            sa.func.julianday(job.cancel_force_at)
            - sa.func.julianday(job.cancel_requested_at)
        )
    ) * 86400 == pytest.approx(45, abs=0.001)
    assert db.scalar(
        sa.select(
            sa.func.julianday(job.cancel_deadline_at)
            - sa.func.julianday(job.cancel_requested_at)
        )
    ) * 86400 == pytest.approx(60, abs=0.001)
    assert not runtime.finalize_owned_job(
        db, handle, "completed", accepted_manifest_json='{"unsafe":true}'
    )
    assert db.get(Job, "job").accepted_run_manifest_json is None
    assert (
        runtime.heartbeat_job(db, handle)
        == runtime.HeartbeatDisposition.cancel_requested
    )
    assert runtime.finalize_owned_job(db, handle, "canceled")


def test_queued_cancel_and_repeated_cancel_are_idempotent(runtime, db):
    runtime.assign_task(db, "job", "task-a")
    assert runtime.request_cancel(db, "job").status == "canceled"
    completed = db.get(Job, "job").completed_at
    assert completed
    assert runtime.request_cancel(db, "job").status == "canceled"
    assert db.get(Job, "job").completed_at == completed
    assert (
        runtime.claim_job(db, "job", "task-a", "token", worker_id="w").disposition
        == runtime.ClaimDisposition.terminal
    )


def test_repeated_running_cancel_keeps_original_deadlines(runtime, db):
    claim(runtime, db)
    runtime.request_cancel(db, "job")
    db.execute(
        sa.update(Job).values(
            cancel_requested_at="2000-01-01T00:00:00.000Z",
            cancel_force_at="2000-01-01T00:00:45.000Z",
            cancel_deadline_at="2000-01-01T00:01:00.000Z",
        )
    )
    db.commit()
    assert runtime.request_cancel(db, "job").status == "canceling"
    assert db.get(Job, "job").cancel_force_at == "2000-01-01T00:00:45.000Z"


@pytest.mark.parametrize(
    "status", ["completed", "completed_with_errors", "failed", "deleted", "deleting"]
)
def test_terminal_cancel_conflicts(runtime, db, status):
    db.execute(sa.update(Job).values(status=status))
    db.commit()
    with pytest.raises(runtime.JobLifecycleError) as error:
        runtime.request_cancel(db, "job")
    assert error.value.status_code == 409
    assert db.get(Job, "job").status == status


def test_missing_job_dispositions(runtime, db):
    assert runtime.assign_task(db, "missing", "task") == 0
    assert (
        runtime.claim_job(db, "missing", "task", "token", worker_id="w").disposition
        == runtime.ClaimDisposition.missing
    )
    with pytest.raises(runtime.JobLifecycleError) as error:
        runtime.request_cancel(db, "missing")
    assert error.value.status_code == 404


def test_stale_token_cannot_heartbeat_register_or_finalize(runtime, db):
    handle = claim(runtime, db)
    stale = runtime.RunHandle("job", "task-a", "old-token", 1)
    identity = runtime.ExecutorIdentity(
        "worker-a", "container-1", 123, 9876543210, "boot-1"
    )
    assert not runtime.register_executor(db, stale, identity)
    assert runtime.heartbeat_job(db, stale) == runtime.HeartbeatDisposition.lost
    assert not runtime.finalize_owned_job(db, stale, "failed")
    assert runtime.register_executor(db, handle, identity)
    assert runtime.heartbeat_job(db, handle) == runtime.HeartbeatDisposition.alive
    job = db.get(Job, "job")
    assert (
        job.worker_id,
        job.worker_container_id,
        job.executor_pid,
        job.executor_pid_start_ticks,
        job.executor_boot_id,
    ) == ("worker-a", "container-1", 123, 9876543210, "boot-1")


def test_finalization_is_owned_and_completed_timestamp_set_once(runtime, db):
    handle = claim(runtime, db)
    assert runtime.finalize_owned_job(
        db,
        handle,
        "completed",
        metrics_json='{"n":1}',
        accepted_manifest_json='{"run":"a"}',
    )
    job = db.get(Job, "job")
    completed = job.completed_at
    assert completed and job.metrics_json == '{"n":1}'
    assert job.accepted_run_manifest_json == '{"run":"a"}'
    assert not runtime.finalize_owned_job(db, handle, "failed", error_summary="late")
    assert db.get(Job, "job").completed_at == completed
    assert db.get(Job, "job").status == "completed"
    assert db.get(Job, "job").executor_pid is None


def test_reconciliation_uses_database_time_and_never_replays(runtime, db):
    claim(runtime, db)
    db.execute(
        sa.update(Job).values(
            heartbeat_at=sa.func.strftime("%Y-%m-%dT%H:%M:%fZ", "now", "-119 seconds")
        )
    )
    db.commit()
    assert (
        runtime.reconcile_stale_jobs(
            db, stale_seconds=120, undispatched_grace_seconds=30
        ).failed_running
        == 0
    )
    db.execute(
        sa.update(Job).values(
            heartbeat_at=sa.func.strftime("%Y-%m-%dT%H:%M:%fZ", "now", "-121 seconds")
        )
    )
    db.commit()
    assert (
        runtime.reconcile_stale_jobs(
            db, stale_seconds=120, undispatched_grace_seconds=30
        ).failed_running
        == 1
    )
    assert db.get(Job, "job").status == "failed"
    assert db.get(Job, "job").execution_attempt == 1
    assert (
        runtime.reconcile_stale_jobs(
            db, stale_seconds=120, undispatched_grace_seconds=30
        ).failed_running
        == 0
    )


@pytest.mark.parametrize(
    "status, dispatched, age, expected",
    [
        ("canceling", False, 121, "canceled"),
        ("canceling", False, 119, "canceling"),
        ("queued", False, 31, "failed"),
        ("queued", False, 29, "queued"),
        ("queued", True, 121, "queued"),
    ],
)
def test_reconciliation_canceling_and_undispatched_grace(
    runtime, db, status, dispatched, age, expected
):
    db.execute(
        sa.update(Job).values(
            status=status,
            heartbeat_at=sa.func.strftime(
                "%Y-%m-%dT%H:%M:%fZ", "now", f"-{age} seconds"
            ),
            created_at=sa.func.strftime("%Y-%m-%dT%H:%M:%fZ", "now", f"-{age} seconds"),
            queued_at=sa.func.strftime("%Y-%m-%dT%H:%M:%fZ", "now", f"-{age} seconds"),
            dispatched_at="2026-01-01" if dispatched else None,
        )
    )
    db.commit()
    runtime.reconcile_stale_jobs(db, stale_seconds=120, undispatched_grace_seconds=30)
    assert db.get(Job, "job").status == expected


def test_escalation_force_time_lease_reclaim_and_stale_completion(runtime, db):
    handle = claim(runtime, db)
    identity = runtime.ExecutorIdentity("worker-a", "container", 123, 456, "boot")
    runtime.register_executor(db, handle, identity)
    runtime.request_cancel(db, "job")
    assert not runtime.claim_cancel_escalation(
        db, "job", "lease-a", lease_seconds=15
    ).claimed
    db.execute(
        sa.update(Job).values(
            cancel_force_at=sa.func.strftime("%Y-%m-%dT%H:%M:%fZ", "now", "-1 seconds")
        )
    )
    db.commit()
    lease = runtime.claim_cancel_escalation(db, "job", "lease-a", lease_seconds=15)
    assert lease.claimed and lease.handle == handle and lease.identity == identity
    assert not runtime.claim_cancel_escalation(
        db, "job", "lease-b", lease_seconds=15
    ).claimed
    db.execute(
        sa.update(Job).values(
            cancel_escalation_started_at=sa.func.strftime(
                "%Y-%m-%dT%H:%M:%fZ", "now", "-16 seconds"
            )
        )
    )
    db.commit()
    assert runtime.claim_cancel_escalation(
        db, "job", "lease-b", lease_seconds=15
    ).claimed
    assert not runtime.complete_cancel_escalation(db, handle, "lease-a")
    stale = runtime.RunHandle("job", "task-a", "stale", 1)
    assert not runtime.complete_cancel_escalation(db, stale, "lease-b")
    assert runtime.complete_cancel_escalation(db, handle, "lease-b")
    job = db.get(Job, "job")
    assert job.status == "canceled" and job.completed_at
    assert job.executor_pid is None and job.worker_container_id is None
    assert job.cancel_escalation_token is None


def test_independent_sessions_racing_claim_have_one_winner(runtime, db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    runtime.assign_task(db, "job", "task-a")
    gate = Barrier(2)

    def run(token):
        with Session(db.bind) as other:
            gate.wait(timeout=10)
            return runtime.claim_job(other, "job", "task-a", token, worker_id=token)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, ["token-a", "token-b"]))
    assert sorted(result.disposition.value for result in results) == ["busy", "claimed"]
    db.expire_all()
    assert db.get(Job, "job").run_token == next(
        r.handle.run_token for r in results if r.handle
    )


def test_executor_registration_is_frozen_once_escalation_claims(runtime, db):
    handle = claim(runtime, db)
    identity = runtime.ExecutorIdentity("worker-a", "container", 123, 456, "boot")
    assert runtime.register_executor(db, handle, identity)
    runtime.request_cancel(db, "job")
    db.execute(sa.update(Job).values(cancel_force_at="2000-01-01T00:00:00Z"))
    db.commit()
    assert runtime.claim_cancel_escalation(db, "job", "lease", lease_seconds=15).claimed
    replacement = runtime.ExecutorIdentity(
        "worker-a", "replacement-container", 987, 654, "other-boot"
    )
    assert not runtime.register_executor(db, handle, replacement)
    assert db.get(Job, "job").worker_container_id == "container"


def test_model_package_exports_terminal_statuses():
    import backend.app.models as models

    assert "canceled" in models.TERMINAL_JOB_STATUSES
    assert "canceling" not in models.TERMINAL_JOB_STATUSES


def test_escalation_loses_if_executor_identity_changes_after_snapshot(
    runtime, db, monkeypatch
):
    handle = claim(runtime, db)
    runtime.request_cancel(db, "job")
    db.execute(sa.update(Job).values(cancel_force_at="2000-01-01T00:00:00Z"))
    db.commit()
    execute = db.execute
    raced = False

    def race(statement, *args, **kwargs):
        nonlocal raced
        if getattr(statement, "is_update", False) and not raced:
            raced = True
            with Session(db.bind) as other:
                runtime.register_executor(
                    other, handle, runtime.ExecutorIdentity("w", "new", 42, 99, "boot")
                )
        return execute(statement, *args, **kwargs)

    monkeypatch.setattr(db, "execute", race)
    assert not runtime.claim_cancel_escalation(
        db, "job", "lease", lease_seconds=15
    ).claimed
    assert db.get(Job, "job").cancel_escalation_token is None


def test_claim_returns_its_attempt_when_row_is_deleted_after_commit(
    runtime, db, monkeypatch
):
    runtime.assign_task(db, "job", "task-a")
    commit = db.commit

    def delete_after_commit():
        commit()
        with Session(db.bind) as other:
            other.execute(sa.delete(Job).where(Job.job_id == "job"))
            other.commit()

    monkeypatch.setattr(db, "commit", delete_after_commit)
    result = runtime.claim_job(db, "job", "task-a", "token-a", worker_id="w")
    assert result.handle == runtime.RunHandle("job", "task-a", "token-a", 1)
