"""Publication ambiguity must never revoke a claimed execution."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from backend.app.database_v2 import Base
from backend.app.models.job import Job
from backend.app.services import job_dispatch as dispatch, job_runtime as runtime


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'dispatch.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Job(job_id='job', status='queued', execution_profile='standard', created_at='2020-01-01T00:00:00Z'))
        session.commit()
        yield session
    engine.dispose()


@pytest.mark.parametrize('phase', [None, 'phase-a'])
def test_identity_is_committed_before_publish_and_phase_parity(db, phase):
    def sender(*, task_id, args):
        with Session(db.get_bind()) as observer:
            assert observer.get(Job, 'job').celery_task_id == task_id == 'task-a'
        assert args == (['job'] if phase is None else ['job', phase])
    result = dispatch.dispatch_job(db, 'job', pcap_label=phase, sender=sender, task_id_factory=lambda: 'task-a')
    assert result.status == 'queued'
    assert db.get(Job, 'job').dispatched_at


def test_publish_exception_cannot_overwrite_fast_worker_claim(db):
    def sender(**kwargs):
        with Session(db.get_bind()) as worker:
            runtime.claim_job(worker, 'job', kwargs['task_id'], 'token', 'worker')
        raise ConnectionError('redis://secret:password@broker')
    result = dispatch.dispatch_job(db, 'job', sender=sender, task_id_factory=lambda: 'task-a')
    assert result.status == 'running'
    assert db.get(Job, 'job').error_summary is None


def test_definite_failure_has_stable_public_error_and_late_delivery_is_terminal(db):
    def sender(**kwargs):
        raise ConnectionError('redis://secret:password@broker')
    with pytest.raises(dispatch.JobDispatchFailed) as error:
        dispatch.dispatch_job(db, 'job', sender=sender, task_id_factory=lambda: 'task-a')
    assert error.value.detail == {'code': 'JOB_DISPATCH_FAILED', 'job_id': 'job'}
    assert 'redis' not in db.get(Job, 'job').error_summary
    assert runtime.claim_job(db, 'job', 'task-a', 'token', 'worker').disposition == 'terminal'


def test_confirmed_publish_cannot_be_failed(db):
    runtime.assign_task(db, 'job', 'task-a')
    runtime.mark_dispatched(db, 'job', 'task-a')
    assert not runtime.mark_dispatch_failed(db, 'job', 'task-a', 'failed')


def test_publisher_process_loss_is_reconciled_without_replay(db):
    runtime.assign_task(db, 'job', 'task-a')
    result = runtime.reconcile_stale_jobs(db, stale_seconds=120, undispatched_grace_seconds=30)
    assert result.failed_undispatched == 1
    assert runtime.claim_job(db, 'job', 'task-a', 'token', 'worker').disposition == 'terminal'



@pytest.mark.parametrize('route,service', [('create_job','create_job_from_upload'), ('create_job_from_arkime','create_job_from_arkime'), ('create_job_from_security_onion','create_job_from_security_onion')])
def test_creation_and_import_routes_return_stable_503(db, monkeypatch, route, service):
    import asyncio
    from fastapi import Response
    from backend.app.api import jobs
    from backend.app.schemas.job import JobCreateResponse
    from backend.app import worker
    response = JobCreateResponse(schema_version='1.0', job_id='job')
    def create(*args):
        return response
    async def import_job(*args):
        return response
    module = jobs.job_creation if route == 'create_job' else jobs.job_imports
    monkeypatch.setattr(module, service, create if route == 'create_job' else import_job)
    def publish(**kw):
        raise ConnectionError('redis://private-broker')
    monkeypatch.setattr(worker.run_job, 'apply_async', publish)
    with pytest.raises(dispatch.JobDispatchFailed) as error:
        asyncio.run(getattr(jobs, route)(body=None, response=Response(), request_id='request', db=db, settings=None))
    assert error.value.status_code == 503
    assert error.value.detail == {'code':'JOB_DISPATCH_FAILED','job_id':'job'}
