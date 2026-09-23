"""Publication ambiguity must never revoke a claimed execution."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from backend.app.database_v2 import Base
from backend.app.models.job import Job
from backend.app.services import job_dispatch as dispatch, job_runtime as runtime


def test_queued_attempt_migration_preserves_history_and_defaults(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    migration_path = Path(__file__).parents[2]/'backend/alembic/versions/9c7a5e3b2d01_add_queued_attempt_time.py'
    spec = importlib.util.spec_from_file_location('queued_migration', migration_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engine = create_engine(f"sqlite:///{tmp_path/'migration.db'}")
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE jobs (job_id TEXT PRIMARY KEY, created_at TEXT NOT NULL)')
        connection.exec_driver_sql("INSERT INTO jobs VALUES ('old', '2020-01-01T00:00:00Z')")
        monkeypatch.setattr(module, 'op', Operations(MigrationContext.configure(connection)))
        module.upgrade()
        assert connection.exec_driver_sql('SELECT queued_at FROM jobs').scalar() == '2020-01-01T00:00:00Z'
        connection.exec_driver_sql("INSERT INTO jobs (job_id, created_at) VALUES ('new', 'historical')")
        value = connection.exec_driver_sql("SELECT queued_at FROM jobs WHERE job_id='new'").scalar()
        assert value.endswith('Z') and value > '2020-01-01'
        module.downgrade()
        assert connection.exec_driver_sql('SELECT count(*) FROM jobs').scalar() == 2


@pytest.mark.parametrize('claimed', [False, True])
def test_failure_event_is_once_after_commit_only_for_winner(db, monkeypatch, claimed):
    from backend.app import worker
    events = []
    def emit(job_id, status):
        with Session(db.get_bind()) as observer:
            assert observer.get(Job, job_id).status == status == 'failed'
        events.append((job_id, status))
        raise ConnectionError('private event payload')
    monkeypatch.setattr(worker, '_emit_complete', emit)
    def sender(**kw):
        if claimed:
            with Session(db.get_bind()) as observer:
                runtime.claim_job(observer, 'job', kw['task_id'], 'token', 'worker')
        raise ConnectionError('private broker payload')
    if claimed:
        assert dispatch.dispatch_job(db, 'job', sender=sender).status == 'running'
    else:
        with pytest.raises(dispatch.JobDispatchFailed):
            dispatch.dispatch_job(db, 'job', sender=sender)
    assert events == ([] if claimed else [('job', 'failed')])


@pytest.mark.parametrize('during_publish', [False, True])
def test_reanalysis_has_fresh_database_time_grace(db, during_publish):
    from backend.app.models.job_pcap import JobPcap
    from backend.app.services.job_lifecycle import reanalyze_job
    job = db.get(Job, 'job')
    job.status = 'completed'
    db.add(JobPcap(job_id='job', upload_id='upload', ordinal=0, filename='test.pcap', label='phase'))
    db.commit()
    sent = []
    def reconcile():
        with Session(db.get_bind()) as observer:
            assert runtime.reconcile_stale_jobs(observer, stale_seconds=120, undispatched_grace_seconds=30).failed_undispatched == 0
            row = observer.get(Job, 'job')
            assert row.created_at == '2020-01-01T00:00:00Z'
            assert row.queued_at > row.created_at
    def phase(session, job_id, label):
        if not during_publish:
            reconcile()
        def sender(**kw):
            if during_publish:
                reconcile()
            sent.append(kw['task_id'])
        dispatch.dispatch_job(session, job_id, pcap_label=label, sender=sender)
    reanalyze_job(job, db, 'phase', phase)
    assert len(sent) == 1
    assert runtime.claim_job(db, 'job', sent[0], 'new-token', 'worker').disposition == 'claimed'


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
    from sqlalchemy import update
    db.execute(update(Job).values(queued_at=runtime._now(-31)))
    db.commit()
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
