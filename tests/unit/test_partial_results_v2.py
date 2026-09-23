"""Partial snapshots use the authoritative V2 job and writer transaction."""
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import event, create_engine, text
from sqlalchemy.orm import Session
from starlette.responses import Response

from backend.app.database_v2 import Base, _set_sqlite_pragmas, get_fenced_session_factory
from backend.app.db_models import JobDB, PartialJobResultDB
from backend.app.domain_models import JobStatus
from backend.app.models.job import Job
from backend.app.partial_results import save_partial_result, get_partial_result
from backend.app.services.job_runtime import assign_task, claim_job, request_cancel
from backend.app.pipeline.runtime_control import JobCancellationRequested


@pytest.fixture
def partial_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'partial.db'}")
    event.listen(engine, 'connect', _set_sqlite_pragmas)
    Base.metadata.create_all(engine)
    JobDB.__table__.create(engine)
    PartialJobResultDB.__table__.create(engine)
    with Session(engine) as db:
        db.add(Job(job_id='v2-job', status='queued', execution_profile='standard',
                   source_type='pcap', created_at='2026-01-01T00:00:00Z'))
        db.commit()
    yield engine
    engine.dispose()


def test_partial_results_use_v2_parent_in_owned_transaction(partial_engine):
    with Session(partial_engine) as db:
        assign_task(db, 'v2-job', 'task')
        claim = claim_job(db, 'v2-job', 'task', 'run', worker_id='test')
    with get_fenced_session_factory(claim.handle, bind=partial_engine)() as db:
        save_partial_result('v2-job', {'stage': 'aggregate'}, db=db)
        save_partial_result('v2-job', {'stage': 'theories'}, db=db)
    with Session(partial_engine) as db:
        assert get_partial_result('v2-job', db=db) == {'stage': 'theories'}
        assert db.get(JobDB, 'v2-job') is None
        assert db.get(PartialJobResultDB, 'v2-job') is None
        assert db.execute(text('PRAGMA foreign_key_check')).all() == []


def test_partial_result_rolls_back_with_lost_ownership(partial_engine):
    with Session(partial_engine) as db:
        assign_task(db, 'v2-job', 'task')
        claim = claim_job(db, 'v2-job', 'task', 'run', worker_id='test')
        request_cancel(db, 'v2-job')
    with get_fenced_session_factory(claim.handle, bind=partial_engine)() as db:
        with pytest.raises(JobCancellationRequested):
            save_partial_result('v2-job', {'stage': 'aggregate'}, db=db)
        db.rollback()
    with Session(partial_engine) as db:
        assert get_partial_result('v2-job', db=db) is None


def test_legacy_snapshot_and_parent_are_not_overwritten(partial_engine):
    now = datetime.now(timezone.utc)
    with Session(partial_engine) as db:
        db.add(JobDB(id='v2-job', source='existing', mode='existing',
                     created_at=now, updated_at=now, status=JobStatus.COMPLETED,
                     job_metadata={'keep': True}))
        db.commit()
        db.add(PartialJobResultDB(job_id='v2-job', result={'legacy': True}, updated_at=now))
        db.commit()
        save_partial_result('v2-job', {'stage': 'aggregate'}, db=db)
        parent = db.get(JobDB, 'v2-job')
        assert (parent.source, parent.mode, parent.status, parent.job_metadata) == (
            'existing', 'existing', JobStatus.COMPLETED, {'keep': True})
        assert db.get(PartialJobResultDB, 'v2-job').result == {'legacy': True}


def test_retention_removes_v2_snapshot(partial_engine, tmp_path):
    from backend.app.services.cleanup import cleanup_old_jobs
    settings = SimpleNamespace(aipam_job_retention_days=30, aipam_job_root=tmp_path / 'jobs')
    with Session(partial_engine) as db:
        save_partial_result('v2-job', {'stage': 'aggregate'}, db=db)
        assert cleanup_old_jobs(db, settings) == 1
        assert get_partial_result('v2-job', db=db) is None
        assert db.get(JobDB, 'v2-job') is None


def test_partial_endpoint_reads_the_v2_database(partial_engine, monkeypatch):
    from backend.app.api.jobs import get_partial_results
    import backend.app.partial_results as partials
    legacy_engine = create_engine('sqlite:///:memory:')
    PartialJobResultDB.__table__.create(legacy_engine)
    monkeypatch.setattr(partials, 'engine', legacy_engine)
    try:
        with Session(partial_engine) as db:
            save_partial_result('v2-job', {'completed_stages': ['parse'], 'partial_data': {'count': 3}}, db=db)
            result = asyncio.run(get_partial_results('v2-job', Response(), request_id='test', db=db))
            assert result.completed_stages == ['parse']
            assert result.partial_data == {'count': 3}
    finally:
        legacy_engine.dispose()
