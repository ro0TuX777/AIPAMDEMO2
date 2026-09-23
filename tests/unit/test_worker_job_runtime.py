"""Database fences, cancellation control, and supervisor contracts."""
import importlib
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session, sessionmaker
from backend.app import database_v2
from backend.app.database_v2 import Base
from backend.app.models.job import Job
from backend.app.services import job_runtime as runtime


@pytest.fixture
def owned(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'runtime.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, autoflush=False)
    with factory() as db:
        db.add(Job(job_id='job', status='queued', execution_profile='standard', created_at='2026-01-01T00:00:00Z'))
        db.commit()
        runtime.assign_task(db, 'job', 'task')
        handle = runtime.claim_job(db, 'job', 'task', 'token', 'worker').handle
    yield factory, handle, tmp_path
    engine.dispose()


@pytest.mark.parametrize('new_status,exception', [('canceling', 'JobCancellationRequested'), ('failed', 'JobOwnershipLost')])
def test_internal_commit_is_fenced(owned, new_status, exception):
    factory, handle, _ = owned
    control = importlib.import_module('backend.app.pipeline.runtime_control')
    fenced = database_v2.get_fenced_session_factory(handle, bind=factory.kw['bind'])()
    with factory() as rival:
        rival.execute(update(Job).values(status=new_status))
        rival.commit()
    fenced.add(Job(job_id='leak', status='queued', execution_profile='standard', created_at='now'))
    with pytest.raises(getattr(control, exception)):
        fenced.commit()
    fenced.rollback()
    fenced.close()
    with factory() as db:
        assert db.get(Job, 'leak') is None


def test_fence_uses_transaction_connection_and_allows_owned_commit(owned):
    factory, handle, _ = owned
    fenced = database_v2.get_fenced_session_factory(handle, bind=factory.kw['bind'])()
    fenced.get(Job, 'job').job_name = 'saved'
    fenced.commit()
    fenced.close()
    with factory() as db:
        assert db.get(Job, 'job').job_name == 'saved'


def test_heartbeat_cancellation_creates_file_and_checkpoint_raises(owned):
    factory, handle, root = owned
    m = importlib.import_module('backend.app.pipeline.runtime_control')
    control = m.ExecutionControl(handle, root, factory)
    with factory() as db:
        runtime.request_cancel(db, 'job')
    control.heartbeat_once()
    assert control.cancel_path.exists()
    with pytest.raises(m.JobCancellationRequested):
        control.checkpoint()


def test_heartbeat_busy_is_retried_not_ownership_loss(owned):
    from sqlalchemy.exc import OperationalError
    factory, handle, root = owned
    m = importlib.import_module('backend.app.pipeline.runtime_control')
    attempts = []
    def sessions():
        attempts.append(1)
        if len(attempts) == 1:
            raise OperationalError('busy', {}, Exception('database is locked'))
        return factory()
    control = m.ExecutionControl(handle, root, sessions)
    assert control.heartbeat_once() is False
    assert control.heartbeat_once() is True
    control.checkpoint()


def test_runtime_settings_defaults_and_limits():
    from backend.app.config_v2 import Settings
    s = Settings(aipam_api_token='test', _env_file=None)
    assert (s.aipam_heartbeat_seconds, s.aipam_stale_seconds, s.aipam_cancel_poll_seconds) == (15, 120, 2)
    assert (s.aipam_task_soft_time_limit, s.aipam_task_time_limit, s.aipam_visibility_timeout) == (21300, 21600, 25200)


@pytest.mark.parametrize('values', [
    {'aipam_visibility_timeout': 21600}, {'aipam_visibility_timeout': 21599},
    {'aipam_task_soft_time_limit': 21600}, {'aipam_task_time_limit': 0},
    {'aipam_heartbeat_seconds': 0}, {'aipam_cancel_poll_seconds': 'bad'},
    {'aipam_stale_seconds': 15}, {'aipam_max_concurrent_jobs': 2},
])
def test_invalid_runtime_settings_refused(values):
    from backend.app.config_v2 import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(aipam_api_token='test', _env_file=None, **values)


@pytest.fixture
def worker_harness(owned, monkeypatch):
    from types import SimpleNamespace
    from backend.app import worker
    from backend.app.pipeline import orchestrator, runtime_control
    from backend.app.config_v2 import Settings
    import docker
    factory, handle, root = owned
    with factory() as db:
        db.execute(update(Job).values(status='queued', run_token=None))
        db.commit()
    monkeypatch.setattr(database_v2, 'init_v2_db', lambda: None)
    monkeypatch.setattr(database_v2, 'get_session_factory', lambda: factory)
    monkeypatch.setattr(database_v2, 'get_engine', lambda: factory.kw['bind'])
    monkeypatch.setattr(worker, 'get_settings', lambda: Settings(aipam_api_token='test', aipam_job_root=root/'jobs', aipam_upload_root=root/'uploads', _env_file=None))
    monkeypatch.setattr(docker, 'from_env', lambda **kw: None)
    identity = runtime.ExecutorIdentity('node', 'a'*64, 42, 123, 'boot', 42, 'nonce')
    monkeypatch.setattr(runtime_control, 'current_executor', lambda *a: identity)
    events = []
    def emit(job_id, status):
        with factory() as db:
            row = db.get(Job, job_id)
            assert row.completed_at and row.status == status
        events.append(status)
    monkeypatch.setattr(worker, '_emit_complete', emit)
    monkeypatch.setattr(worker.distill_job, 'delay', lambda *a: None)
    return SimpleNamespace(factory=factory, worker=worker, pipeline=orchestrator, events=events)


def test_worker_registers_exact_executor_and_fenced_session(worker_harness, monkeypatch):
    h = worker_harness
    from backend.app.pipeline.outcomes import derive_outcome
    def pipeline(**kw):
        assert isinstance(kw['db'], database_v2.FencedSession)
        with h.factory() as db:
            row = db.get(Job, 'job')
            assert (row.worker_container_id, row.executor_pid, row.executor_pid_start_ticks, row.executor_boot_id) == ('a'*64, 42, 123, 'boot')
            assert (row.executor_session_id, row.executor_group_nonce) == (42, 'nonce')
            assert os.environ['AIPAM_RUN_CONTROL_DIR'] == str((kw['run_output_dir']/'control').resolve())
        return derive_outcome()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    assert h.worker.execute_job('job', 'task') == 'completed'
    assert h.events == ['completed']
    assert h.worker.execute_job('job', 'task') == 'terminal'
    assert h.events == ['completed']


@pytest.mark.parametrize('cancel', [False, True])
def test_worker_cannot_finalize_or_remove_pending_escape_receipt(worker_harness, monkeypatch, cancel):
    import json
    from backend.app.pipeline.outcomes import derive_outcome
    from backend.app.bluescrub.isolation.runner import ProcessCleanupIncomplete
    from backend.app.pipeline.runtime_control import JobCancellationRequested
    h = worker_harness
    receipts = []
    def pipeline(**kw):
        receipt = kw['run_output_dir']/'control'/'handler-analyzer-pending.json'
        receipt.write_text(json.dumps(dict(state='launching', group_nonce='pending')))
        receipts.append(receipt)
        if cancel:
            with h.factory() as db:
                runtime.request_cancel(db, 'job')
        return derive_outcome()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    with pytest.raises(JobCancellationRequested if cancel else ProcessCleanupIncomplete):
        h.worker.execute_job('job', 'task')
    assert receipts[0].exists() and h.events == []
    with h.factory() as db:
        row = db.get(Job, 'job')
        assert row.status == ('canceling' if cancel else 'running') and row.completed_at is None


def test_cancel_before_internal_commit_finishes_canceled(worker_harness, monkeypatch):
    h = worker_harness
    def pipeline(**kw):
        with h.factory() as db:
            runtime.request_cancel(db, 'job')
        kw['db'].add(Job(job_id='leak', status='queued', execution_profile='standard', created_at='now'))
        kw['db'].commit()
        pytest.fail('canceled execution committed')
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    assert h.worker.execute_job('job', 'task') == 'canceled'
    assert h.events == ['canceled']
    with h.factory() as db:
        assert db.get(Job, 'leak') is None


def test_flush_failure_terminalizes_using_fresh_session(worker_harness, monkeypatch):
    from sqlalchemy.exc import IntegrityError
    h = worker_harness
    def pipeline(**kw):
        kw['db'].add(Job(job_id='job', created_at='duplicate'))
        kw['db'].flush()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    with pytest.raises(IntegrityError):
        h.worker.execute_job('job', 'task')
    assert h.events == ['failed']


def test_running_cancel_is_nonterminal_until_worker_stops(owned):
    from backend.app.services.job_lifecycle import cancel_job
    factory, _, _ = owned
    with factory() as db:
        result = cancel_job(db.get(Job, 'job'), db)
        assert result.status == 'canceling'
        assert result.completed_at is None


def test_celery_limits_are_durable_delivery_contract():
    from backend.app.worker import celery_app
    c = celery_app.conf
    assert c.worker_concurrency == 1
    assert c.worker_max_tasks_per_child == 1
    assert c.task_reject_on_worker_lost
    assert (c.task_soft_time_limit, c.task_time_limit) == (21300, 21600)
    assert c.broker_transport_options['visibility_timeout'] == 25200


@pytest.mark.parametrize('name', ['zeek', 'suricata', 'tls_enrich', 'beaconing', 'file_triage', 'capa', 'ti_matcher'])
def test_every_registry_handler_crosses_process_boundary(tmp_path, monkeypatch, name):
    from backend.app.pipeline import sensor_runner
    from backend.app.sensors.registry import SENSORS
    process = importlib.import_module('backend.app.pipeline.sensor_process')
    launched = []
    def launch(sensor_def, **kw):
        launched.append(sensor_def.name)
        assert kw['cancel_path'] == tmp_path/'control'/'cancel.requested'
    monkeypatch.setattr(process, 'run_handler_process', launch)
    result = sensor_runner.run_sensor(SENSORS[name], tmp_path, 'job', 'standard', run_output_dir=tmp_path)
    assert result.status == 'completed'
    assert launched == [name]


def test_real_sensor_subprocess_runs_and_reaps(tmp_path):
    from backend.app.pipeline.sensor_runner import run_sensor
    from backend.app.sensors.registry import SENSORS
    result = run_sensor(SENSORS['tls_enrich'], tmp_path, 'job', 'standard', run_output_dir=tmp_path)
    assert result.status == 'completed'
    assert not list((tmp_path/'control').glob('handler-*.json'))
    assert (tmp_path/'sensors'/'tls_enrich'/'sensor.results.jsonl').exists()


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux /proc and process-group gate; run in Task 10 app image')
def test_unresponsive_real_handler_group_is_killed_and_reaped(tmp_path):
    import subprocess
    import time
    from backend.app.pipeline.sensor_process import run_tracked_process
    from backend.app.pipeline.runtime_control import SensorExecutionContext
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_tracked_process([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(90)'],
                            run_output_dir=tmp_path, name='stubborn', timeout_seconds=.3,
                            context=SensorExecutionContext(tmp_path/'control'/'cancel.requested'))
    assert time.monotonic()-start < 6
    assert not list((tmp_path/'control').glob('handler-*.json'))


@pytest.mark.parametrize('changed', ['start_ticks', 'boot_id'])
def test_reused_identity_is_never_signaled(tmp_path, changed):
    m = importlib.import_module('backend.app.pipeline.sensor_process')
    expected = {'pid': 42, 'start_ticks': 123, 'boot_id': 'boot', 'pgid': 42}
    live = dict(expected, **{changed: 'changed'})
    assert m.classify_identity(expected, live) == 'conflict'
    assert m.classify_identity(expected, None) == 'absent'
    assert m.classify_identity(expected, expected) == 'matching'


@pytest.mark.parametrize('verdict,status', [('matching', 'canceled'), ('absent', 'canceled'), ('conflict', 'canceling')])
def test_supervisor_escalates_only_matching_identity_with_deadline_budget(owned, verdict, status):
    m = importlib.import_module('backend.app.runtime_supervisor')
    factory, handle, root = owned
    with factory() as db:
        runtime.register_executor(db, handle, runtime.ExecutorIdentity('node', 'a'*64, 42, 123, 'boot'))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1), cancel_deadline_at=runtime._now(15)))
        db.commit()
    calls, events = [], []
    class Transport:
        def stop_executor(self, identity, run_dir, budget):
            assert 0 < budget.remaining() <= 12
            calls.append('executor')
            return verdict
        def cleanup_containers(self, handle, budget):
            calls.append('containers')
    supervisor = m.RuntimeSupervisor(factory, root, transport=Transport(), emit=lambda *args: events.append(args))
    supervisor.cancel_once()
    with factory() as db:
        row = db.get(Job, 'job')
        assert row.status == status
        if verdict == 'conflict':
            assert row.error_summary == 'CANCEL_EXECUTOR_IDENTITY_CONFLICT'
            assert calls == ['executor']
            assert not events
        else:
            assert row.completed_at
            assert len(events) == 1
            assert calls == ['executor', 'containers']
    supervisor.cancel_once()
    assert len(events) == (0 if verdict == 'conflict' else 1)


def test_stale_owner_cannot_cleanup_new_run(owned):
    m = importlib.import_module('backend.app.runtime_supervisor')
    factory, handle, root = owned
    with factory() as db:
        db.execute(update(Job).values(run_token='new'))
        db.commit()
    supervisor = m.RuntimeSupervisor(factory, root)
    assert not supervisor.owns_cancel(handle, 'stale-escalation')


@pytest.mark.parametrize('quiescent', [True, False])
def test_supervisor_finalizes_only_after_group_quiescence(owned, monkeypatch, quiescent):
    import json, signal
    from backend.app import runtime_supervisor as supervisor
    from backend.app.pipeline import sensor_process as process
    from backend.app.bluescrub.isolation import runner
    factory, handle, root = owned
    leader = dict(pid=202, pgid=202, sid=202, start_ticks=100, boot_id='boot', state='S')
    members = {202: dict(leader)}
    run_dir = root/'job'/'.runs'/handle.run_token
    receipt = run_dir/'control'/'handler-test.json'
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({**leader, 'group_nonce': 'nonce'}))
    with factory() as db:
        runtime.register_executor(db, handle, runtime.ExecutorIdentity('node', 'a'*64, 999, 1, 'boot'))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1)))
        db.commit()
    monkeypatch.setattr(signal, 'SIGSTOP', 19, raising=False)
    monkeypatch.setattr(signal, 'SIGKILL', 9, raising=False)
    monkeypatch.setattr(runner, 'read_process_identity', members.get)
    monkeypatch.setattr(runner, 'group_members', lambda pgid: list(members.values()))
    monkeypatch.setattr(runner, 'session_members', lambda sid: list(members.values()) if sid == 202 else [])
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: 'nonce')
    monkeypatch.setattr(process, 'read_identity', members.get)
    monkeypatch.setattr(process, 'read_process_identity', members.get)
    def send(item, sig):
        if sig == signal.SIGSTOP and quiescent:
            members[item['pid']]['state'] = 'T'
        if sig == signal.SIGKILL:
            members.pop(item['pid'], None)
            if item['pid'] == 202:
                members[303] = dict(leader, pid=303, start_ticks=101)
    monkeypatch.setattr(process, '_signal_exact', send)
    class Transport:
        def stop_executor(self, identity, path, budget):
            return process.stop_executor(dict(executor_pid=999, executor_pid_start_ticks=1,
                                               executor_boot_id='boot', executor_session_id=999, executor_group_nonce='nonce'), path, .3)
        def cleanup_containers(self, *args):
            assert not members
    events = []
    def emit(*args):
        assert not members
        events.append(args)
    supervisor.RuntimeSupervisor(factory, root, transport=Transport(), emit=emit).cancel_once()
    with factory() as db:
        assert db.get(Job, 'job').status == ('canceled' if quiescent else 'canceling')
    assert len(events) == int(quiescent)
    if not quiescent:
        assert receipt.exists() and members


def test_health_uses_45_second_freshness(tmp_path):
    m = importlib.import_module('backend.app.runtime_supervisor')
    path = tmp_path/'heartbeat'
    assert not m.healthy(path, now=100)
    path.touch()
    os.utime(path, (70, 70))
    assert m.healthy(path, now=100)
    assert not m.healthy(path, now=116)



def test_reconciliation_preserves_live_executor_conflict_and_emits_only_winners(owned):
    m = importlib.import_module('backend.app.runtime_supervisor')
    factory, handle, root = owned
    with factory() as db:
        runtime.register_executor(db, handle, runtime.ExecutorIdentity('node', 'a'*64, 42, 123, 'boot'))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(heartbeat_at=runtime._now(-180), error_summary='CANCEL_EXECUTOR_IDENTITY_CONFLICT'))
        db.commit()
    events = []
    s = m.RuntimeSupervisor(factory, root, emit=lambda *args: events.append(args))
    s.reconcile_once(heartbeat_path=root/'heartbeat')
    with factory() as db:
        assert db.get(Job, 'job').status == 'canceling'
        db.execute(update(Job).values(status='running'))
        db.commit()
    s.reconcile_once(heartbeat_path=root/'heartbeat')
    s.reconcile_once(heartbeat_path=root/'heartbeat')
    assert events == [('job', 'failed')]


def test_startup_recovery_does_not_fail_live_heartbeats(owned):
    from backend.app.pipeline.recovery import recover_interrupted_jobs
    factory, _, _ = owned
    with factory() as db:
        assert recover_interrupted_jobs(db) == 0
        assert db.get(Job, 'job').status == 'running'


def test_handler_record_iteration_checks_cancellation(tmp_path):
    from backend.app.pipeline.runtime_control import SensorExecutionContext, _current_control, JobCancellationRequested
    from backend.app.pipeline.sensor_handlers import _iter_zeek_log
    cancel = tmp_path/'cancel'
    records = tmp_path/'conn.log'
    records.write_text('{"id": 1}\n{"id": 2}\n')
    token = _current_control.set(SensorExecutionContext(cancel))
    try:
        it = _iter_zeek_log(records)
        assert next(it) == {'id': 1}
        cancel.touch()
        with pytest.raises(JobCancellationRequested):
            next(it)
    finally:
        _current_control.reset(token)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux /proc and process-group gate; run in Task 10 app image')
def test_real_cooperative_child_cancels_under_thirty_seconds(tmp_path):
    import threading, time
    from backend.app.pipeline.sensor_process import run_tracked_process
    from backend.app.pipeline.runtime_control import SensorExecutionContext, JobCancellationRequested, request_cancel_file
    cancel = tmp_path/'control'/'cancel.requested'
    timer = threading.Timer(.5, request_cancel_file, (cancel,))
    timer.start()
    start = time.monotonic()
    try:
        with pytest.raises(JobCancellationRequested):
            run_tracked_process([sys.executable, '-c', 'import time; time.sleep(90)'], run_output_dir=tmp_path,
                                name='cooperative', timeout_seconds=90, context=SensorExecutionContext(cancel))
    finally:
        timer.join()
    assert time.monotonic()-start < 30
    assert not list((tmp_path/'control').glob('handler-*.json'))



def test_partial_results_use_owned_transaction(owned):
    from backend.app.partial_results import save_partial_result
    from backend.app.db_models import PartialJobResultDB
    from backend.app.pipeline.runtime_control import JobCancellationRequested
    factory, handle, _ = owned
    PartialJobResultDB.__table__.create(factory.kw['bind'], checkfirst=True)
    with factory() as db:
        runtime.request_cancel(db, 'job')
    with database_v2.get_fenced_session_factory(handle, bind=factory.kw['bind'])() as db:
        with pytest.raises(JobCancellationRequested):
            save_partial_result('job', {'stage': 'parse'}, db=db)
    with factory() as db:
        assert db.get(PartialJobResultDB, 'job') is None



def test_sensor_paths_need_no_worker_credentials(monkeypatch):
    from backend.app import config_v2
    monkeypatch.delenv('AIPAM_API_TOKEN', raising=False)
    paths = config_v2.SensorPaths(_env_file=None)
    assert paths.aipam_yara_rules_dir == Path('/opt/aipam/rules/yara')
    assert not hasattr(paths, 'aipam_api_token')


def test_event_bus_failures_are_bounded_and_sanitized(monkeypatch, caplog):
    from backend.app import events
    import redis
    seen = {}
    def unavailable(url, **kw):
        seen.update(kw)
        raise RuntimeError('redis://secret:password@broker')
    monkeypatch.setattr(redis.Redis, 'from_url', unavailable)
    monkeypatch.setattr(events, '_redis_client', None)
    events.publish_job_event('job', 'job.complete', {})
    assert seen['socket_timeout'] <= 1
    assert seen['socket_connect_timeout'] <= 1
    assert 'secret' not in caplog.text


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux exact executor identity gate; Task 10 app image')
@pytest.mark.parametrize('identity_change', [None, 'start_ticks', 'boot_id'])
def test_real_executor_exact_identity_and_conflict(tmp_path, identity_change):
    import subprocess
    from backend.app.pipeline.runtime_control import process_identity
    from backend.app.pipeline.sensor_process import stop_executor
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)'], start_new_session=True)
    try:
        identity = process_identity(process.pid)
        if identity_change:
            identity[identity_change] = 'reused'
        executor = dict(executor_pid=process.pid, executor_pid_start_ticks=identity['start_ticks'], executor_boot_id=identity['boot_id'], executor_session_id=process.pid, executor_group_nonce='test')
        result = stop_executor(executor, tmp_path, 5)
        if identity_change:
            assert result == 'conflict'
            assert process.poll() is None
        else:
            assert result == 'matching'
            assert process.wait(timeout=1) < 0
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()



@pytest.mark.skipif(sys.platform != 'linux', reason='Linux orphan group cleanup gate; Task 10 app image')
def test_absent_executor_reaps_tracked_handler_descendants(tmp_path):
    import subprocess, time, os
    from backend.app.bluescrub.isolation.runner import ProcessGroup, read_process_identity
    from backend.app.pipeline.runtime_control import process_identity, atomic_json
    from backend.app.pipeline.sensor_process import stop_executor
    child_file = tmp_path/'child.pid'
    code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(90)']); open(sys.argv[1],'w').write(str(p.pid)); time.sleep(90)"
    nonce = 'existing-orphan-test'
    proc = subprocess.Popen([sys.executable, '-c', code, str(child_file)], start_new_session=True,
                            env={**os.environ, 'AIPAM_PROCESS_GROUP_NONCE': nonce})
    proc.aipam_group = ProcessGroup(read_process_identity(proc.pid), nonce)
    try:
        deadline = time.monotonic()+3
        while not child_file.exists() and time.monotonic()<deadline:
            time.sleep(.02)
        identity = process_identity(proc.pid)
        atomic_json(tmp_path/'control'/'handler-stubborn.json', {**identity, 'handler': 'stubborn', 'group_nonce': nonce})
        result = stop_executor(dict(executor_pid=2147483647, executor_pid_start_ticks=1, executor_boot_id=identity['boot_id'], executor_session_id=2147483647, executor_group_nonce='test'), tmp_path, 5)
        assert result == 'absent'
        proc.wait(timeout=1)
        child_stat = Path('/proc')/child_file.read_text()/'stat'
        assert not child_stat.exists() or child_stat.read_text().rsplit(')',1)[1].split()[0] == 'Z'
    finally:
        from backend.app.bluescrub.isolation.runner import _kill_group
        _kill_group(proc, 0)



def test_ownership_lost_never_fails_still_running_row(worker_harness, monkeypatch):
    from backend.app.pipeline.runtime_control import JobOwnershipLost
    h = worker_harness
    def pipeline(**kw):
        raise JobOwnershipLost()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    assert h.worker.execute_job('job', 'task') == 'superseded'
    with h.factory() as db:
        assert db.get(Job, 'job').status == 'running'
    assert not h.events


@pytest.mark.parametrize('soft,hard,visibility,valid', [(1,2,3,True), (2,2,3,False), (3,2,4,False), (1,2,2,False), (1,2,1,False), (-1,2,3,False)])
def test_time_limit_order_boundaries(soft, hard, visibility, valid):
    from backend.app.config_v2 import Settings
    from pydantic import ValidationError
    values = dict(aipam_api_token='test', _env_file=None, aipam_task_soft_time_limit=soft, aipam_task_time_limit=hard, aipam_visibility_timeout=visibility)
    if valid:
        assert Settings(**values).aipam_task_time_limit == hard
    else:
        with pytest.raises(ValidationError):
            Settings(**values)



@pytest.mark.parametrize('code,error', [(71,'JobCancellationRequested'), (72,'JobOwnershipLost'), (73,'SQLAlchemyError')])
def test_real_child_control_failures_cross_process_boundary(tmp_path, code, error):
    from backend.app.pipeline.sensor_process import run_tracked_process
    from backend.app.pipeline import runtime_control
    from sqlalchemy.exc import SQLAlchemyError
    exception = SQLAlchemyError if error == 'SQLAlchemyError' else getattr(runtime_control, error)
    with pytest.raises(exception):
        run_tracked_process([sys.executable, '-c', f'import sys; sys.exit({code})'], run_output_dir=tmp_path,
                            name='control', timeout_seconds=5,
                            context=runtime_control.SensorExecutionContext(tmp_path/'cancel'))
    assert not list((tmp_path/'control').glob('handler-*.json'))



def test_stale_worker_recovery_reaps_only_persisted_private_identity(owned):
    from dataclasses import asdict
    from backend.app.pipeline.runtime_control import atomic_json
    from backend.app.runtime_supervisor import RuntimeSupervisor
    factory, handle, root = owned
    run_dir = root/'job'/'.runs'/'token'
    identity = runtime.ExecutorIdentity('node', 'a'*64, 42, 123, 'boot')
    atomic_json(run_dir/'control'/'executor.json', {'handle': asdict(handle), 'identity': asdict(identity)})
    with factory() as db:
        runtime.register_executor(db, handle, identity)
        db.execute(update(Job).values(heartbeat_at=runtime._now(-121)))
        db.commit()
    calls = []
    class Transport:
        def stop_executor(self, actual, path, budget):
            assert actual == identity
            assert path == run_dir
            with factory() as db:
                assert db.get(Job, 'job').status == 'failed'
            calls.append('stop')
            return 'absent'
        def cleanup_containers(self, actual, budget):
            assert actual == handle
            calls.append('cleanup')
    RuntimeSupervisor(factory, root, transport=Transport(), emit=lambda *a: None).reconcile_once(heartbeat_path=root/'heartbeat')
    assert calls == ['stop', 'cleanup']
    assert not run_dir.exists()



@pytest.mark.parametrize('state,expected', [('absent','absent'), ('recreated','conflict'), ('stopped','absent')])
def test_docker_executor_container_identity_gate(monkeypatch, tmp_path, state, expected):
    from types import SimpleNamespace
    from dataclasses import asdict
    import docker
    from backend.app.runtime_supervisor import docker_operation
    def get(container_id):
        assert container_id == 'a'*64
        if state == 'absent':
            raise docker.errors.NotFound('not found')
        return SimpleNamespace(id='b'*64 if state == 'recreated' else 'a'*64,
                               status='exited' if state == 'stopped' else 'running',
                               exec_run=lambda *a: pytest.fail('must not signal'))
    client = SimpleNamespace(containers=SimpleNamespace(get=get), close=lambda: None)
    monkeypatch.setattr(docker, 'from_env', lambda **kw: client)
    identity = runtime.ExecutorIdentity('node','a'*64,42,123,'boot')
    assert docker_operation('stop', {'identity':asdict(identity),'run_dir':str(tmp_path)}, 8) == expected


def test_docker_call_timeout_never_exceeds_remaining_deadline(monkeypatch):
    import subprocess
    from backend.app.runtime_supervisor import DeadlineBudget, DockerTransport
    clock = [45.0]
    budget = DeadlineBudget(12, clock=lambda: clock[0])
    clock[0] = 54
    def run(argv, **kw):
        import json
        assert json.loads(argv[-1])['deadline'] == 57
        assert kw['timeout'] == 3
        assert kw['stderr'] == subprocess.DEVNULL
        raise subprocess.TimeoutExpired(argv, kw['timeout'])
    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(subprocess.TimeoutExpired):
        DockerTransport().cleanup_containers(runtime.RunHandle('job','task','token',1), budget)
    clock[0] = 57
    with pytest.raises(TimeoutError):
        DockerTransport().cleanup_containers(runtime.RunHandle('job','task','token',1), budget)


def test_cancel_finalization_uses_reserved_deadline_and_post_commit_event(owned, monkeypatch):
    from backend.app import runtime_supervisor as m
    factory, handle, root = owned
    with factory() as db:
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1), cancel_deadline_at=runtime._now(15)))
        db.commit()
    clock = [45.0]
    budget_type = m.DeadlineBudget
    monkeypatch.setattr(m, 'DeadlineBudget', lambda seconds: budget_type(seconds, clock=lambda: clock[0]))
    class Transport:
        def stop_executor(self, identity, run_dir, budget):
            assert budget.remaining() <= 7
            clock[0] += 4
            return 'absent'
        def cleanup_containers(self, handle, budget):
            assert budget.remaining() <= 8.1
            clock[0] += 4
    events = []
    def emit(job_id, status):
        with factory() as db:
            assert db.get(Job, job_id).status == 'canceled'
        assert clock[0] <= 60
        events.append(status)
    m.RuntimeSupervisor(factory, root, transport=Transport(), emit=emit).cancel_once()
    assert events == ['canceled']


@pytest.mark.parametrize('registered', [False, True])
def test_exhausted_cleanup_budget_still_finalizes_proven_stopped_writer(owned, monkeypatch, registered):
    from backend.app import runtime_supervisor as m
    from dataclasses import asdict
    from backend.app.pipeline.runtime_control import atomic_json
    factory, handle, root = owned
    with factory() as db:
        if registered:
            identity = runtime.ExecutorIdentity('node', 'a'*64, 42, 123, 'boot')
            runtime.register_executor(db, handle, identity)
            atomic_json(root/'job'/'.runs'/handle.run_token/'control'/'executor.json',
                        dict(handle=asdict(handle), identity=asdict(identity), resource_protocol=1))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1), cancel_deadline_at=runtime._now(15)))
        db.commit()
    clock = [45.0]
    budget_type = m.DeadlineBudget
    monkeypatch.setattr(m, 'DeadlineBudget', lambda seconds: budget_type(seconds, clock=lambda: clock[0]))
    class Transport(m.DockerTransport):
        def stop_executor(self, identity, run_dir, budget):
            clock[0] += 7
            return 'matching' if registered else 'absent'
        def _call(self, operation, payload, budget):
            clock[0] += budget.remaining()
            # Exercise the real transport's zero-budget branch.
            return super()._call(operation, payload, budget)
    events = []
    def emit(job_id, status):
        with factory() as db:
            assert db.get(Job, job_id).status == 'canceled'
        assert clock[0] <= 60
        events.append(status)
    m.RuntimeSupervisor(factory, root, transport=Transport(), emit=emit).cancel_once()
    assert events == ['canceled']


@pytest.mark.parametrize('remaining', [2, -2])
def test_never_registered_executor_finalizes_with_real_zero_budget_transport(owned, remaining):
    from backend.app import runtime_supervisor as m
    factory, handle, root = owned
    with factory() as db:
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-20), cancel_deadline_at=runtime._now(remaining)))
        db.commit()
    events = []
    m.RuntimeSupervisor(factory, root, emit=lambda *args: events.append(args)).cancel_once()
    with factory() as db:
        assert db.get(Job, 'job').status == 'canceled'
    assert len(events) == 1


def test_unresolved_container_writer_prevents_finalization(owned):
    from backend.app import runtime_supervisor as m
    factory, handle, root = owned
    marker = root/'job'/'.runs'/handle.run_token/'control'/'containers.requested'
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    with factory() as db:
        runtime.register_executor(db, handle, runtime.ExecutorIdentity('node', 'a'*64, 42, 123, 'boot'))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1)))
        db.commit()
    class Transport:
        def stop_executor(self, *args): return 'matching'
        def cleanup_containers(self, *args): raise TimeoutError()
    events = []
    m.RuntimeSupervisor(factory, root, transport=Transport(), emit=lambda *a: events.append(a)).cancel_once()
    with factory() as db:
        assert db.get(Job, 'job').status == 'canceling'
    assert events == []


def test_second_supervisor_cannot_reclaim_during_stop_but_can_after_loss(owned, monkeypatch):
    from backend.app import runtime_supervisor as m
    from sqlalchemy import func
    factory, handle, root = owned
    with factory() as db:
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1)))
        db.commit()
        assert runtime.claim_cancel_escalation(db, 'job', 'first', lease_seconds=m.ESCALATION_LEASE_SECONDS).claimed
    original_now = runtime._now
    for elapsed, expected in [(6, False), (14, False), (16, True)]:
        monkeypatch.setattr(runtime, '_now', lambda offset=0, elapsed=elapsed: original_now(offset+elapsed))
        with factory() as db:
            assert runtime.claim_cancel_escalation(db, 'job', 'second', lease_seconds=m.ESCALATION_LEASE_SECONDS).claimed is expected



def test_worker_finally_reaps_registered_run_children(worker_harness, monkeypatch):
    import threading, time
    from backend.app.pipeline.sensor_process import run_tracked_process
    from backend.app.pipeline.runtime_control import SensorExecutionContext
    from backend.app.pipeline.outcomes import derive_outcome
    h = worker_harness
    threads = []
    records = []
    def pipeline(**kw):
        root = kw['run_output_dir']
        def child():
            try:
                run_tracked_process([sys.executable, '-c', 'import time; time.sleep(20)'],
                                    run_output_dir=root, name='lingering', timeout_seconds=25,
                                    context=SensorExecutionContext(root/'control'/'cancel.requested'))
            except Exception:
                pass
        thread = threading.Thread(target=child, daemon=True)
        thread.start()
        threads.append(thread)
        record = root/'control'/'handler-lingering.json'
        deadline = time.monotonic()+5
        while not record.exists() and time.monotonic()<deadline:
            time.sleep(.02)
        assert record.exists()
        records.append(record)
        return derive_outcome()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    h.worker.execute_job('job','task')
    threads[0].join(timeout=5)
    assert not threads[0].is_alive()
    assert not records[0].exists()



def test_reaper_racing_identity_publication_leaves_no_stale_record(tmp_path, monkeypatch):
    import threading
    from backend.app.pipeline import sensor_process as m
    from backend.app.pipeline.runtime_control import SensorExecutionContext
    entered, release = threading.Event(), threading.Event()
    from backend.app.bluescrub.isolation import launch as boundary
    original = boundary.publish
    def publish(path, payload):
        entered.set()
        assert release.wait(3)
        original(path, payload)
    monkeypatch.setattr(boundary, 'publish', publish)
    def launch():
        try:
            m.run_tracked_process([sys.executable, '-c', 'import time; time.sleep(20)'],
                                  run_output_dir=tmp_path, name='race', timeout_seconds=25,
                                  context=SensorExecutionContext(tmp_path/'control'/'cancel.requested'))
        except Exception:
            pass
    thread = threading.Thread(target=launch)
    thread.start()
    assert entered.wait(3)
    stop = threading.Thread(target=m.reap_run_processes, args=(tmp_path,))
    stop.start()
    stop.join(timeout=.2)
    release.set()
    stop.join(timeout=5)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert not list((tmp_path/'control').glob('handler-*.json'))



def test_handler_environment_preserves_paths_without_worker_secrets(tmp_path, monkeypatch):
    from backend.app.pipeline import sensor_process as m
    from backend.app.sensors.registry import SENSORS
    for key in ('AIPAM_CAPA_RULES_DIR','AIPAM_CAPA_SIGNATURES_DIR','AIPAM_TI_BUNDLE_DIR'):
        monkeypatch.setenv(key, '/configured/path')
    monkeypatch.setenv('AIPAM_API_TOKEN','must-not-cross')
    monkeypatch.setenv('AIPAM_REDIS_URL','must-not-cross')
    seen = []
    def run(argv, **kw):
        env = kw['env']
        assert env['AIPAM_CAPA_RULES_DIR'] == '/configured/path'
        assert env['AIPAM_CAPA_SIGNATURES_DIR'] == '/configured/path'
        assert env['AIPAM_TI_BUNDLE_DIR'] == '/configured/path'
        assert 'AIPAM_API_TOKEN' not in env and 'AIPAM_REDIS_URL' not in env
        seen.append(argv)
    monkeypatch.setattr(m, 'run_tracked_process', run)
    m.run_handler_process(SENSORS['capa'], input_root=tmp_path,run_output_dir=tmp_path,
                          sensor_output_dir=tmp_path/'sensors'/'capa',job_id='job',
                          execution_profile='standard',cancel_path=tmp_path/'cancel')
    assert len(seen) == 1



def test_supervisor_terminal_event_cannot_consume_finalization_reserve(monkeypatch, caplog):
    import subprocess
    from backend.app import runtime_supervisor as m
    calls = []
    def publish(argv, **kw):
        assert kw['timeout'] <= 2
        assert kw['stderr'] == subprocess.DEVNULL
        calls.append(argv)
        raise subprocess.TimeoutExpired(argv, kw['timeout'])
    monkeypatch.setattr(subprocess, 'run', publish)
    m.emit_terminal_bounded('job','canceled')
    assert len(calls) == 1



def test_batch_cancel_uses_same_nonterminal_transition(owned):
    import asyncio
    from fastapi import Response
    from backend.app.api.jobs import batch_jobs
    from backend.app.schemas.system import BatchJobsRequest
    factory, _, _ = owned
    with factory() as db:
        result = asyncio.run(batch_jobs(BatchJobsRequest(action='cancel',job_ids=['job']), Response(), request_id='request',db=db))
        assert result.accepted == ['job']
        assert db.get(Job,'job').status == 'canceling'
        assert db.get(Job,'job').completed_at is None


@pytest.mark.parametrize('batch', [False,True])
def test_canceling_job_cannot_be_deleted_before_executor_stops(owned, batch):
    import asyncio
    from fastapi import Response, HTTPException
    from backend.app.api.jobs import batch_jobs, delete_job
    from backend.app.schemas.system import BatchJobsRequest
    factory, _, _ = owned
    with factory() as db:
        runtime.request_cancel(db,'job')
        if batch:
            result = asyncio.run(batch_jobs(BatchJobsRequest(action='delete',job_ids=['job']), Response(),request_id='request',db=db))
            assert not result.accepted
        else:
            with pytest.raises(HTTPException) as error:
                asyncio.run(delete_job('job', Response(), request_id='request',db=db))
            assert error.value.status_code == 409
        assert db.get(Job,'job').status == 'canceling'



def test_native_provider_exception_payloads_are_not_logged(tmp_path, monkeypatch, caplog):
    from types import SimpleNamespace
    from backend.app.pipeline.sensor_handlers import handle_file_triage
    rules = tmp_path/'rules'
    rules.mkdir()
    (rules/'test.yar').write_text('rule test {}')
    files = tmp_path/'extracted_files'/'files'
    files.mkdir(parents=True)
    (files/'sample').write_bytes(b'MZsample')
    output = tmp_path/'sensors'/'file_triage'
    output.mkdir(parents=True)
    monkeypatch.setenv('AIPAM_YARA_RULES_DIR', str(rules))
    def compile_rules(**kw):
        raise RuntimeError('provider-private-token')
    monkeypatch.setitem(sys.modules,'yara',SimpleNamespace(compile=compile_rules,Error=RuntimeError))
    handle_file_triage(tmp_path,output,'job','standard',run_output_dir=tmp_path)
    assert 'provider-private-token' not in caplog.text



def test_stopped_control_refuses_submissions_after_private_cleanup(owned):
    from backend.app.pipeline.runtime_control import ExecutionControl, JobOwnershipLost
    factory, handle, root = owned
    control = ExecutionControl(handle,root,factory)
    control.stop()
    control.cancel_path.unlink()
    with pytest.raises(JobOwnershipLost):
        control.checkpoint()


def interrupt_cleanup(monkeypatch, control, stage, observe=lambda: None):
    """Raise the real Celery timeout once at a real cleanup boundary."""
    from billiard.exceptions import SoftTimeLimitExceeded
    from backend.app.pipeline import sensor_process, runtime_control
    if stage == 'context':
        original_context = runtime_control._current_control
        class Context:
            def get(self):
                return original_context.get()
            def set(self, value):
                return interrupted(value)
            def reset(self, token):
                return interrupted(None)
        original = original_context.set
        calls = []
        def interrupted(value):
            calls.append(stage)
            # Interrupt after restoration, before stop records it. Retrying a
            # single-use ContextVar token would fail here.
            result = original(value)
            observe()
            if len(calls) == 1:
                raise SoftTimeLimitExceeded()
            return result
        monkeypatch.setattr(runtime_control, '_current_control', Context())
        return calls
    if stage == 'join':
        target, name = control._thread, 'join'
    elif stage == 'reaper':
        target, name = sensor_process, 'reap_run_processes'
    else:
        target, name = runtime_control, 'request_cancel_file'
    original = getattr(target, name)
    calls = []
    def interrupted(*args, **kwargs):
        calls.append(stage)
        observe()
        if len(calls) == 1:
            raise SoftTimeLimitExceeded()
        return original(*args, **kwargs)
    monkeypatch.setattr(target, name, interrupted)
    return calls


@pytest.mark.parametrize('stage', ['join', 'reaper', 'cancel_file', 'context'])
def test_stop_retries_soft_timeout_and_success_is_idempotent(owned, monkeypatch, stage):
    from billiard.exceptions import SoftTimeLimitExceeded
    from backend.app.pipeline.runtime_control import ExecutionControl, JobOwnershipLost
    factory, handle, root = owned
    control = ExecutionControl(handle, root, factory).start()
    calls = interrupt_cleanup(monkeypatch, control, stage)
    try:
        with pytest.raises(SoftTimeLimitExceeded):
            control.stop()
        with pytest.raises(JobOwnershipLost):
            control.checkpoint()
        assert not control.cleanup_complete
        control.stop()
        assert control.cleanup_complete
        assert control.cancel_path.exists()
        assert len(calls) == 2
        control.stop()
        control.stop()
        assert len(calls) == 2
    finally:
        control._stop.set()
        control._thread.join(timeout=2)


@pytest.mark.parametrize('stage', ['join', 'reaper', 'cancel_file'])
@pytest.mark.parametrize('mode', ['success', 'failed', 'canceling', 'cancel_race', 'lost'])
def test_soft_timeout_preserves_unresolved_worker_receipts_and_original_error(
        worker_harness, monkeypatch, caplog, stage, mode):
    import json
    from billiard.exceptions import SoftTimeLimitExceeded
    from backend.app.pipeline.runtime_control import JobCancellationRequested, JobOwnershipLost
    from backend.app.pipeline.outcomes import derive_outcome
    h = worker_harness
    saved, terminal_calls = {}, []
    original_error = {'success': SoftTimeLimitExceeded, 'cancel_race': SoftTimeLimitExceeded, 'failed': RuntimeError,
                      'canceling': JobCancellationRequested, 'lost': JobOwnershipLost}[mode]
    error = original_error('pipeline-private-detail') if mode not in ('success', 'cancel_race') else None
    original_finalize = runtime.finalize_owned_job
    def finalize(*args, **kwargs):
        terminal_calls.append(args)
        return original_finalize(*args, **kwargs)
    monkeypatch.setattr(runtime, 'finalize_owned_job', finalize)
    def pipeline(**kw):
        receipt = kw['run_output_dir']/'control'/'handler-pending.json'
        receipt.write_text(json.dumps({'state': 'launching', 'group_nonce': 'pending'}))
        saved.update(receipt=receipt, control=kw['control'])
        def observe():
            if mode == 'cancel_race':
                with h.factory() as db:
                    runtime.request_cancel(db, 'job')
        interrupt_cleanup(monkeypatch, kw['control'], stage, observe)
        if mode == 'canceling':
            with h.factory() as db:
                runtime.request_cancel(db, 'job')
        if error is not None:
            raise error
        return derive_outcome()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    with pytest.raises(original_error) as raised:
        h.worker.execute_job('job', 'task')
    if error is not None:
        assert raised.value is error
    assert saved['receipt'].exists()
    assert terminal_calls == [] and h.events == []
    assert not saved['control'].cleanup_complete
    assert 'JOB_CLEANUP_INCOMPLETE' in caplog.text
    assert 'pipeline-private-detail' not in caplog.text
    with h.factory() as db:
        row = db.get(Job, 'job')
        assert row.status == ('canceling' if mode in ('canceling', 'cancel_race') else 'running')
        assert row.completed_at is None
    # The fixture never launched a child. Resolve its synthetic pending intent,
    # then prove a later stop really reconciles instead of caching the failure.
    saved['receipt'].unlink()
    saved['control'].stop()
    assert saved['control'].cleanup_complete
    assert saved['control'].cancel_path.exists()
    assert terminal_calls == [] and h.events == []


@pytest.mark.parametrize('stage', ['join', 'reaper', 'cancel_file', 'context'])
@pytest.mark.parametrize('mode', ['success', 'failed', 'canceling', 'cancel_race', 'lost'])
def test_worker_soft_timeout_retry_proves_cleanup_before_terminal_cas(
        worker_harness, monkeypatch, stage, mode):
    from billiard.exceptions import SoftTimeLimitExceeded
    from backend.app.pipeline.runtime_control import JobCancellationRequested, JobOwnershipLost
    from backend.app.pipeline.outcomes import derive_outcome
    h = worker_harness
    saved, terminal_proofs = {}, []
    original_error = {'success': SoftTimeLimitExceeded, 'cancel_race': SoftTimeLimitExceeded, 'failed': RuntimeError,
                      'canceling': JobCancellationRequested, 'lost': JobOwnershipLost}[mode]
    error = original_error() if mode not in ('success', 'cancel_race') else None
    original_finalize = runtime.finalize_owned_job
    def finalize(*args, **kwargs):
        # Observe the real CAS without blocking it: a false proof must still be
        # detected even when the worker catches an exception from finalization.
        terminal_proofs.append((getattr(saved['control'], 'cleanup_complete', False),
                               saved['control'].cancel_path.exists(), len(saved['calls'])))
        return original_finalize(*args, **kwargs)
    monkeypatch.setattr(runtime, 'finalize_owned_job', finalize)
    def pipeline(**kw):
        saved['control'] = kw['control']
        def observe():
            assert h.events == []
            with h.factory() as db:
                assert db.get(Job, 'job').completed_at is None
                if mode == 'cancel_race':
                    runtime.request_cancel(db, 'job')
        saved['calls'] = interrupt_cleanup(monkeypatch, kw['control'], stage, observe)
        if mode == 'canceling':
            with h.factory() as db:
                runtime.request_cancel(db, 'job')
        if error is not None:
            raise error
        return derive_outcome()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    if mode in ('success', 'failed', 'cancel_race'):
        with pytest.raises(original_error) as raised:
            h.worker.execute_job('job', 'task')
        if error is not None:
            assert raised.value is error
    else:
        assert h.worker.execute_job('job', 'task') == ('canceled' if mode == 'canceling' else 'superseded')
    assert saved['control'].cleanup_complete
    assert terminal_proofs == ([] if mode == 'lost' else [(True, True, 2)])
    assert h.events == ([] if mode == 'lost' else ['canceled' if mode in ('canceling', 'cancel_race') else 'failed'])


def test_stop_does_not_prove_cleanup_while_heartbeat_is_alive(owned, monkeypatch):
    import threading
    from backend.app.pipeline.runtime_control import ExecutionControl
    from backend.app.bluescrub.isolation.runner import ProcessCleanupIncomplete
    factory, handle, root = owned
    control = ExecutionControl(handle, root, factory)
    release = threading.Event()
    control._thread = threading.Thread(target=release.wait, daemon=True)
    control._thread.start()
    original_join = control._thread.join
    monkeypatch.setattr(control._thread, 'join', lambda **kwargs: original_join(timeout=0))
    try:
        with pytest.raises(ProcessCleanupIncomplete):
            control.stop()
        assert not control.cleanup_complete
        assert not control.cancel_path.exists()
    finally:
        release.set()
        original_join(timeout=2)
    control.stop()
    assert control.cleanup_complete and control.cancel_path.exists()


def test_worker_requires_positive_cleanup_proof_even_if_stop_returns(worker_harness, monkeypatch):
    from backend.app.bluescrub.isolation.runner import ProcessCleanupIncomplete
    from backend.app.pipeline.outcomes import derive_outcome
    h = worker_harness
    saved, terminal_calls = {}, []
    original_finalize = runtime.finalize_owned_job
    def finalize(*args, **kwargs):
        terminal_calls.append(args)
        return original_finalize(*args, **kwargs)
    monkeypatch.setattr(runtime, 'finalize_owned_job', finalize)
    def pipeline(**kw):
        control = kw['control']
        saved.update(control=control, stop=control.stop, root=kw['run_output_dir'])
        # Model a stop method that incorrectly returns without reconciling.
        monkeypatch.setattr(control, 'stop', lambda: None)
        return derive_outcome()
    monkeypatch.setattr(h.pipeline, 'run_pipeline', pipeline)
    try:
        with pytest.raises(ProcessCleanupIncomplete):
            h.worker.execute_job('job', 'task')
        assert saved['root'].exists()
        assert terminal_calls == [] and h.events == []
        with h.factory() as db:
            assert db.get(Job, 'job').status == 'running'
    finally:
        saved['stop']()
