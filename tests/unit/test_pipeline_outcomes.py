"""Truthful outcomes and durable worker ownership, using real SQLite transactions."""
import json
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.database_v2 import Base
from backend.app.models.job import Job
from backend.app.pipeline import orchestrator
from backend.app.pipeline.run_artifacts import create_run_output_dir
from backend.app.services.job_runtime import assign_task, claim_job, request_cancel


def outcome_module():
    from backend.app.pipeline import outcomes
    return outcomes


@pytest.mark.parametrize('required,optional,want', [(True, False, 'failed'), (False, True, 'completed_with_errors'), (False, False, 'completed')])
def test_outcome_policy(required, optional, want):
    m = outcome_module()
    failure = m.StageFailure('correlate', 'broken')
    result = m.derive_outcome(required=[failure] if required else [], optional=[failure] if optional else [])
    assert result.status == want


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    from backend.app import worker, database_v2
    engine = create_engine(f"sqlite:///{tmp_path / 'runtime.db'}")
    Base.metadata.create_all(engine)
    sessions = []
    factory = sessionmaker(bind=engine)
    def session_factory():
        session = factory()
        sessions.append(session)
        return session
    settings = SimpleNamespace(aipam_job_root=tmp_path/'jobs', aipam_upload_root=tmp_path/'uploads', aipam_sensor_config_dir=None, aipam_max_job_disk_bytes=1000000, aipam_preflight_multiplier=4)
    monkeypatch.setattr(worker, 'get_settings', lambda: settings)
    monkeypatch.setattr(database_v2, 'init_v2_db', lambda: None)
    monkeypatch.setattr(database_v2, 'get_session_factory', lambda: session_factory)
    import docker
    monkeypatch.setattr(docker, 'from_env', lambda: None)
    events, distilled = [], []
    import backend.app.events as event_module
    def emit(job_id, event, payload):
        with factory() as observer:
            row = observer.get(Job, job_id)
            assert row.completed_at is not None
            events.append((event, row.status))
    monkeypatch.setattr(event_module, 'publish_job_event', emit)
    if hasattr(worker, 'distill_job'):
        monkeypatch.setattr(worker.distill_job, 'delay', lambda job_id: distilled.append(job_id))
    with factory() as db:
        db.add(Job(job_id='job', execution_profile='standard', status='queued', created_at='2026-09-23T00:00:00Z', artifact_layout_version=2))
        db.commit()
        assign_task(db, 'job', 'task')
    yield SimpleNamespace(worker=worker, factory=factory, sessions=sessions, settings=settings, events=events, distilled=distilled)
    engine.dispose()


def completed(run_dir):
    m = outcome_module()
    from backend.app.pipeline.run_artifacts import build_accepted_manifest
    return m.derive_outcome(metrics={'total': 1}, accepted_manifest_json=build_accepted_manifest(None, run_dir.name, None))


@pytest.mark.parametrize('status', ['completed', 'completed_with_errors', 'failed'])
def test_worker_claims_and_finalizes_outcome(runtime, monkeypatch, status):
    def pipeline(**kw):
        assert kw['db'].get(Job, 'job').status == 'running'
        assert kw['run_output_dir'].parent.name == '.runs'
        m = outcome_module()
        failure = m.StageFailure('test', 'broken')
        return m.derive_outcome(required=[failure] if status == 'failed' else [], optional=[failure] if status == 'completed_with_errors' else [], metrics={'total': 1}, accepted_manifest_json=completed(kw['run_output_dir']).accepted_manifest_json)
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    assert runtime.worker.execute_job('job', 'task') == status
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        assert row.status == status
        assert row.completed_at
        assert json.loads(row.metrics_json) == {'total': 1}
        assert bool(row.accepted_run_manifest_json) == (status != 'failed')
    assert runtime.events == [('job.complete', status)]
    assert runtime.distilled == ([] if status == 'failed' else ['job'])


@pytest.mark.parametrize('delivery', ['duplicate', 'busy', 'superseded'])
def test_worker_rejects_nonclaimable_delivery(runtime, monkeypatch, delivery):
    def pipeline(**kw):
        return completed(kw['run_output_dir'])
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    if delivery == 'duplicate':
        runtime.worker.execute_job('job', 'task')
    elif delivery == 'busy':
        with runtime.factory() as db:
            claim_job(db, 'job', 'task', str(uuid4()), 'other')
    monkeypatch.setattr(orchestrator, 'run_pipeline', lambda **kw: pytest.fail('must not execute'))
    runtime.worker.execute_job('job', 'old-task' if delivery == 'superseded' else 'task')
    assert len(runtime.events) == (1 if delivery == 'duplicate' else 0)


def test_poisoned_pipeline_session_is_closed_before_fresh_failure_transaction(runtime, monkeypatch):
    pipeline_session = []
    def pipeline(**kw):
        db = kw['db']
        pipeline_session.append(db)
        db.add(Job(job_id='job', created_at='duplicate'))
        db.flush()  # Real SQLite integrity failure puts Session into rollback-required state.
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    with pytest.raises(IntegrityError):
        runtime.worker.execute_job('job', 'task')
    assert runtime.sessions[-1] is not pipeline_session[0]
    assert not pipeline_session[0].in_transaction()
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        assert row.status == 'failed'
        assert row.completed_at
    assert runtime.events == [('job.complete', 'failed')]


@pytest.mark.parametrize('exception', [False, True])
def test_cancel_racing_pipeline_never_accepts_outputs(runtime, monkeypatch, exception):
    def pipeline(**kw):
        with runtime.factory() as db:
            request_cancel(db, 'job')
        if exception:
            raise outcome_module().PipelineCanceled('canceled')
        return completed(kw['run_output_dir'])
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    assert runtime.worker.execute_job('job', 'task') == 'canceled'
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        assert row.status == 'canceled'
        assert row.accepted_run_manifest_json is None
    assert runtime.distilled == []


@pytest.mark.parametrize('exception', [False, True])
def test_lost_owner_cleans_only_its_private_run(runtime, monkeypatch, exception):
    winner_token = str(uuid4())
    winner_dir = create_run_output_dir(runtime.settings.aipam_job_root, 'job', winner_token)
    def pipeline(**kw):
        with runtime.factory() as db:
            db.execute(update(Job).where(Job.job_id == 'job').values(run_token=winner_token, celery_task_id='winner'))
            db.commit()
        if exception:
            raise outcome_module().OwnershipLost('superseded')
        return completed(kw['run_output_dir'])
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    assert runtime.worker.execute_job('job', 'task') == 'superseded'
    assert list(winner_dir.parent.iterdir()) == [winner_dir]
    with runtime.factory() as db:
        assert db.get(Job, 'job').status == 'running'
    assert not runtime.events


@pytest.fixture
def pipeline_env(runtime, monkeypatch):
    # External/heavy enrichment providers are replaced; orchestrator and persistence remain real.
    modules = {
        'backend.app.normalize.correlate': {'correlate_job': lambda *a, **k: {'findings': 0}},
        'backend.app.normalize.post_process': {'update_global_host_stats': lambda *a: None},
        'backend.app.normalize.network_events': {'normalize_network_events': lambda *a: 0},
        'backend.app.services.theory_engine': {'generate_all_theories': lambda *a, **k: {'total': 0}},
        'backend.app.services.slicer': {'generate_slices': lambda *a, **k: []},
        'backend.app.services.contextualizer': {'generate_annotations': lambda *a, **k: []},
        'backend.app.services.embedding_models': {'get_embedding_model_service': lambda *a: SimpleNamespace(get_active=lambda: None), 'get_runtime_ollama_url': lambda *a: ''},
        'backend.app.services.kb_service': {'auto_index_job': lambda **k: None},
    }
    for name, attrs in modules.items():
        monkeypatch.setitem(sys.modules, name, SimpleNamespace(**attrs))
    runtime.pipeline_events = []
    monkeypatch.setattr(orchestrator, '_emit', lambda job_id, event, **kw: runtime.pipeline_events.append(event))
    monkeypatch.setitem(sys.modules, 'backend.app.distillation', SimpleNamespace(reload_teacher_config=lambda: pytest.fail('distillation must be post-terminal')))
    monkeypatch.setattr(orchestrator, '_publish_partial_result', lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, 'get_stages_for_profile', lambda _: [])
    monkeypatch.setattr(orchestrator, 'get_sensors_for_profile', lambda _: [])
    import backend.app.partial_results as partial
    monkeypatch.setattr(partial, 'delete_partial_result', lambda _: None)
    with runtime.factory() as db:
        claim = claim_job(db, 'job', 'task', str(uuid4()), 'worker')
        row = db.get(Job, 'job')
        row.source_type = 'other'
        db.commit()
    run_dir = create_run_output_dir(runtime.settings.aipam_job_root, 'job', claim.handle.run_token)
    def run():
        with runtime.factory() as db:
            return orchestrator.run_pipeline('job', db, docker_client=None, job_root=runtime.settings.aipam_job_root, upload_root=runtime.settings.aipam_upload_root, run_output_dir=run_dir)
    return run, runtime, run_dir


@pytest.mark.parametrize('stage,want', [('success', 'completed'), ('correlate', 'failed'), ('theories', 'completed_with_errors'), ('annotations', 'completed_with_errors')])
def test_pipeline_stage_policy_and_no_terminal_writes(pipeline_env, monkeypatch, stage, want):
    run, runtime, run_dir = pipeline_env
    targets = {'correlate': ('backend.app.normalize.correlate', 'correlate_job'), 'theories': ('backend.app.services.theory_engine', 'generate_all_theories'), 'annotations': ('backend.app.services.contextualizer', 'generate_annotations')}
    if stage != 'success':
        module, attr = targets[stage]
        monkeypatch.setattr(sys.modules[module], attr, lambda *a, **k: (_ for _ in ()).throw(RuntimeError('broken')))
    outcome = run()
    assert outcome.status == want
    assert 'job.complete' not in runtime.pipeline_events
    failures = outcome.required_failures if stage == 'correlate' else outcome.optional_failures
    if stage != 'success':
        assert stage in [f.stage for f in failures]
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        assert row.status == 'running'
        assert row.completed_at is None
        assert row.accepted_run_manifest_json is None


@pytest.mark.parametrize('kind', ['PipelineCanceled', 'OwnershipLost'])
def test_control_exceptions_propagate_from_optional_stage(pipeline_env, monkeypatch, kind):
    run, _, _ = pipeline_env
    error = getattr(outcome_module(), kind)
    monkeypatch.setattr(sys.modules['backend.app.services.theory_engine'], 'generate_all_theories', lambda *a, **k: (_ for _ in ()).throw(error('stop')))
    with pytest.raises(error):
        run()

@pytest.mark.parametrize('required,status,want', [(False, 'failed', 'completed_with_errors'), (True, 'failed', 'failed'), (False, 'timeout', 'completed_with_errors')])
@pytest.mark.parametrize('is_stage', [False, True])
def test_sensor_registry_required_policy(pipeline_env, monkeypatch, required, status, want, is_stage):
    from backend.app.pipeline.sensor_runner import SensorResult
    from backend.app.sensors.registry import SensorDef
    run, runtime, _ = pipeline_env
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        row.source_type, row.upload_id = 'pcap', 'upload'
        db.commit()
    upload = runtime.settings.aipam_upload_root/'upload'
    upload.mkdir(parents=True)
    (upload/'capture.pcap').write_bytes(b'pcap')
    sensor = SensorDef(name='sensor', type='stage' if is_stage else 'sensor', required=required)
    monkeypatch.setattr(orchestrator, 'get_stages_for_profile' if is_stage else 'get_sensors_for_profile', lambda _: [sensor])
    monkeypatch.setattr(orchestrator, 'run_sensor', lambda **kw: SensorResult(sensor='sensor', status=status, error='broken'))
    result = run()
    assert result.status == want
    assert [f.stage for f in (result.required_failures if required else result.optional_failures)] == ['sensor']


def test_quota_failure_is_required(pipeline_env, monkeypatch):
    from backend.app.pipeline.sensor_runner import SensorResult
    from backend.app.sensors.registry import SensorDef
    run, runtime, _ = pipeline_env
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        row.source_type, row.upload_id = 'pcap', 'upload'
        db.commit()
    upload = runtime.settings.aipam_upload_root/'upload'
    upload.mkdir(parents=True)
    (upload/'capture.pcap').write_bytes(b'pcap')
    monkeypatch.setattr(orchestrator, 'get_sensors_for_profile', lambda _: [SensorDef(name='sensor', type='sensor')])
    monkeypatch.setattr(orchestrator, 'run_sensor', lambda **kw: SensorResult(sensor='sensor', status='completed'))
    monkeypatch.setattr(orchestrator, 'check_job_quota', lambda *a: True)
    result = run()
    assert result.status == 'failed'
    assert [f.stage for f in result.required_failures] == ['quota']


@pytest.mark.parametrize('source_type', ['binary', 'code_artifact'])
@pytest.mark.parametrize('mode,want', [('success', 'completed'), ('partial', 'completed_with_errors'), ('missing', 'failed'), ('failure', 'failed')])
def test_alternate_branches_return_outcomes_without_status_writes(pipeline_env, monkeypatch, source_type, mode, want):
    run, runtime, _ = pipeline_env
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        row.source_type = source_type
        db.commit()
    directory = runtime.settings.aipam_job_root/'job'/'input'
    if mode != 'missing':
        if source_type == 'code_artifact':
            directory = directory/'source'
        directory.mkdir(parents=True, exist_ok=True)
        (directory/'sample').write_bytes(b'test')
    def analyze(*a, **kw):
        if mode == 'failure':
            raise RuntimeError('broken')
        if source_type == 'binary':
            return SimpleNamespace(artifact_class='binary', format='elf', yara_available=mode != 'partial', yara_matches=[]), None, 0
        return {'dacv': {'partial': mode == 'partial', 'partial_reasons': [{'sensor': 'semgrep', 'error': 'broken'}] if mode == 'partial' else []}}
    module = 'backend.app.binalysis.service' if source_type == 'binary' else 'backend.app.bluescrub.service'
    monkeypatch.setitem(sys.modules, module, SimpleNamespace(analyze_and_persist=analyze))
    result = run()
    assert result.status == want
    with runtime.factory() as db:
        assert db.get(Job, 'job').status == 'running'


def test_manifest_failure_is_required(pipeline_env, monkeypatch):
    run, _, _ = pipeline_env
    monkeypatch.setattr(orchestrator, 'build_accepted_manifest', lambda *a: (_ for _ in ()).throw(ValueError('invalid manifest')))
    result = run()
    assert result.status == 'failed'
    assert [f.stage for f in result.required_failures] == ['manifest']


def test_production_dispatch_assigns_identity_before_delivery(runtime, monkeypatch):
    from backend.app.services import job_dispatch
    with runtime.factory() as db:
        db.execute(update(Job).where(Job.job_id == 'job').values(celery_task_id=None))
        db.commit()
    delivered = []
    def apply_async(*, args, task_id):
        with runtime.factory() as db:
            assert db.get(Job, 'job').celery_task_id == task_id
            handle = claim_job(db, 'job', task_id, str(uuid4()), 'test').handle
            assert handle is not None
        delivered.append(args)
    monkeypatch.setattr(runtime.worker.run_job, 'apply_async', apply_async)
    job_dispatch.dispatch_job('job')
    assert delivered == [['job']]
    with runtime.factory() as db:
        assert db.get(Job, 'job').dispatched_at


def test_phase_reanalysis_is_queued_and_claimable(runtime, monkeypatch):
    from backend.app.services.job_lifecycle import reanalyze_job
    from backend.app.services.job_dispatch import dispatch_job_phase
    from backend.app.models.job_pcap import JobPcap
    delivered = []
    def apply_async(*, args, task_id):
        with runtime.factory() as db:
            assert db.get(Job, 'job').status == 'queued'
            assert claim_job(db, 'job', task_id, str(uuid4()), 'worker').handle is not None
        delivered.append(args)
    monkeypatch.setattr(runtime.worker.run_job_phase, 'apply_async', apply_async)
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        row.status, row.run_token = 'completed', str(uuid4())
        row.completed_at = '2026-09-23T00:00:00Z'
        db.add(JobPcap(job_id='job', upload_id='upload', filename='a.pcap', ordinal=0, label='after'))
        db.commit()
        reanalyze_job(row, db, 'after', dispatch_job_phase)
    assert delivered == [['job', 'after']]


def test_distillation_failure_never_changes_successful_analysis(runtime, monkeypatch):
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        row.status, row.completed_at = 'completed', '2026-09-23T00:00:00Z'
        db.commit()
    async def fail(**kw):
        raise RuntimeError('teacher offline')
    monkeypatch.setitem(sys.modules, 'backend.app.distillation', SimpleNamespace(reload_teacher_config=lambda: SimpleNamespace(enabled=True, is_configured=lambda: True), distill_v2=fail))
    assert runtime.worker.distill_job('job')['status'] == 'failed'
    with runtime.factory() as db:
        assert db.get(Job, 'job').status == 'completed'

@pytest.mark.parametrize('kind', ['PipelineCanceled', 'OwnershipLost'])
def test_sensor_handler_control_exceptions_are_not_sensor_failures(tmp_path, kind):
    from backend.app.pipeline.sensor_runner import run_sensor
    from backend.app.sensors.registry import SensorDef
    error = getattr(outcome_module(), kind)
    def handler(**kw):
        raise error('stop')
    sensor = SensorDef(name='control', type='sensor', handler=handler)
    with pytest.raises(error):
        run_sensor(sensor, tmp_path, 'job', 'standard', run_output_dir=tmp_path)


def test_required_sensor_missing_inputs_fails_pipeline(pipeline_env, monkeypatch):
    from backend.app.sensors.registry import SensorDef
    run, runtime, _ = pipeline_env
    with runtime.factory() as db:
        row = db.get(Job, 'job')
        row.source_type, row.upload_id = 'pcap', 'upload'
        db.commit()
    upload = runtime.settings.aipam_upload_root/'upload'
    upload.mkdir(parents=True)
    (upload/'capture.pcap').write_bytes(b'pcap')
    sensor = SensorDef(name='required_sensor', type='sensor', required=True, inputs_required=('missing',), skip_if_missing_inputs=True)
    monkeypatch.setattr(orchestrator, 'get_sensors_for_profile', lambda _: [sensor])
    result = run()
    assert result.status == 'failed'
    assert [f.stage for f in result.required_failures] == ['required_sensor']


def test_postprocessing_failure_is_optional(pipeline_env, monkeypatch):
    run, _, _ = pipeline_env
    monkeypatch.setattr(sys.modules['backend.app.normalize.post_process'], 'update_global_host_stats', lambda *a: (_ for _ in ()).throw(RuntimeError('broken')))
    result = run()
    assert result.status == 'completed_with_errors'
    assert [f.stage for f in result.optional_failures] == ['host_stats']


def test_metrics_runtime_is_measured_before_terminal_commit(pipeline_env):
    run, runtime, run_dir = pipeline_env
    with runtime.factory() as db:
        db.get(Job, 'job').started_at = '2000-01-01T00:00:00Z'
        db.commit()
    run()
    metrics = json.loads((run_dir/'metrics'/'job_metrics.json').read_text())
    assert metrics['total_runtime_sec'] > 0


@pytest.mark.parametrize('phase', [None, 'after'])
def test_celery_request_id_is_the_claim_identity(runtime, monkeypatch, phase):
    def pipeline(**kw):
        assert kw['pcap_label'] == phase
        assert kw['db'].get(Job, 'job').celery_task_id == 'task'
        return completed(kw['run_output_dir'])
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    task = runtime.worker.run_job if phase is None else runtime.worker.run_job_phase
    args = ['job'] if phase is None else ['job', phase]
    result = task.apply(args=args, task_id='task', throw=True)
    assert result.result == 'completed'
    with runtime.factory() as db:
        assert db.get(Job, 'job').status == 'completed'


def test_rollback_error_does_not_prevent_fresh_session_failure(runtime, monkeypatch):
    def pipeline(**kw):
        db = kw['db']
        original_rollback = db.rollback
        def broken_rollback():
            original_rollback()
            raise RuntimeError('rollback transport error')
        monkeypatch.setattr(db, 'rollback', broken_rollback)
        db.add(Job(job_id='job', created_at='duplicate'))
        db.flush()
    monkeypatch.setattr(orchestrator, 'run_pipeline', pipeline)
    with pytest.raises(IntegrityError):
        runtime.worker.execute_job('job', 'task')
    with runtime.factory() as db:
        assert db.get(Job, 'job').status == 'failed'
        assert db.get(Job, 'job').completed_at
