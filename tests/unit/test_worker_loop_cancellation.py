from types import SimpleNamespace
import pytest
from backend.app.pipeline import runtime_control as control


@pytest.fixture
def cancel(tmp_path):
    path = tmp_path/'cancel'
    token = control._current_control.set(control.SensorExecutionContext(path))
    yield path
    control._current_control.reset(token)


def test_network_reader_stops_after_first_record(tmp_path, cancel, monkeypatch):
    from backend.app.normalize import network_events as m
    path = tmp_path/'events.jsonl'
    path.write_text('{}\n{}\n')
    calls = []
    original = m.json.loads
    def loads(line):
        calls.append(line)
        cancel.touch()
        return original(line)
    monkeypatch.setattr(m.json, 'loads', loads)
    with pytest.raises(control.JobCancellationRequested):
        m._read_jsonl(path)
    assert len(calls) == 1


def test_telemetry_parser_does_not_request_second_record(tmp_path, cancel, monkeypatch):
    from backend.app.pipeline import telemetry_pipeline as m
    seen = []
    def parse(*a, **kw):
        seen.append(1)
        cancel.touch()
        yield object()
        seen.append(2)
        yield object()
    parser = SimpleNamespace(name='test', parse=parse)
    monkeypatch.setattr(m, 'get_parser_registry', lambda: SimpleNamespace(find_for_file=lambda *a, **k: parser))
    with pytest.raises(control.JobCancellationRequested):
        m._parse_entry(tmp_path/'file', 'job', m.SourceType.log_bundle)
    assert seen == [1]


@pytest.mark.parametrize('file_count', [1, 2])
def test_telemetry_does_not_start_next_file_or_stage(tmp_path, cancel, monkeypatch, file_count):
    from backend.app.pipeline import telemetry_pipeline as m
    folder = tmp_path/'input'/'telemetry'
    folder.mkdir(parents=True)
    entries = [SimpleNamespace(filename=n, source_type='log_bundle', parser_hint=None,
                source_system=None, label=None) for n in ('first', 'second')[:file_count]]
    for e in entries:
        (folder/e.filename).touch()
    monkeypatch.setattr(m, 'register_all_parsers', lambda: None)
    monkeypatch.setattr(m, '_load_manifest', lambda p: SimpleNamespace(entries=entries, exercise_id=None))
    calls = []
    def parse(path, **kw):
        calls.append(path.name)
        cancel.touch()
        return [], m.FileDiagnostic(filename=path.name, status='ok')
    monkeypatch.setattr(m, '_parse_entry', parse)
    monkeypatch.setattr(m, 'persist_parser_results', lambda *a: pytest.fail('next stage ran'))
    with pytest.raises(control.JobCancellationRequested):
        m.run_telemetry_pipeline('job', tmp_path, None, run_output_dir=tmp_path)
    assert calls == ['first']


def test_correlation_persistence_stops_after_first_record(cancel, monkeypatch):
    from backend.app.services import telemetry_correlator as m
    seen = []
    def add(row):
        seen.append(row)
        cancel.touch()
    monkeypatch.setattr(m, 'parser_result_to_db', lambda row, job: row)
    with pytest.raises(control.JobCancellationRequested):
        m.persist_parser_results([1, 2], 'job', SimpleNamespace(add=add))
    assert seen == [1]


def test_network_conversion_stops_after_first_record(tmp_path, cancel, monkeypatch):
    from backend.app.normalize import network_events as m
    folder = tmp_path/'sensors'/'zeek'
    folder.mkdir(parents=True)
    (folder/'sensor.results.jsonl').write_text('{}\n{}\n')
    calls = []
    def convert(*args):
        calls.append(args)
        cancel.touch()
    monkeypatch.setattr(m, '_record_to_event', convert)
    with pytest.raises(control.JobCancellationRequested):
        m.normalize_network_events('job', tmp_path, None)
    assert len(calls) == 1


@pytest.mark.parametrize('module,first,entrypoint', [
    ('backend.app.sensors.behavioral', 'detect_role_baseline_anomalies', 'run_behavioral_detectors'),
    ('backend.app.services.behavioral_memory', 'extract_beacon_profiles', 'extract_all_fingerprints'),
])
def test_downstream_cancellation_is_not_swallowed(cancel, monkeypatch, module, first, entrypoint):
    import importlib
    m = importlib.import_module(module)
    def stop(*args):
        cancel.touch()
        control.checkpoint()
    monkeypatch.setattr(m, first, stop)
    with pytest.raises(control.JobCancellationRequested):
        getattr(m, entrypoint)(None, 'job')
