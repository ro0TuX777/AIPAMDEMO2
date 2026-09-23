"""Containment survives ancestry loss; missing proof cannot authorize completion."""
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.app.bluescrub.isolation import runner
from backend.app.pipeline import sensor_process as process


def executor_identity():
    return dict(executor_pid=42, executor_pid_start_ticks=100, executor_boot_id='boot',
                executor_session_id=42, executor_group_nonce='executor-nonce')


def reparenting_table(monkeypatch, *, unresponsive=False):
    def item(pid, parent, ticks):
        return dict(pid=pid, ppid=parent, start_ticks=ticks, boot_id='boot',
                    pgid=42, sid=42, state='S')
    table = {42: item(42, 1, 100), 51: item(51, 42, 101)}
    signals = []
    class ProcRoot:
        def glob(self, pattern):
            return [SimpleNamespace(parent=SimpleNamespace(name=str(pid))) for pid in list(table)]
    real_path = process.Path
    monkeypatch.setattr(process, 'Path', lambda p: ProcRoot() if str(p) == '/proc' else real_path(p))
    monkeypatch.setattr(runner, 'read_process_identity', table.get)
    monkeypatch.setattr(process, 'read_identity', table.get)
    monkeypatch.setattr(process, 'read_process_identity', table.get)
    monkeypatch.setattr(runner, 'group_members', lambda pgid: [dict(p) for p in table.values() if p['pgid'] == pgid])
    monkeypatch.setattr(runner, 'session_members', lambda sid: [dict(p) for p in table.values() if p['sid'] == sid], raising=False)
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: 'executor-nonce')
    monkeypatch.setattr(signal, 'SIGSTOP', 19, raising=False)
    monkeypatch.setattr(signal, 'SIGKILL', 9, raising=False)
    def send(expected, sig):
        pid = expected['pid']
        signals.append((pid, sig))
        if pid not in table:
            return
        if pid == 42 and sig == signal.SIGSTOP:
            # Still-running 51 forks 61; 61 forks 303, exits, and is reaped by
            # 51 before the first discovery. No handler receipt ever existed.
            table[303] = item(303, 1, 103)
        if pid == 303 and unresponsive:
            return
        if sig == signal.SIGSTOP:
            table[pid]['state'] = 'T'
        elif sig == signal.SIGKILL:
            table.pop(pid)
    monkeypatch.setattr(process, '_signal_exact', send)
    monkeypatch.setattr(runner, 'signal_exact_process', send)
    return table, signals


def test_executor_session_catches_fork_reap_reparent_without_handler_receipt(tmp_path, monkeypatch):
    table, signals = reparenting_table(monkeypatch)
    result = process.stop_executor(executor_identity(), tmp_path, .3)
    assert result == 'matching'
    assert not table, 'terminal proof lost the reparented writer 303'
    assert (303, signal.SIGKILL) in signals
    assert signals.index((51, signal.SIGKILL)) < signals.index((42, signal.SIGKILL))


def test_legacy_executor_without_containment_proof_fails_closed(tmp_path, monkeypatch):
    table, signals = reparenting_table(monkeypatch)
    identity = executor_identity()
    del identity['executor_session_id']
    del identity['executor_group_nonce']
    assert process.stop_executor(identity, tmp_path, .3) == 'unavailable'
    assert signals == []


@pytest.mark.parametrize('unresponsive', [False, True])
def test_supervisor_cannot_cas_while_reparented_writer_survives(tmp_path, monkeypatch, unresponsive):
    from sqlalchemy import create_engine, update
    from sqlalchemy.orm import sessionmaker
    from backend.app.database_v2 import Base
    from backend.app.models.job import Job
    from backend.app.services import job_runtime as runtime
    from backend.app.runtime_supervisor import RuntimeSupervisor
    engine = create_engine(f"sqlite:///{tmp_path/'runtime.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory() as db:
        db.add(Job(job_id='job', status='queued', execution_profile='standard', created_at='2026-01-01'))
        db.commit()
        runtime.assign_task(db, 'job', 'task')
        handle = runtime.claim_job(db, 'job', 'task', 'token', 'worker').handle
        # Use the existing constructor here so RED exercises the actual unsafe
        # helper/CAS rather than failing on the future dataclass fields.
        runtime.register_executor(db, handle, runtime.ExecutorIdentity('node', 'a'*64, 42, 100, 'boot'))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1)))
        db.commit()
    table, signals = reparenting_table(monkeypatch, unresponsive=unresponsive)
    calls, events, survivors_at_cas = [], [], []
    real_complete = runtime.complete_cancel_escalation
    def complete(*args):
        survivors_at_cas.append(set(table))
        calls.append(True)
        return real_complete(*args)
    monkeypatch.setattr(runtime, 'complete_cancel_escalation', complete)
    class Transport:
        def stop_executor(self, identity, path, budget):
            return process.stop_executor(executor_identity(), path, .2)
        def cleanup_containers(self, *args):
            pass
    service = RuntimeSupervisor(factory, tmp_path, transport=Transport(), emit=lambda *a: events.append(a))
    service.cancel_once()
    with factory() as db:
        row = db.get(Job, 'job')
        if unresponsive:
            assert row.status == 'canceling' and row.error_summary == 'CANCEL_ESCALATION_UNAVAILABLE'
            assert 303 in table and calls == [] and events == []
            db.execute(update(Job).values(cancel_escalation_started_at=runtime._now(-16)))
            db.commit()
        else:
            assert row.status == 'canceled' and not table
            assert calls == [True] and events == [('job', 'canceled')]
            assert survivors_at_cas == [set()]
    if unresponsive:
        service.cancel_once()
        assert 303 in table and calls == [] and events == []
    engine.dispose()


def test_handler_launch_publishes_pending_receipt_before_fork(tmp_path, monkeypatch):
    monkeypatch.setattr(process, 'require_process_control', lambda: None)
    class StopProbe(Exception):
        pass
    def popen(*args, **kwargs):
        receipt = json.loads((tmp_path/'control'/'handler-test.json').read_text())
        assert receipt['state'] == 'launching'
        raise StopProbe()
    monkeypatch.setattr(process.subprocess, 'Popen', popen)
    with pytest.raises(StopProbe):
        process.run_tracked_process(['test'], run_output_dir=tmp_path, name='test',
                                    timeout_seconds=1, context=SimpleNamespace(checkpoint=lambda: None))


def test_current_executor_establishes_unique_session_before_identity(monkeypatch):
    from backend.app.pipeline import runtime_control
    events = []
    monkeypatch.setattr(runtime_control, 'os', SimpleNamespace(getpid=lambda: 42,
        setsid=lambda: events.append('setsid'), environ={}))
    def read(pid):
        assert events == ['setsid']
        return dict(pid=42, pgid=42, sid=42, start_ticks=100, boot_id='boot')
    monkeypatch.setattr(runtime_control, 'process_identity', read)
    monkeypatch.setattr(runner, 'require_process_control', lambda: None)
    docker = SimpleNamespace(containers=SimpleNamespace(get=lambda name: SimpleNamespace(id='a'*64)))
    value = runtime_control.current_executor('node', docker)
    assert value.executor_session_id == 42 and value.executor_group_nonce


@pytest.mark.parametrize('missing', [True, False])
def test_incomplete_or_conflicting_executor_containment_never_signals(tmp_path, monkeypatch, missing):
    table, signals = reparenting_table(monkeypatch)
    table.pop(42)
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: None if missing else 'different')
    result = process.stop_executor(executor_identity(), tmp_path, .1)
    assert result == ('unavailable' if missing else 'conflict')
    assert signals == [] and 51 in table


def test_pending_boundary_receipt_blocks_completion_across_retries(tmp_path, monkeypatch):
    table, signals = reparenting_table(monkeypatch)
    path = tmp_path/'control'/'handler-pending.json'
    path.parent.mkdir()
    path.write_text(json.dumps(dict(state='launching', group_nonce='new')))
    for _ in range(2):
        assert process.stop_executor(executor_identity(), tmp_path, .1) == 'unavailable'
    assert path.exists() and 303 in table
    assert all(sig == signal.SIGSTOP for _, sig in signals)


def test_session_tracks_members_that_change_process_group(monkeypatch):
    leader = dict(pid=42, ppid=1, pgid=42, sid=42, start_ticks=100, boot_id='boot', state='S')
    orphan = dict(leader, pid=303, ppid=1, pgid=303, start_ticks=103)
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: leader if pid == 42 else orphan)
    monkeypatch.setattr(runner, 'session_members', lambda sid: [leader, orphan])
    assert {item['pid'] for item in runner.ProcessSession(leader, 'nonce').snapshot()} == {42, 303}


def test_signal_rejects_changed_session_even_when_pid_start_boot_match(monkeypatch):
    expected = dict(pid=42, pgid=42, sid=42, start_ticks=100, boot_id='boot')
    closed, sent = [], []
    monkeypatch.setattr(runner, 'os', SimpleNamespace(pidfd_open=lambda pid: 77, close=closed.append))
    monkeypatch.setattr(runner, 'signal', SimpleNamespace(pidfd_send_signal=lambda *args: sent.append(args)))
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: dict(expected, pgid=51, sid=51))
    with pytest.raises(runner.ProcessIdentityConflict):
        runner.signal_exact_process(expected, 15)
    assert sent == [] and closed == [77]


def test_boundary_bootstrap_publishes_exact_receipt_before_exec(tmp_path, monkeypatch):
    from backend.app.bluescrub.isolation import launch
    receipt = tmp_path/'handler-test.json'
    receipt.write_text(json.dumps(dict(state='launching', group_nonce='nonce')))
    identity = dict(pid=42, pgid=42, sid=42, start_ticks=100, boot_id='boot', state='S')
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: identity)
    class Executed(Exception):
        pass
    def execute(*args):
        stored = json.loads(receipt.read_text())
        assert stored == {**identity, 'group_nonce': 'nonce', 'handler': 'test'}
        raise Executed()
    monkeypatch.setattr(launch, 'os', SimpleNamespace(getpid=lambda: 42, execvpe=execute, environ={}))
    with pytest.raises(Executed):
        launch.main(dict(record=str(receipt), nonce='nonce', name='test', argv=['analyzer']))


def test_bluescrub_launch_intent_exists_before_session_escape(tmp_path, monkeypatch):
    monkeypatch.setenv('AIPAM_RUN_CONTROL_DIR', str(tmp_path))
    monkeypatch.setattr(runner, 'require_process_control', lambda: None)
    monkeypatch.setattr(runner, 'resolve_drop_target', lambda user: (None, None))
    class Interrupted(Exception):
        pass
    def spawn(argv, **kwargs):
        records = list(tmp_path.glob('handler-analyzer-*.json'))
        assert len(records) == 1
        assert json.loads(records[0].read_text())['state'] == 'launching'
        raise Interrupted()
    monkeypatch.setattr(runner.subprocess, 'Popen', spawn)
    with pytest.raises(Interrupted):
        runner.run_analyzer(['analyzer'], require_privilege_drop=False)


def test_sensor_entry_refuses_another_process_receipt(tmp_path, monkeypatch):
    request = tmp_path/'request.json'
    control = tmp_path/'control'
    control.mkdir()
    request.write_text(json.dumps(dict(name='zeek', input_root=str(tmp_path), run_output_dir=str(tmp_path),
                                      sensor_output_dir=str(tmp_path), job_id='job', execution_profile='standard',
                                      cancel_path=str(control/'cancel.requested'))))
    (control/'handler-zeek.json').write_text(json.dumps(dict(pid=999, pgid=999, sid=999,
        start_ticks=1, boot_id='boot', group_nonce='nonce')))
    work = []
    monkeypatch.setitem(sys.modules, 'backend.app.sensors.registry', SimpleNamespace(
        SENSORS={'zeek': SimpleNamespace(handler=lambda **kw: work.append(True))}))
    monkeypatch.setattr(process, 'os', SimpleNamespace(name='posix', getpid=lambda: 42,
                                                     environ={'AIPAM_PROCESS_GROUP_NONCE':'nonce'}))
    monkeypatch.setattr(process, 'read_process_identity', lambda pid: dict(pid=42, pgid=42, sid=42,
        start_ticks=100, boot_id='boot'))
    monkeypatch.setattr(sys, 'argv', ['sensor_process', '--request', str(request)])
    token = process._current_control.set(None)
    try:
        assert process.main() == 1
        assert work == []
    finally:
        process._current_control.reset(token)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux launch/session/pidfd containment gate')
def test_real_boundary_receipt_precedes_work_and_contains_orphan(tmp_path):
    from backend.app.bluescrub.isolation.launch import launch_process
    receipt = tmp_path/'control'/'handler-real.json'
    writer = tmp_path/'writer'
    code = '''import json,os,pathlib,signal,time
receipt=json.loads(pathlib.Path(os.environ['AIPAM_RUN_CONTROL_DIR'],'handler-real.json').read_text())
assert receipt['pid']==os.getpid()==os.getsid(0)
parent=os.fork()
if parent:
    os.waitpid(parent,0)
    time.sleep(30)
else:
    child=os.fork()
    if child:
        os._exit(0)
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    pathlib.Path(os.environ['WRITER']).write_text(str(os.getpid()))
    time.sleep(30)
'''
    proc = launch_process([sys.executable, '-c', code], record=receipt, name='real',
                          env={**os.environ, 'WRITER': str(writer)}, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE)
    try:
        until = time.monotonic()+5
        while not writer.exists() and time.monotonic() < until:
            time.sleep(.01)
        assert writer.exists()
        item = json.loads(receipt.read_text())
        expected = dict(executor_pid=proc.pid, executor_pid_start_ticks=item['start_ticks'],
                        executor_boot_id=item['boot_id'], executor_session_id=proc.pid,
                        executor_group_nonce=item['group_nonce'])
        # The executor-session path alone must find this orphan; remove the
        # duplicate handler receipt in this fixture, before cancellation starts.
        receipt.unlink()
        assert process.stop_executor(expected, tmp_path, 5) == 'matching'
        live = runner.read_process_identity(int(writer.read_text()))
        assert live is None or live['state'] == 'Z'
    finally:
        runner._kill_group(proc, 0)
