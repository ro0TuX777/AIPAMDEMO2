"""Portable identity/reuse tests; Linux regressions use real orphan processes."""
from types import SimpleNamespace
from pathlib import Path
import os
import signal
import subprocess
import sys
import time
import json
import pytest
from backend.app.bluescrub.isolation import runner


def _forking_executor(monkeypatch, behavior):
    from backend.app.pipeline import sensor_process as m
    monkeypatch.setattr(signal, 'SIGSTOP', 19, raising=False)
    monkeypatch.setattr(signal, 'SIGKILL', 9, raising=False)
    root = dict(identity(pid=42), ppid=1, pgid=42, sid=42)
    current = {42: dict(root)}
    if behavior in ('child_anchor_exit', 'deep_fork_captured'):
        current[51] = dict(identity(pid=51, ticks=101), ppid=42, pgid=42, sid=42)
    sent = []
    class ProcRoot:
        def glob(self, pattern):
            return [SimpleNamespace(parent=SimpleNamespace(name=str(pid))) for pid in list(current)]
    actual_path = m.Path
    monkeypatch.setattr(m, 'Path', lambda p: ProcRoot() if str(p) == '/proc' else actual_path(p))
    monkeypatch.setattr(m, 'read_identity', lambda pid: current.get(pid))
    monkeypatch.setattr(m, 'read_process_identity', lambda pid: current.get(pid))
    monkeypatch.setattr(runner, 'read_process_identity', current.get)
    monkeypatch.setattr(runner, 'session_members', lambda sid: list(current.values()) if sid == 42 else [])
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: 'nonce')
    def send(item, sig):
        pid = item['pid']
        sent.append((pid, sig))
        if pid not in current:
            return
        # Model a fork just before STOP takes effect (or, in the old code,
        # immediately before the first TERM exits the still-running parent).
        should_fork = ((pid == 42 and behavior not in ('child_anchor_exit', 'deep_fork_captured')) or
                       (pid == 51 and behavior in ('child_anchor_exit', 'deep_fork_captured')))
        if should_fork and current[pid]['state'] == 'S' and sig in (signal.SIGSTOP, signal.SIGTERM):
            current[303] = dict(identity(pid=303, ticks=102), ppid=pid, pgid=42, sid=42)
            if behavior in ('before_freeze_exit', 'child_anchor_exit') or sig == signal.SIGTERM:
                current.pop(pid)
                current[303]['ppid'] = 1
                return
        if sig == signal.SIGSTOP:
            current[pid]['state'] = 'T'
        elif sig == signal.SIGTERM:
            if current[pid]['state'] != 'T':
                current.pop(pid)
        elif sig == signal.SIGKILL:
            current.pop(pid)
    monkeypatch.setattr(m, '_signal_exact', send)
    return m, current, sent


@pytest.mark.parametrize('behavior', ['before_freeze_exit', 'freeze_captures_fork', 'child_anchor_exit', 'deep_fork_captured'])
def test_no_receipt_fork_and_reparent_stays_in_executor_session(tmp_path, monkeypatch, behavior):
    m, current, sent = _forking_executor(monkeypatch, behavior)
    executor = dict(executor_pid=42, executor_pid_start_ticks=100, executor_boot_id='boot',
                    executor_session_id=42, executor_group_nonce='nonce')
    assert m.stop_executor(executor, tmp_path, .3) == 'matching'
    assert not current
    assert sent[0] == (42, signal.SIGSTOP)
    assert m.stop_executor(executor, tmp_path, .3) == 'absent'


def test_supervisor_does_not_cas_legacy_executor_without_containment(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, update
    from sqlalchemy.orm import sessionmaker
    from backend.app.database_v2 import Base
    from backend.app.models.job import Job
    from backend.app.services import job_runtime as runtime
    from backend.app import runtime_supervisor as supervisor
    engine = create_engine(f"sqlite:///{tmp_path/'freeze.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory() as db:
        db.add(Job(job_id='job', status='queued', execution_profile='standard', created_at='2026-01-01'))
        db.commit()
        runtime.assign_task(db, 'job', 'task')
        handle = runtime.claim_job(db, 'job', 'task', 'token', 'worker').handle
        runtime.register_executor(db, handle, runtime.ExecutorIdentity('node', 'a'*64, 42, 100, 'boot'))
        runtime.request_cancel(db, 'job')
        db.execute(update(Job).values(cancel_force_at=runtime._now(-1)))
        db.commit()
    process, current, sent = _forking_executor(monkeypatch, 'before_freeze_exit')
    cas, events = [], []
    actual_cas = runtime.complete_cancel_escalation
    def complete(*args):
        cas.append(True)
        return actual_cas(*args)
    monkeypatch.setattr(runtime, 'complete_cancel_escalation', complete)
    class Transport:
        def stop_executor(self, identity, path, budget):
            return process.stop_executor(dict(executor_pid=42, executor_pid_start_ticks=100,
                                              executor_boot_id='boot'), path, .3)
        def cleanup_containers(self, *args): pass
    service = supervisor.RuntimeSupervisor(factory, tmp_path, transport=Transport(), emit=lambda *a: events.append(a))
    service.cancel_once()
    with factory() as db:
        assert db.get(Job, 'job').status == 'canceling'
        db.execute(update(Job).values(cancel_escalation_started_at=runtime._now(-16)))
        db.commit()
    service.cancel_once()
    with factory() as db:
        assert db.get(Job, 'job').status == 'canceling'
    assert 42 in current and not cas and not events and not sent
    engine.dispose()


@pytest.mark.parametrize('stage', ['initial', 'post_term'])
def test_executor_reuse_before_discovery_never_authorizes_replacement_child(tmp_path, monkeypatch, stage):
    from backend.app.pipeline import sensor_process as m
    monkeypatch.setattr(signal, 'SIGSTOP', 19, raising=False)
    original = dict(identity(pid=42), ppid=1, pgid=42, sid=42)
    replacement = dict(original, start_ticks=200)
    unrelated = dict(identity(pid=88, ticks=201), ppid=42, pgid=42, sid=42)
    current = {42: original}
    sent = []
    term_seen = [False]
    class Stat:
        parent = SimpleNamespace(name='88')
    class ProcRoot:
        def glob(self, pattern):
            if stage == 'initial' or term_seen[0]:
                current.update({42: replacement, 88: unrelated})
            return [Stat()]
    actual_path = m.Path
    monkeypatch.setattr(m, 'Path', lambda p: ProcRoot() if str(p) == '/proc' else actual_path(p))
    monkeypatch.setattr(m, 'read_identity', lambda pid: current.get(pid))
    monkeypatch.setattr(m, 'read_process_identity', lambda pid: current.get(pid))
    monkeypatch.setattr(runner, 'read_process_identity', current.get)
    def members(sid):
        ProcRoot().glob('')
        return list(current.values())
    monkeypatch.setattr(runner, 'session_members', members)
    def send(item, sig):
        sent.append((item['pid'], sig))
        if sig == signal.SIGSTOP:
            current[item['pid']]['state'] = 'T'
        if sig == signal.SIGTERM:
            term_seen[0] = True
    monkeypatch.setattr(m, '_signal_exact', send)
    monkeypatch.setattr(m.time, 'sleep', lambda seconds: None)
    result = m.stop_executor(dict(executor_pid=42, executor_pid_start_ticks=100,
                                 executor_boot_id='boot', executor_session_id=42, executor_group_nonce='nonce'), tmp_path, .1)
    assert result == 'conflict'
    assert all(pid != 88 for pid, sig in sent)


@pytest.mark.parametrize('local', [True, False])
def test_fork_at_kill_boundary_is_drained_before_success(tmp_path, monkeypatch, local):
    from backend.app.pipeline import sensor_process as m
    monkeypatch.setattr(signal, 'SIGKILL', 9, raising=False)
    monkeypatch.setattr(signal, 'SIGSTOP', 19, raising=False)
    leader = identity()
    members = {202: dict(leader)}
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: members.get(pid))
    monkeypatch.setattr(runner, 'group_members', lambda pgid: list(members.values()))
    monkeypatch.setattr(runner, 'session_members', lambda sid: list(members.values()) if sid == 202 else [])
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: 'nonce')
    def send(item, sig):
        if sig == signal.SIGSTOP:
            members[item['pid']]['state'] = 'T'
        if sig == signal.SIGKILL:
            members.pop(item['pid'], None)
            if item['pid'] == 202:
                members[303] = identity(pid=303, ticks=101)
    monkeypatch.setattr(runner, 'signal_exact_process', send)
    if local:
        record = tmp_path/'receipt'
        record.touch()
        proc = SimpleNamespace(pid=202, aipam_group=runner.ProcessGroup(leader, 'nonce'), wait=lambda **kw: 0)
        monkeypatch.setattr(runner, 'os', SimpleNamespace(name='posix'))
        m.TrackedChild(proc, record).reap(grace=0)
        assert not record.exists()
    else:
        control = tmp_path/'control'
        control.mkdir()
        (control/'handler-test.json').write_text(json.dumps({**leader, 'group_nonce':'nonce'}))
        monkeypatch.setattr(m, 'read_identity', lambda pid: members.get(pid))
        monkeypatch.setattr(m, 'read_process_identity', lambda pid: members.get(pid))
        monkeypatch.setattr(m, '_signal_exact', send)
        assert m.stop_executor(dict(executor_pid=999, executor_pid_start_ticks=1,
                                   executor_boot_id='boot', executor_session_id=999, executor_group_nonce='nonce'), tmp_path, .3) == 'absent'
    assert members == {}


@pytest.mark.parametrize('failure', ['missing_open', 'missing_signal', 'ENOSYS', 'EPERM', 'signal_EPERM'])
def test_bluescrub_pidfd_unavailable_prevents_analyzer_launch(monkeypatch, failure):
    import errno
    launched = []
    closed = []
    def unavailable(*args):
        raise OSError(errno.ENOSYS if failure == 'ENOSYS' else errno.EPERM, 'blocked')
    fake_os = SimpleNamespace(name='posix', getpid=lambda: 1, close=closed.append,
                              pidfd_open=unavailable if failure in ('ENOSYS', 'EPERM') else lambda pid: 77)
    if failure == 'missing_open':
        del fake_os.pidfd_open
    monkeypatch.setattr(runner, 'os', fake_os)
    monkeypatch.setattr(runner, 'signal', SimpleNamespace(**({} if failure == 'missing_signal' else
        {'pidfd_send_signal': unavailable if failure == 'signal_EPERM' else lambda *a: None})))
    monkeypatch.setattr(runner, 'resolve_drop_target', lambda user: (None, None))
    def popen(*args, **kwargs):
        launched.append(True)
        raise AssertionError('analyzer work must not launch')
    monkeypatch.setattr(runner.subprocess, 'Popen', popen)
    try:
        runner.run_analyzer(['analyzer'], require_privilege_drop=False)
    except (RuntimeError, OSError, AttributeError):
        pass
    assert launched == []
    assert closed == ([77] if failure in ('missing_signal', 'signal_EPERM') else [])


def test_reused_intermediate_ancestor_does_not_authorize_new_children(monkeypatch):
    root = dict(identity(pid=42), ppid=1, pgid=42, sid=42)
    # Reused intermediate PID and its child belong to the replacement session,
    # even if an old/stale parent link still appears to point at the executor.
    parent = dict(identity(pid=51, ticks=200), ppid=42, pgid=51, sid=51)
    child = dict(identity(pid=88, ticks=202), ppid=51, pgid=51, sid=51)
    current = {42: root, 51: parent, 88: child}
    class ProcRoot:
        def glob(self, pattern):
            return [SimpleNamespace(parent=SimpleNamespace(name=str(pid))) for pid in current]
    monkeypatch.setattr(runner, 'Path', lambda p: ProcRoot())
    monkeypatch.setattr(runner, 'read_process_identity', current.get)
    assert runner.ProcessSession(root, 'nonce').snapshot() == [root]


def test_unresolved_local_group_retains_receipt(tmp_path, monkeypatch):
    from backend.app.pipeline import sensor_process as m
    monkeypatch.setattr(signal, 'SIGSTOP', 19, raising=False)
    record = tmp_path/'receipt'
    record.touch()
    group = runner.ProcessGroup(identity(), 'nonce')
    monkeypatch.setattr(group, 'snapshot', lambda: [identity()])
    monkeypatch.setattr(runner, 'signal_exact_process', lambda *a: None)
    actual_stop = group.stop
    monkeypatch.setattr(group, 'stop', lambda grace: actual_stop(grace, deadline=time.monotonic()+.02))
    monkeypatch.setattr(runner, 'os', SimpleNamespace(name='posix'))
    proc = SimpleNamespace(pid=202, aipam_group=group, wait=lambda **kw: pytest.fail('unresolved group reaped'))
    child = m.TrackedChild(proc, record)
    with pytest.raises(runner.ProcessCleanupIncomplete):
        child.reap(grace=0)
    assert record.exists() and not child.reaped


def identity(pid=202, ticks=100):
    return dict(pid=pid, pgid=202, sid=202, start_ticks=ticks, boot_id='boot', state='S')


def test_reaped_leader_reuse_never_signals(monkeypatch):
    signals = []
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: identity(ticks=999), raising=False)
    monkeypatch.setattr(runner, 'signal_exact_process', lambda *a: signals.append(a), raising=False)
    group = runner.ProcessGroup(identity(), 'nonce')
    with pytest.raises(runner.ProcessIdentityConflict):
        group.stop(0)
    assert signals == []


def test_shared_bluescrub_reaper_rejects_reused_leader(monkeypatch):
    monkeypatch.setattr(runner, 'os', SimpleNamespace(name='posix'))
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: identity(ticks=999))
    monkeypatch.setattr(runner, 'signal_exact_process', lambda *a: pytest.fail('signaled reused PID'))
    proc = SimpleNamespace(pid=202, aipam_group=runner.ProcessGroup(identity(), 'nonce'),
                           poll=lambda: pytest.fail('reaped before validation'),
                           wait=lambda **kw: pytest.fail('waited for unrelated PID'))
    with pytest.raises(runner.ProcessIdentityConflict):
        runner._kill_group(proc, 0)


def test_live_leader_anchors_dropped_uid_group_without_reading_environ(monkeypatch):
    member = identity(pid=303, ticks=101)
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: identity())
    monkeypatch.setattr(runner, 'group_members', lambda pgid: [member])
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: pytest.fail('cannot read dropped UID environ'))
    assert runner.ProcessGroup(identity(), 'nonce').snapshot() == [member]


def test_reuse_between_term_and_kill_never_signals_replacement(monkeypatch):
    current = [identity()]
    signals = []
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: current[0], raising=False)
    monkeypatch.setattr(runner, 'group_members', lambda pgid: [current[0]], raising=False)
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: 'nonce', raising=False)
    def send(item, sig):
        signals.append((item['start_ticks'], sig))
        current[0] = identity(ticks=999)
    monkeypatch.setattr(runner, 'signal_exact_process', send, raising=False)
    with pytest.raises(runner.ProcessIdentityConflict):
        runner.ProcessGroup(identity(), 'nonce').stop(0)
    assert signals == [(100, signal.SIGTERM)]


@pytest.mark.parametrize('nonce,expected', [('nonce', 'matching'), ('different', 'conflict')])
def test_absent_leader_group_requires_inherited_identity(monkeypatch, nonce, expected):
    member = identity(pid=303, ticks=101)
    monkeypatch.setattr(runner, 'read_process_identity', lambda pid: None, raising=False)
    monkeypatch.setattr(runner, 'group_members', lambda pgid: [member], raising=False)
    monkeypatch.setattr(runner, 'process_group_nonce', lambda pid: nonce, raising=False)
    group = runner.ProcessGroup(identity(), 'nonce')
    if expected == 'conflict':
        with pytest.raises(runner.ProcessIdentityConflict):
            group.snapshot()
    else:
        assert group.snapshot() == [member]


def test_tracked_reaper_uses_launch_identity_without_polling(tmp_path, monkeypatch):
    from backend.app.pipeline import sensor_process
    calls = []
    proc = SimpleNamespace(pid=202, poll=lambda: pytest.fail('poll reaps before identity cleanup'))
    monkeypatch.setattr(sensor_process, '_kill_group', lambda p, grace: calls.append(p))
    sensor_process.TrackedChild(proc, tmp_path/'receipt').reap()
    assert calls == [proc]


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux /proc, pidfd and orphan groups')
def test_absent_executor_and_leader_stubborn_grandchild_is_stopped(tmp_path):
    from backend.app.pipeline import sensor_process
    nonce = 'orphan-regression'
    ready = tmp_path/'ready'
    code = "import os,signal,time,pathlib; p=os.fork(); " \
           "signal.signal(signal.SIGTERM,signal.SIG_IGN); " \
           f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid())) if p==0 else None; " \
           "time.sleep(30) if p==0 else time.sleep(.3)"
    proc = subprocess.Popen([sys.executable, '-c', code], start_new_session=True,
                            env={**os.environ, 'AIPAM_PROCESS_GROUP_NONCE': nonce})
    leader = runner.read_process_identity(proc.pid)
    control = tmp_path/'control'
    control.mkdir()
    (control/'handler-test.json').write_text(json.dumps({**leader, 'group_nonce': nonce}))
    try:
        proc.wait(timeout=5)
        assert ready.exists()
        assert runner.read_process_identity(proc.pid) is None
        result = sensor_process.stop_executor(dict(executor_pid=proc.pid,
            executor_pid_start_ticks=leader['start_ticks'], executor_boot_id=leader['boot_id'],
            executor_session_id=proc.pid, executor_group_nonce=nonce), tmp_path, 5)
        assert result == 'absent'
        live = runner.read_process_identity(int(ready.read_text()))
        assert live is None or live['state'] == 'Z'
    finally:
        runner.ProcessGroup(leader, nonce).stop(0)
        proc.wait(timeout=5)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux BlueScrub process/session boundary')
def test_bluescrub_timeout_cleans_stubborn_group():
    code = '''import os, signal, time
child = os.fork()
if child == 0:
    os.close(1)
    os.close(2)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(30)
else:
    print(child, flush=True)
    time.sleep(30)
'''
    from backend.app.bluescrub.isolation.limits import ResourceLimits
    result = runner.run_analyzer([sys.executable, '-c', code], drop_user=None,
                                 require_privilege_drop=False,
                                 limits=ResourceLimits(wall_clock_seconds=1, grace_seconds=0))
    assert result.status == runner.AnalyzerStatus.timeout
    pid = int(result.stdout.strip())
    deadline = time.monotonic()+3
    while time.monotonic() < deadline:
        live = runner.read_process_identity(pid)
        if live is None or live['state'] == 'Z':
            return
        time.sleep(.02)
    pytest.fail('BlueScrub orphan survived timeout cleanup')
