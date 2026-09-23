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
            executor_pid_start_ticks=leader['start_ticks'], executor_boot_id=leader['boot_id']), tmp_path, 5)
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
