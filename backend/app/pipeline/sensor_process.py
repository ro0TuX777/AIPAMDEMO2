"""Mandatory, killable registry handler boundary. No database writes here."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import threading

from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost
from backend.app.bluescrub.isolation.runner import (
    _kill_group, ProcessIdentityConflict, read_process_identity,
    signal_exact_process, same_process, drain_processes, ProcessCleanupIncomplete,
    require_process_control,
)
from backend.app.bluescrub.isolation.limits import build_env
from backend.app.pipeline.runtime_control import (
    SensorExecutionContext, JobCancellationRequested, JobOwnershipLost,
    atomic_json, process_identity, _current_control,
)


_children = {}
_children_lock = threading.Lock()


class TrackedChild:
    def __init__(self, proc, record):
        self.proc, self.record = proc, record
        self.lock = threading.Lock()
        self.reaped = False

    def reap(self, grace=3):
        with self.lock:
            if self.reaped:
                return
            _kill_group(self.proc, grace)
            self.record.unlink(missing_ok=True)
            self.reaped = True
        with _children_lock:
            _children.pop(self.proc.pid, None)


def reap_run_processes(run_output_dir):
    """Reap local children, then prove receipt-bearing session quiescence."""
    root = Path(run_output_dir).resolve()
    from backend.app.pipeline.runtime_control import request_cancel_file
    request_cancel_file(root / 'control' / 'cancel.requested')
    with _children_lock:
        children = [child for child in _children.values() if child.record.parent.parent.resolve() == root]
    for child in children:
        child.reap(grace=0)
    from backend.app.bluescrub.isolation.runner import ProcessSession
    for record in (root/'control').glob('handler-*.json'):
        try:
            item = json.loads(record.read_text())
        except FileNotFoundError:
            continue
        if item.get('state') == 'launching':
            raise ProcessCleanupIncomplete('Process launch receipt pending')
        if (os.name == 'nt' or item.get('pid') != item.get('pgid')
                or item.get('pid') != item.get('sid') or not item.get('group_nonce')):
            raise ProcessCleanupIncomplete('Process containment unavailable')
        ProcessSession(item, item['group_nonce']).stop(0)
        record.unlink(missing_ok=True)


def classify_identity(expected, live):
    if live is None:
        return 'absent'
    return 'matching' if all(expected[k] == live[k] for k in ('pid', 'start_ticks', 'boot_id')) else 'conflict'


def read_identity(pid):
    try:
        return process_identity(pid)
    except FileNotFoundError:
        return None


def run_tracked_process(argv, *, run_output_dir, name, timeout_seconds, context, env=None):
    context.checkpoint()
    require_process_control()
    record = Path(run_output_dir) / 'control' / f'handler-{name}.json'
    record.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    # Publication and registration are one critical section: a concurrent final
    # reaper cannot remove a receipt before the launching thread writes it.
    with _children_lock:
        context.checkpoint()
        from backend.app.bluescrub.isolation.launch import launch_process
        proc = launch_process(argv, record=record, name=name, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=os.environ if env is None else env)
        child = TrackedChild(proc, record)
        try:
            _children[proc.pid] = child
        except BaseException:
            _kill_group(proc, 0)
            record.unlink(missing_ok=True)
            raise
    try:
        while proc.poll() is None:
            context.checkpoint()
            if time.monotonic() - start >= timeout_seconds:
                raise subprocess.TimeoutExpired(argv, timeout_seconds)
            try:
                proc.wait(timeout=min(.2, max(.01, timeout_seconds - (time.monotonic()-start))))
            except subprocess.TimeoutExpired:
                pass
        context.checkpoint()
        if proc.returncode == 71:
            raise JobCancellationRequested()
        if proc.returncode == 72:
            raise JobOwnershipLost()
        if proc.returncode == 73:
            from sqlalchemy.exc import SQLAlchemyError
            raise SQLAlchemyError('Handler database operation failed')
        if proc.returncode:
            raise RuntimeError('Handler process failed')
    finally:
        # The leader can exit while descendants survive. Always reap the group.
        child.reap()


def run_handler_process(sensor_def, *, input_root, run_output_dir, sensor_output_dir,
                        job_id, execution_profile, cancel_path, control=None):
    if sensor_def.name not in ('zeek', 'suricata', 'tls_enrich', 'beaconing', 'file_triage', 'capa', 'ti_matcher'):
        raise ValueError('Unknown registry handler')
    request = Path(run_output_dir) / 'control' / f'request-{sensor_def.name}.json'
    atomic_json(request, dict(name=sensor_def.name, input_root=str(Path(input_root).resolve()),
                             run_output_dir=str(Path(run_output_dir).resolve()),
                             sensor_output_dir=str(Path(sensor_output_dir).resolve()), job_id=job_id,
                             execution_profile=execution_profile, cancel_path=str(Path(cancel_path).resolve())))
    # Pass only non-secret sensor configuration; never worker credentials.
    extra = {k: v for k, v in os.environ.items() if k in (
        'AIPAM_SURICATA_RULES_DIR', 'AIPAM_YARA_RULES_DIR', 'AIPAM_TI_BUNDLE_DIR',
        'AIPAM_CAPA_RULES_DIR', 'AIPAM_CAPA_SIGNATURES_DIR',
        'AIPAM_SENSOR_CONFIG_DIR', 'SYSTEMROOT', 'WINDIR', 'PYTHONPATH',
    )}
    run_tracked_process([sys.executable, '-m', __name__, '--request', str(request.resolve())],
                        run_output_dir=run_output_dir, name=sensor_def.name,
                        timeout_seconds=sensor_def.timeout_seconds,
                        context=control or SensorExecutionContext(Path(cancel_path)), env=build_env(extra))


def _signal_exact(identity, sig):
    signal_exact_process(identity, sig)


def stop_executor(identity, run_dir, seconds, deadline=None):
    """Drain launch-time containment; parent links are never completion proof."""
    from backend.app.bluescrub.isolation.runner import ProcessSession
    deadline = min(time.monotonic() + max(0, seconds), deadline if deadline is not None else float("inf"))
    expected = {'pid': identity['executor_pid'], 'start_ticks': identity['executor_pid_start_ticks'],
                'boot_id': identity['executor_boot_id']}
    verdict = classify_identity(expected, read_identity(expected['pid']))
    if verdict == 'conflict':
        return verdict
    sid, nonce = identity.get('executor_session_id'), identity.get('executor_group_nonce')
    # Historical rows/receipts have no containment proof. Empty ancestry is
    # never sufficient, including when the historical executor has disappeared.
    if sid is None or not nonce:
        return 'unavailable'
    if sid != expected['pid']:
        return 'conflict'
    control_dir = Path(run_dir)/'control'
    if (control_dir/'ancestry.freeze.pending').exists():
        return 'unavailable'
    expected.update(pgid=sid, sid=sid)
    executor = ProcessSession(expected, nonce)
    groups = {}

    def snapshot():
        # Rescan durable launch intents on every pass: a child may publish a
        # new boundary while its parent is being stopped. Pending intent means
        # a potential escaping child whose identity is not yet known.
        result = executor.snapshot()
        for path in control_dir.glob('handler-*.json'):
            try:
                item = json.loads(path.read_text())
            except FileNotFoundError:
                continue  # Local reaper removes a receipt only after quiescence.
            if item.get('state') == 'launching':
                raise ProcessCleanupIncomplete('Process launch receipt pending')
            if item['pgid'] != item['pid'] or item.get('sid') != item['pid'] or not item.get('group_nonce'):
                raise ProcessIdentityConflict('Invalid process boundary')
            key = (str(path), item['pid'], item['start_ticks'], item['boot_id'], item['group_nonce'])
            if key not in groups:
                groups[key] = ProcessSession(item, item['group_nonce'])
        for group in groups.values():
            result.extend(group.snapshot())
        members = {item['pid']: item for item in result}
        def depth(item):
            # Parent links order already-authorized members only. They never
            # discover members or grant signal/containment authority.
            count, seen = 0, {item['pid']}
            parent = item.get('ppid')
            while parent in members and parent not in seen:
                count += 1
                seen.add(parent)
                parent = members[parent].get('ppid')
            return count
        return sorted(members.values(),
                      key=lambda item: (item['pid'] != expected['pid'], depth(item)), reverse=True)

    try:
        # Stop the exact root before discovery. Its running descendants may
        # fork/reap in this interval; session membership still contains them.
        if verdict == 'matching':
            _signal_exact(expected, signal.SIGSTOP)
        targets = snapshot()
        for item in targets:
            _signal_exact(item, signal.SIGTERM)
        end_grace = min(max(time.monotonic(), deadline-.5), time.monotonic()+3)
        while time.monotonic() < end_grace and snapshot():
            time.sleep(min(.05, max(0, end_grace-time.monotonic())))
        drain_processes(snapshot, deadline, send=_signal_exact)
    except ProcessIdentityConflict:
        return 'conflict'
    except (ProcessCleanupIncomplete, OSError, AttributeError, ValueError, KeyError):
        return 'unavailable'
    return verdict


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request')
    parser.add_argument('--stop-executor')
    args = parser.parse_args()
    if args.stop_executor:
        payload = json.loads(args.stop_executor)
        print(stop_executor(**payload))
        return 0
    payload = json.loads(Path(args.request).read_text())
    name = payload.pop('name')
    context = SensorExecutionContext(Path(payload.pop('cancel_path')))
    _current_control.set(context)
    try:
        context.checkpoint()
        # A stale filename or another process's receipt is never permission to
        # execute a handler. The bootstrap published this exact session first.
        record = Path(payload['run_output_dir'])/'control'/f'handler-{name}.json'
        deadline = time.monotonic()+10
        while True:
            context.checkpoint()
            try:
                item = json.loads(record.read_text())
            except FileNotFoundError:
                item = {'state': 'launching'}
            if item.get('state') != 'launching':
                if (item.get('pid') != os.getpid()
                        or item.get('group_nonce') != os.environ.get('AIPAM_PROCESS_GROUP_NONCE')):
                    return 1
                if os.name != 'nt':
                    live = read_process_identity(os.getpid())
                    if (not same_process(item, live) or live['sid'] != live['pid']
                            or live['pgid'] != live['pid']):
                        return 1
                break
            if time.monotonic() > deadline:
                return 1
            time.sleep(.02)
        from backend.app.sensors.registry import SENSORS
        for key in ('input_root', 'run_output_dir', 'sensor_output_dir'):
            payload[key] = Path(payload[key])
        SENSORS[name].handler(**payload)
        context.checkpoint()
        return 0
    except PipelineCanceled:
        return 71
    except OwnershipLost:
        return 72
    except Exception as exc:
        from sqlalchemy.exc import SQLAlchemyError
        return 73 if isinstance(exc, SQLAlchemyError) else 1


if __name__ == '__main__':
    raise SystemExit(main())
