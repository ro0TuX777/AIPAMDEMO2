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
from uuid import uuid4

from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost
from backend.app.bluescrub.isolation.runner import (
    _kill_group, ProcessGroup, ProcessIdentityConflict, read_process_identity,
    signal_exact_process,
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
    """Only Popen objects created by this Celery child can be reaped here."""
    root = Path(run_output_dir).resolve()
    from backend.app.pipeline.runtime_control import request_cancel_file
    request_cancel_file(root / 'control' / 'cancel.requested')
    with _children_lock:
        children = [child for child in _children.values() if child.record.parent.parent.resolve() == root]
    for child in children:
        child.reap(grace=0)


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
    record = Path(run_output_dir) / 'control' / f'handler-{name}.json'
    record.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    # Publication and registration are one critical section: a concurrent final
    # reaper cannot remove a receipt before the launching thread writes it.
    with _children_lock:
        context.checkpoint()
        nonce = uuid4().hex
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                env={**(os.environ if env is None else env), 'AIPAM_PROCESS_GROUP_NONCE': nonce},
                                start_new_session=os.name != 'nt',
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
        child = TrackedChild(proc, record)
        try:
            if os.name == 'nt':
                identity = {'pid': proc.pid, 'pgid': proc.pid, 'start_ticks': None, 'boot_id': None}
            else:
                identity = read_process_identity(proc.pid)
                proc.aipam_group = ProcessGroup(identity, nonce)
            atomic_json(record, {**identity, 'handler': name, 'group_nonce': nonce})
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


def _descendants(pid):
    parents = {}
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            item = read_process_identity(int(path.parent.name))
            if item:
                parents[item['pid']] = item
        except (OSError, ValueError, IndexError):
            continue
    result = []
    def walk(parent):
        for child, item in parents.items():
            if item['ppid'] == parent:
                walk(child)
                result.append(item)
    walk(pid)
    return result


def _signal_exact(identity, sig):
    signal_exact_process(identity, sig)


def stop_executor(identity, run_dir, seconds, deadline=None):
    """Runs inside the recorded worker namespace. Conflict means signal nothing."""
    deadline = min(time.monotonic() + max(0, seconds), deadline if deadline is not None else float("inf"))
    expected = {'pid': identity['executor_pid'], 'start_ticks': identity['executor_pid_start_ticks'],
                'boot_id': identity['executor_boot_id']}
    verdict = classify_identity(expected, read_identity(expected['pid']))
    if verdict == 'conflict':
        return verdict
    groups = []
    for path in Path(run_dir).joinpath('control').glob('handler-*.json'):
        item = json.loads(path.read_text())
        if item['pgid'] != item['pid']:
            return 'conflict'
        groups.append(ProcessGroup(item, item.get('group_nonce')))
    try:
        tracked = [item for group in groups for item in group.snapshot()]
    except ProcessIdentityConflict:
        return 'conflict'
    children = _descendants(expected['pid']) if verdict == 'matching' else []
    for item in tracked:
        children.extend(_descendants(item['pid']))
    children = list({item['pid']: item for item in children}.values())
    if time.monotonic() >= deadline:
        return "unavailable"
    targets = list({i['pid']: i for i in [*children, *tracked]}.values())
    if verdict == 'matching':
        targets.append(expected)
    try:
        for item in targets:
            _signal_exact(item, signal.SIGTERM)
    except ProcessIdentityConflict:
        return 'conflict'
    end_grace = min(max(time.monotonic(), deadline-.5), time.monotonic()+3)
    while time.monotonic() < end_grace:
        if not any(read_identity(i['pid']) for i in [*children, *tracked, expected]):
            break
        time.sleep(.05)
    try:
        if verdict == 'matching':
            current = classify_identity(expected, read_identity(expected['pid']))
            if current == 'conflict':
                return 'conflict'
            if current == 'matching':
                targets.extend(_descendants(expected['pid']))
        for group in groups:
            targets.extend(group.snapshot())
        for item in {i['pid']: i for i in targets}.values():
            _signal_exact(item, signal.SIGKILL)
    except ProcessIdentityConflict:
        return 'conflict'
    # Reaping direct children belongs to their parent/Celery pool; only report
    # stopped once /proc reports absence or zombie (no further writes possible).
    for item in targets:
        while time.monotonic() < deadline:
            live = read_identity(item['pid'])
            if live is None:
                break
            if classify_identity(item, live) == 'conflict':
                return 'conflict'
            try:
                state = Path(f"/proc/{item['pid']}/stat").read_text().rsplit(')', 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == 'Z':
                break
            time.sleep(.02)
        else:
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
        # Parent publishes identity before allowing handler Python to start.
        record = Path(payload['run_output_dir'])/'control'/f'handler-{name}.json'
        deadline = time.monotonic()+10
        while not record.exists():
            context.checkpoint()
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
