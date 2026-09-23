"""Per-execution cooperative channel and independent database heartbeat."""
from __future__ import annotations
from contextvars import ContextVar
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import threading
from sqlalchemy.exc import OperationalError
from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost
from backend.app.services.job_runtime import ExecutorIdentity, heartbeat_job, HeartbeatDisposition

logger = logging.getLogger(__name__)

class JobCancellationRequested(PipelineCanceled):
    pass

class JobOwnershipLost(OwnershipLost):
    pass

def atomic_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f'.{os.getpid()}.{threading.get_ident()}.tmp')
    temporary.write_text(json.dumps(data), encoding='utf-8')
    temporary.replace(path)

def request_cancel_file(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    os.close(descriptor)

@dataclass
class SensorExecutionContext:
    cancel_path: Path

    def checkpoint(self):
        if self.cancel_path.exists():
            raise JobCancellationRequested()

_current_control = ContextVar('execution_control', default=None)

def checkpoint():
    control = _current_control.get()
    if control is not None:
        control.checkpoint()


def checked_iter(values):
    """Check before advancing a parser/file iterator as well as after each item."""
    iterator = iter(values)
    while True:
        checkpoint()
        try:
            value = next(iterator)
        except StopIteration:
            return
        checkpoint()
        yield value

class ExecutionControl(SensorExecutionContext):
    def __init__(self, handle, run_output_dir, factory, *, heartbeat_seconds=15):
        super().__init__(Path(run_output_dir) / 'control' / 'cancel.requested')
        self.handle, self.factory = handle, factory
        self.heartbeat_seconds = heartbeat_seconds
        self._stop, self._lost = threading.Event(), threading.Event()
        self._thread = None

    def heartbeat_once(self):
        try:
            with self.factory() as db:
                disposition = heartbeat_job(db, self.handle)
        except OperationalError:
            logger.warning('Runtime heartbeat deferred for %s', self.handle.job_id)
            return False
        if disposition == HeartbeatDisposition.cancel_requested:
            request_cancel_file(self.cancel_path)
        elif disposition == HeartbeatDisposition.lost:
            self._lost.set()
            request_cancel_file(self.cancel_path)
        return True

    def checkpoint(self):
        if self._lost.is_set() or self._stop.is_set():
            raise JobOwnershipLost()
        super().checkpoint()

    def start(self):
        self.heartbeat_once()
        self._context_token = _current_control.set(self)
        def beat():
            while not self._stop.wait(self.heartbeat_seconds):
                try:
                    self.heartbeat_once()
                except Exception:
                    logger.warning('Runtime heartbeat unavailable for %s', self.handle.job_id)
        self._thread = threading.Thread(target=beat, name='job-heartbeat', daemon=True)
        self._thread.start()
        self.checkpoint()
        return self

    def stop(self):
        if self._stop.is_set():
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=16)
        from backend.app.pipeline.sensor_process import reap_run_processes
        reap_run_processes(self.cancel_path.parent.parent)
        if getattr(self, '_context_token', None) is not None:
            _current_control.reset(self._context_token)
            self._context_token = None

def process_identity(pid: int, proc_root=Path('/proc')):
    """Linux field 22; comm can contain spaces and parentheses."""
    stat = (proc_root / str(pid) / 'stat').read_text()
    fields = stat.rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': int(fields[19]), 'pgid': int(fields[2]),
            'boot_id': (proc_root / 'sys/kernel/random/boot_id').read_text().strip()}

def current_executor(worker_node, docker_client):
    import socket
    identity = process_identity(os.getpid())
    container_id = docker_client.containers.get(socket.gethostname()).id
    if len(container_id) != 64 or any(c not in '0123456789abcdef' for c in container_id):
        raise JobOwnershipLost()
    return ExecutorIdentity(worker_node, container_id, identity['pid'], identity['start_ticks'], identity['boot_id'])
