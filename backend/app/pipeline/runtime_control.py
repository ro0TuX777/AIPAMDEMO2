"""Per-execution cooperative channel and independent database heartbeat."""
from __future__ import annotations
from contextvars import ContextVar, Token
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
        self._cleanup_lock = threading.Lock()
        # Active -> stop requested -> cleanup complete. A stop request fences
        # submissions, but only reconciliation grants permission to finalize.
        self.cleanup_complete = False

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
        with self._cleanup_lock:
            if self.cleanup_complete:
                return
            self._stop.set()
            try:
                if self._thread is not None:
                    self._thread.join(timeout=16)
                    if self._thread.is_alive():
                        from backend.app.bluescrub.isolation.runner import ProcessCleanupIncomplete
                        raise ProcessCleanupIncomplete('Heartbeat shutdown incomplete')
                from backend.app.pipeline.sensor_process import reap_run_processes
                reap_run_processes(self.cancel_path.parent.parent)
            finally:
                token = getattr(self, '_context_token', None)
                if token is not None:
                    # Setting the saved value is retryable even if interrupted
                    # before clearing the token; ContextVar.reset is single-use.
                    _current_control.set(None if token.old_value is Token.MISSING else token.old_value)
                    self._context_token = None
            # An interruption anywhere above leaves the whole stop retryable.
            self.cleanup_complete = True

def process_identity(pid: int, proc_root=Path('/proc')):
    """Linux field 22; comm can contain spaces and parentheses."""
    stat = (proc_root / str(pid) / 'stat').read_text()
    fields = stat.rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': int(fields[19]), 'pgid': int(fields[2]),
            'sid': int(fields[3]),
            'boot_id': (proc_root / 'sys/kernel/random/boot_id').read_text().strip()}

def current_executor(worker_node, docker_client):
    import socket
    from uuid import uuid4
    from backend.app.bluescrub.isolation.runner import require_process_control, ProcessCleanupIncomplete
    require_process_control()
    # Celery recycles this pool child after one task. Refuse an inherited or
    # already-established session: only a successful setsid establishes fresh
    # containment owned exclusively by this execution, before pipeline work.
    try:
        os.setsid()
    except (OSError, AttributeError) as exc:
        raise ProcessCleanupIncomplete('Executor containment unavailable') from exc
    identity = process_identity(os.getpid())
    if identity['sid'] != identity['pid'] or identity['pgid'] != identity['pid']:
        raise ProcessCleanupIncomplete('Executor containment unavailable')
    nonce = uuid4().hex
    os.environ['AIPAM_PROCESS_GROUP_NONCE'] = nonce
    container_id = docker_client.containers.get(socket.gethostname()).id
    if len(container_id) != 64 or any(c not in '0123456789abcdef' for c in container_id):
        raise JobOwnershipLost()
    return ExecutorIdentity(worker_node, container_id, identity['pid'], identity['start_ticks'],
                            identity['boot_id'], identity['sid'], nonce)
