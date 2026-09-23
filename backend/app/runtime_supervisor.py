"""Independent reconciliation and deadline-driven cancellation; database time wins."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import json
import logging
from pathlib import Path
import subprocess
import sys
import threading
import time
from uuid import uuid4

from sqlalchemy import select, update, func
from backend.app.models.job import Job
from backend.app.services import job_runtime as runtime
from backend.app.pipeline.runtime_control import request_cancel_file
from backend.app.pipeline.run_artifacts import safe_artifact_path

logger = logging.getLogger(__name__)
HEARTBEAT_PATH = Path('/tmp/aipam-runtime-supervisor.heartbeat')


def healthy(path=HEARTBEAT_PATH, *, now=None):
    try:
        return (time.time() if now is None else now) - path.stat().st_mtime <= 45
    except OSError:
        return False


class DeadlineBudget:
    """Monotonic countdown anchored to a fresh SQLite deadline delta."""
    def __init__(self, seconds, clock=time.monotonic):
        self.clock = clock
        self.end = clock() + max(0, seconds)

    def remaining(self):
        return max(0, self.end - self.clock())


class DockerTransport:
    def _call(self, operation, payload, budget):
        seconds = budget.remaining()
        if seconds <= 0:
            raise TimeoutError()
        result = subprocess.run(
            [sys.executable, '-m', 'backend.app.runtime_supervisor', '--docker-operation',
             json.dumps({'operation': operation, 'payload': payload, 'seconds': seconds, 'deadline': budget.end})],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=seconds, check=True,
        )
        return json.loads(result.stdout)

    def stop_executor(self, identity, run_dir, budget):
        if identity is None:
            # Registration is mandatory before any handler/write and escalation
            # prevents late registration. No recorded executor can still start.
            return 'absent'
        return self._call('stop', {'identity': asdict(identity), 'run_dir': str(run_dir)}, budget)

    def cleanup_containers(self, handle, budget):
        self._call('cleanup', asdict(handle), budget)


def docker_operation(operation, payload, seconds, deadline=None):
    """Disposable transport subprocess: even a stuck Docker stream is bounded."""
    import docker
    budget = DeadlineBudget(seconds if deadline is None else min(seconds, max(0, deadline-time.monotonic())))
    client = docker.from_env(timeout=max(.1, min(3, seconds)))
    try:
        if operation == 'stop':
            identity = payload['identity']
            container_id = identity['worker_container_id']
            if len(container_id) != 64:
                return 'conflict'
            try:
                container = client.containers.get(container_id)
            except docker.errors.NotFound:
                return 'absent'
            if container.id != container_id:
                return 'conflict'
            if container.status != 'running':
                return 'absent'
            result = container.exec_run([
                sys.executable, '-m', 'backend.app.pipeline.sensor_process', '--stop-executor',
                json.dumps({**payload, 'seconds': budget.remaining(), 'deadline': budget.end}),
            ])
            if result.exit_code != 0:
                return 'unavailable'
            verdict = result.output.decode().strip()
            return verdict if verdict in ('matching', 'absent', 'conflict') else 'unavailable'
        labels = {f'aipam.{key}': payload[value] for key, value in (
            ('job_id', 'job_id'), ('run_token', 'run_token'), ('celery_task_id', 'task_id'))}
        containers = client.containers.list(all=True, filters={'label': [f'{k}={v}' for k,v in labels.items()]})
        for container in containers:
            if not all(container.labels.get(k) == v for k, v in labels.items()):
                continue
            if budget.remaining() <= 0:
                raise TimeoutError()
            try:
                container.kill(signal='SIGTERM')
                # Bounded wait, then force/remove. Outer process owns final timeout.
                try:
                    container.wait(timeout=min(3, budget.remaining()))
                except Exception:
                    container.kill(signal='SIGKILL')
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
        return 'cleaned'
    finally:
        client.close()


def emit_terminal_bounded(job_id, status):
    """Best-effort diagnostic publication must not consume the final DB reserve."""
    try:
        subprocess.run([sys.executable, '-m', 'backend.app.runtime_supervisor',
                        '--terminal-event', json.dumps([job_id, status])],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=1.5, check=True)
    except Exception:
        logger.warning("Terminal event publication unavailable for %s", job_id)


class RuntimeSupervisor:
    def __init__(self, factory, job_root, *, transport=None, emit=None, reconcile_seconds=15,
                 cancel_poll_seconds=2, stale_seconds=120, undispatched_grace_seconds=30):
        self.factory, self.job_root = factory, Path(job_root)
        self.transport = transport or DockerTransport()
        self.emit = emit or emit_terminal_bounded
        self.reconcile_seconds, self.cancel_poll_seconds = reconcile_seconds, cancel_poll_seconds
        self.stale_seconds, self.undispatched_grace_seconds = stale_seconds, undispatched_grace_seconds

    def owns_cancel(self, handle, token):
        with self.factory() as db:
            return db.scalar(select(Job.job_id).where(*runtime._owned(handle),
                Job.status == 'canceling', Job.cancel_escalation_token == token)) is not None

    def cancel_once(self):
        with self.factory() as db:
            rows = db.execute(select(Job.job_id, Job.run_token).where(Job.status == 'canceling')).all()
        for job_id, run_token in rows:
            if not run_token:
                continue
            run_dir = safe_artifact_path(self.job_root, f'{job_id}/.runs/{run_token}')
            request_cancel_file(run_dir/'control'/'cancel.requested')
            token = str(uuid4())
            with self.factory() as db:
                db.connection().exec_driver_sql("PRAGMA busy_timeout=500")
                claim = runtime.claim_cancel_escalation(db, job_id, token, lease_seconds=5)
                if not claim.claimed:
                    continue
                seconds = db.scalar(select((func.julianday(claim.cancel_deadline_at)-func.julianday(runtime._now()))*86400))
            budget = DeadlineBudget(max(0, seconds - 3))  # final CAS/event reserve
            if not self.owns_cancel(claim.handle, token):
                continue
            try:
                verdict = self.transport.stop_executor(claim.identity, run_dir,
                                                       DeadlineBudget(min(7, budget.remaining())))
                if verdict not in ('matching', 'absent'):
                    self._escalation_error(claim.handle, token, verdict)
                    continue
                if not self.owns_cancel(claim.handle, token):
                    continue
                self.transport.cleanup_containers(claim.handle, budget)
                with self.factory() as db:
                    db.connection().exec_driver_sql("PRAGMA busy_timeout=1000")
                    won = runtime.complete_cancel_escalation(db, claim.handle, token)
                if won:
                    self.emit(job_id, 'canceled')
            except Exception:
                self._escalation_error(claim.handle, token, 'unavailable')

    def _escalation_error(self, handle, token, verdict):
        error = 'CANCEL_EXECUTOR_IDENTITY_CONFLICT' if verdict == 'conflict' else 'CANCEL_ESCALATION_UNAVAILABLE'
        with self.factory() as db:
            db.connection().exec_driver_sql("PRAGMA busy_timeout=500")
            db.execute(update(Job).where(*runtime._owned(handle), Job.status == 'canceling',
                Job.cancel_escalation_token == token).values(error_summary=error))
            db.commit()
        logger.error('%s for job %s; operator action required', error, handle.job_id)

    def reconcile_once(self, *, heartbeat_path=HEARTBEAT_PATH):
        with self.factory() as db:
            stats = runtime.reconcile_stale_jobs(db, stale_seconds=self.stale_seconds,
                                                 undispatched_grace_seconds=self.undispatched_grace_seconds,
                                                 emit=self.emit)
        self.reap_stale_runs()
        heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
        heartbeat_path.touch()
        return stats

    def reap_stale_runs(self):
        pass_budget = DeadlineBudget(12)
        # Runtime reconciliation fences writes first. Private identity receipts
        # allow cleanup to retry after supervisor loss without retaining executor
        # columns in terminal lifecycle rows.
        with self.factory() as db:
            rows = db.execute(select(Job.job_id, Job.run_token).where(
                Job.status == "failed", Job.error_summary == "Worker heartbeat expired",
                Job.run_token.is_not(None))).all()
        for job_id, run_token in rows:
            if pass_budget.remaining() <= 0:
                break
            run_dir = safe_artifact_path(self.job_root, f"{job_id}/.runs/{run_token}")
            receipt = safe_artifact_path(run_dir, "control/executor.json")
            if not receipt.is_file():
                continue
            try:
                payload = json.loads(receipt.read_text())
                handle = runtime.RunHandle(**payload["handle"])
                identity = runtime.ExecutorIdentity(**payload["identity"])
                if (handle.job_id, handle.run_token) != (job_id, run_token):
                    continue
                with self.factory() as db:
                    if db.scalar(select(Job.job_id).where(*runtime._owned(handle),
                        Job.status == "failed", Job.error_summary == "Worker heartbeat expired")) is None:
                        continue
                budget = pass_budget
                verdict = self.transport.stop_executor(identity, run_dir, DeadlineBudget(min(7, budget.remaining())))
                if verdict not in ("matching", "absent"):
                    logger.error("Stale executor cleanup requires operator action for %s", job_id)
                    continue
                self.transport.cleanup_containers(handle, budget)
                from types import SimpleNamespace
                from backend.app.worker import _cleanup_private_run
                with self.factory() as db:
                    _cleanup_private_run(SimpleNamespace(aipam_job_root=self.job_root), handle, db.get(Job, job_id))
            except Exception:
                logger.error("Stale executor cleanup deferred for %s", job_id)

    def run(self):
        stop = threading.Event()
        def cancel_loop():
            while not stop.is_set():
                started = time.monotonic()
                try:
                    self.cancel_once()
                except Exception:
                    logger.error('Cancellation scan unavailable')
                stop.wait(max(0, self.cancel_poll_seconds - (time.monotonic() - started)))
        thread = threading.Thread(target=cancel_loop, daemon=True)
        thread.start()
        try:
            while True:
                started = time.monotonic()
                try:
                    self.reconcile_once()
                except Exception:
                    logger.error('Runtime reconciliation unavailable')
                stop.wait(max(0, self.reconcile_seconds - (time.monotonic() - started)))
        finally:
            stop.set()
            thread.join(timeout=15)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--health', action='store_true')
    parser.add_argument('--docker-operation')
    parser.add_argument('--terminal-event')
    args = parser.parse_args()
    if args.health:
        return 0 if healthy() else 1
    if args.terminal_event:
        from backend.app.worker import _emit_complete
        _emit_complete(*json.loads(args.terminal_event))
        return 0
    if args.docker_operation:
        print(json.dumps(docker_operation(**json.loads(args.docker_operation))))
        return 0
    from backend.app.config_v2 import get_settings
    from backend.app.database_v2 import get_session_factory
    settings = get_settings()
    RuntimeSupervisor(get_session_factory(), settings.aipam_job_root,
                      reconcile_seconds=settings.aipam_reconcile_seconds,
                      cancel_poll_seconds=settings.aipam_cancel_poll_seconds,
                      stale_seconds=settings.aipam_stale_seconds,
                      undispatched_grace_seconds=settings.aipam_undispatched_grace_seconds).run()


if __name__ == '__main__':
    raise SystemExit(main())
