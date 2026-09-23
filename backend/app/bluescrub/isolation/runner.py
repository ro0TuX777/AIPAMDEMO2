"""Hardened subprocess runner for vendored Python analyzers.

A ``ThreadPoolExecutor`` timeout is a scheduling hint, not a security control:
a thread spinning in a catastrophic regex cannot be interrupted, and it holds
the worker while it burns. Every analyzer therefore runs as a detached child
process with resource limits, dropped privileges, and a scrubbed environment,
and is killed by process group so its children die with it.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from uuid import uuid4

from backend.app.bluescrub.isolation.limits import ResourceLimits, build_env, build_preexec

logger = logging.getLogger(__name__)


class AnalyzerStatus(str, Enum):
    """Terminal outcomes. A scanner failure degrades a pillar; it never fails the job."""

    completed = "completed"
    completed_truncated = "completed_truncated"
    timeout = "timeout"
    oom = "oom"
    crashed = "crashed"
    unparseable = "unparseable"
    unavailable = "unavailable"
    skipped = "skipped"


@dataclass
class AnalyzerResult:
    status: AnalyzerStatus
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int | None = None
    signal_number: int | None = None
    duration_ms: int = 0
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in (AnalyzerStatus.completed, AnalyzerStatus.completed_truncated)


class PrivilegeDropUnavailable(RuntimeError):
    """Raised when privilege drop is required but cannot be performed."""


def resolve_drop_target(user: str | None) -> tuple[int | None, int | None]:
    """Resolve the unprivileged uid/gid to drop to, or (None, None)."""
    if not user:
        return None, None
    import pwd

    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return None, None
    return entry.pw_uid, entry.pw_gid


def run_analyzer(
    argv: list[str],
    *,
    cwd: Path | None = None,
    limits: ResourceLimits | None = None,
    env_extra: dict[str, str] | None = None,
    drop_user: str | None = "bluescrub",
    require_privilege_drop: bool = True,
    stdin_data: bytes | None = None,
) -> AnalyzerResult:
    """Run one analyzer to completion inside a process boundary.

    Args:
        argv: Command and arguments. Never passed through a shell.
        cwd: Working directory; the analyzer receives no write access to it.
        limits: Resource ceilings. Defaults to the parse-only profile.
        env_extra: Additional environment on top of the allowlist.
        drop_user: Unprivileged account to drop to.
        require_privilege_drop: When True and the drop cannot be performed,
            refuse to run rather than executing with worker privileges. Tests
            and local development pass False explicitly.

    Raises:
        PrivilegeDropUnavailable: drop required but not possible.
    """
    limits = limits or ResourceLimits()
    uid, gid = resolve_drop_target(drop_user)

    if uid is None and require_privilege_drop:
        raise PrivilegeDropUnavailable(
            f"user {drop_user!r} not found; refusing to run an analyzer with worker privileges"
        )
    if uid is not None and os.geteuid() != 0:
        if require_privilege_drop:
            raise PrivilegeDropUnavailable(
                "worker is not root; cannot drop privileges, refusing to run"
            )
        uid, gid = None, None

    if uid is None:
        logger.warning(
            "Analyzer %s running without privilege drop — development mode only", argv[0]
        )

    started = time.monotonic()
    killed_by_us = False

    require_process_control()
    group_nonce = uuid4().hex
    record = None
    try:
        options = dict(cwd=str(cwd) if cwd else None,
                       stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        child_env = build_env({**(env_extra or {}), 'AIPAM_PROCESS_GROUP_NONCE': group_nonce})
        if os.environ.get('AIPAM_RUN_CONTROL_DIR'):
            from backend.app.bluescrub.isolation.launch import launch_process
            record = Path(os.environ['AIPAM_RUN_CONTROL_DIR'])/f'handler-analyzer-{group_nonce}.json'
            proc = launch_process(argv, record=record, name='bluescrub', env=child_env,
                                  limits=limits, uid=uid, gid=gid, **options)
        else:
            proc = subprocess.Popen(argv, env=child_env,
                                    preexec_fn=build_preexec(limits, uid, gid), **options)
    except FileNotFoundError:
        return AnalyzerResult(
            status=AnalyzerStatus.unavailable,
            reason=f"executable not found: {argv[0]}",
        )
    except OSError as exc:
        return AnalyzerResult(status=AnalyzerStatus.crashed, reason=str(exc))

    if record is None:
        proc.aipam_group = ProcessSession(read_process_identity(proc.pid), group_nonce)
    try:
        stdout, stderr = proc.communicate(input=stdin_data, timeout=limits.wall_clock_seconds)
    except subprocess.TimeoutExpired:
        killed_by_us = True
        _kill_group(proc, limits.grace_seconds)
        stdout, stderr = proc.communicate()
    finally:
        if record is not None:
            _kill_group(proc, 0)
            record.unlink(missing_ok=True)
        duration_ms = int((time.monotonic() - started) * 1000)

    truncated = False
    if len(stdout) > limits.max_stdout_bytes:
        stdout = stdout[: limits.max_stdout_bytes]
        truncated = True

    if killed_by_us:
        return AnalyzerResult(
            status=AnalyzerStatus.timeout, stdout=stdout, stderr=stderr[-4096:],
            duration_ms=duration_ms,
            reason=f"wall clock exceeded {limits.wall_clock_seconds}s",
        )

    rc = proc.returncode
    if rc is not None and rc < 0:
        sig = -rc
        # SIGXCPU is RLIMIT_CPU; SIGKILL we did not send is almost always the
        # OOM killer or RLIMIT_AS turning an allocation into a fatal failure.
        if sig == signal.SIGXCPU:
            status, reason = AnalyzerStatus.timeout, "cpu limit exceeded"
        elif sig == signal.SIGKILL:
            status, reason = AnalyzerStatus.oom, "killed (memory limit or OOM)"
        else:
            status, reason = AnalyzerStatus.crashed, f"died on signal {sig}"
        return AnalyzerResult(
            status=status, stdout=stdout, stderr=stderr[-4096:], signal_number=sig,
            duration_ms=duration_ms, reason=reason,
        )

    if rc != 0:
        return AnalyzerResult(
            status=AnalyzerStatus.crashed, stdout=stdout, stderr=stderr[-4096:],
            exit_code=rc, duration_ms=duration_ms, reason=f"exit {rc}",
        )

    return AnalyzerResult(
        status=AnalyzerStatus.completed_truncated if truncated else AnalyzerStatus.completed,
        stdout=stdout, stderr=stderr[-4096:], exit_code=0, duration_ms=duration_ms,
        reason="stdout truncated at cap" if truncated else None,
    )


class ProcessIdentityConflict(RuntimeError):
    """A numeric PID/group no longer identifies the launched execution."""


class ProcessCleanupIncomplete(RuntimeError):
    """Writers remain or their quiescence could not be proved before deadline."""


def require_process_control():
    """Refuse Linux work before launch if pinned signalling is unavailable."""
    if os.name == 'nt':
        return  # Popen retains the Windows kernel process handle.
    try:
        fd = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(fd, 0)
        finally:
            os.close(fd)
    except (AttributeError, OSError) as exc:
        raise ProcessCleanupIncomplete('Pinned process control is unavailable') from exc


def read_process_identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return dict(pid=pid, state=fields[0], ppid=int(fields[1]), pgid=int(fields[2]), sid=int(fields[3]),
                    start_ticks=int(fields[19]),
                    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    except FileNotFoundError:
        return None


def same_process(expected, live):
    return live is not None and all(expected[k] == live[k] for k in ('pid', 'start_ticks', 'boot_id'))


def group_members(pgid):
    members = []
    for path in Path('/proc').glob('[0-9]*/stat'):
        item = read_process_identity(int(path.parent.name))
        if item and item['pgid'] == pgid and item['state'] != 'Z':
            members.append(item)
    return members


def session_members(sid):
    """Session membership survives double-fork/reparent and setpgid changes."""
    members = []
    for path in Path('/proc').glob('[0-9]*/stat'):
        item = read_process_identity(int(path.parent.name))
        if item and item['sid'] == sid and item['state'] != 'Z':
            members.append(item)
    return members


def process_group_nonce(pid):
    try:
        values = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
    except FileNotFoundError:
        return None
    prefix = b'AIPAM_PROCESS_GROUP_NONCE='
    return next((v[len(prefix):].decode() for v in values if v.startswith(prefix)), None)


def signal_exact_process(expected, sig):
    """Pin the kernel task before checking /proc; never signal by numeric PID."""
    try:
        fd = os.pidfd_open(expected['pid'])
    except ProcessLookupError:
        return
    try:
        live = read_process_identity(expected['pid'])
        if live is None:
            return
        if not same_process(expected, live):
            raise ProcessIdentityConflict()
        if any(key in expected and expected[key] != live[key] for key in ('sid', 'pgid')):
            raise ProcessIdentityConflict('Process escaped its recorded containment')
        try:
            signal.pidfd_send_signal(fd, sig)
        except ProcessLookupError:
            pass
    finally:
        os.close(fd)


class ProcessGroup:
    def __init__(self, leader, nonce):
        self.leader, self.nonce = leader, nonce
        self._known = {}

    def members(self):
        return group_members(self.leader['pgid'])

    def snapshot(self):
        if self.leader is None:
            raise ProcessIdentityConflict('Missing launch identity')
        live = read_process_identity(self.leader['pid'])
        if live is not None and not same_process(self.leader, live):
            raise ProcessIdentityConflict()
        if live is not None and any(live[k] != self.leader[k] for k in ('pgid', 'sid')):
            raise ProcessIdentityConflict()
        members = self.members()
        # An unreaped leader (including a zombie) anchors the kernel group and
        # session. This also works after BlueScrub drops UID, where reading
        # another UID's environ may be forbidden without CAP_SYS_PTRACE.
        anchor = read_process_identity(self.leader['pid'])
        if anchor is not None and not same_process(self.leader, anchor):
            raise ProcessIdentityConflict()
        if anchor is not None and any(anchor[k] != self.leader[k] for k in ('pgid', 'sid')):
            raise ProcessIdentityConflict()
        verified = []
        for item in members:
            retained = self._known.get(item['pid'])
            if retained is not None and not same_process(retained, item):
                raise ProcessIdentityConflict()
            nonce = self.nonce if anchor is not None or retained is not None else process_group_nonce(item['pid'])
            if nonce is None and anchor is None:
                current = read_process_identity(item['pid'])
                if current is None or (same_process(item, current) and current['state'] == 'Z'):
                    continue
                raise ProcessCleanupIncomplete('Orphan containment identity unavailable')
            if (item['sid'] != self.leader.get('sid', self.leader['pgid'])
                    or item['boot_id'] != self.leader['boot_id']
                    or item['start_ticks'] < self.leader['start_ticks']
                    or (anchor is None and (not self.nonce or nonce != self.nonce))):
                raise ProcessIdentityConflict()
            verified.append(item)
        self._known.update((item['pid'], dict(item)) for item in verified)
        return verified

    def stop(self, grace, deadline=None):
        deadline = time.monotonic() + grace + 3 if deadline is None else deadline
        for item in self.snapshot():
            signal_exact_process(item, signal.SIGTERM)
        until = min(time.monotonic() + grace, deadline)
        while time.monotonic() < until and self.snapshot():
            time.sleep(min(.05, max(0, until-time.monotonic())))
        drain_processes(self.snapshot, deadline)


class ProcessSession(ProcessGroup):
    """A launch-time session contains descendants independently of ancestry."""
    def members(self):
        return session_members(self.leader['sid'])


def drain_processes(snapshot, deadline, send=None):
    """Freeze a stable membership, kill it, and prove no live members remain.

    Two identical stopped snapshots close forks racing with delivery of STOP.
    Re-enumeration after KILL also catches late members; exhaustion never counts
    as success. The caller keeps its receipt when this raises.
    """
    send = send or signal_exact_process
    stable = None
    empty = False
    while time.monotonic() < deadline:
        items = snapshot()
        if not items:
            if empty:
                return
            empty = True
            continue
        empty = False
        keys = frozenset((i['pid'], i['start_ticks'], i['boot_id']) for i in items)
        stopped = all(i['state'] in ('T', 't') for i in items)
        if stopped and stable == keys:
            for item in items:
                send(item, signal.SIGKILL)
            stable = None
        else:
            stable = keys if stopped else None
            for item in items:
                if item['state'] not in ('T', 't'):
                    send(item, signal.SIGSTOP)
        time.sleep(min(.01, max(0, deadline-time.monotonic())))
    raise ProcessCleanupIncomplete('Process cleanup deadline exhausted')


def _kill_group(proc: subprocess.Popen, grace_seconds: float) -> None:
    """Reap the leader and kill surviving descendants even if TERM exits it."""
    if os.name == 'nt':
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=3)
        return
    proc.aipam_group.stop(grace_seconds)
    proc.wait(timeout=3)
