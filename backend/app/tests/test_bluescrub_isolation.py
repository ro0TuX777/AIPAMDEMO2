"""BlueScrub analyzer isolation — the process boundary must actually hold.

Covers plan §15 acceptance #7 (a scanner timeout or parser failure cannot
terminate or poison the worker process) and the isolation contract's own
acceptance list.
"""

import json
import os
import signal
import sys
import time

import pytest

from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.isolation.runner import PrivilegeDropUnavailable

#: These tests run as an ordinary user, so privilege drop is impossible and is
#: waived explicitly. Production defaults require it; see test_privilege_drop_*.
NO_DROP = dict(drop_user=None, require_privilege_drop=False)

FAST = ResourceLimits(wall_clock_seconds=3, grace_seconds=1, cpu_seconds=5)


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_successful_run_captures_stdout():
    result = run_analyzer(_py("print('hello')"), limits=FAST, **NO_DROP)

    assert result.status is AnalyzerStatus.completed
    assert result.ok
    assert result.stdout.strip() == b"hello"
    assert result.exit_code == 0


def test_nonzero_exit_is_crashed_not_an_exception():
    result = run_analyzer(_py("import sys; sys.exit(3)"), limits=FAST, **NO_DROP)

    assert result.status is AnalyzerStatus.crashed
    assert result.exit_code == 3
    assert not result.ok


def test_missing_executable_is_unavailable():
    result = run_analyzer(["/nonexistent/analyzer-binary"], limits=FAST, **NO_DROP)

    assert result.status is AnalyzerStatus.unavailable
    assert "not found" in result.reason


def test_hung_analyzer_is_killed_and_worker_survives():
    """A spinning analyzer must not hold the worker. This is the core property."""
    started = time.monotonic()
    result = run_analyzer(_py("while True: pass"), limits=FAST, **NO_DROP)
    elapsed = time.monotonic() - started

    assert result.status is AnalyzerStatus.timeout
    assert elapsed < FAST.wall_clock_seconds + 5
    # The worker is still healthy enough to run the next analyzer.
    assert run_analyzer(_py("print('alive')"), limits=FAST, **NO_DROP).ok


def test_catastrophic_regex_is_killed():
    """The exact failure a thread timeout cannot handle."""
    code = "import re; re.match(r'(a+)+$', 'a'*64 + 'b')"
    result = run_analyzer(_py(code), limits=FAST, **NO_DROP)

    assert result.status is AnalyzerStatus.timeout


def test_grandchildren_are_reaped(tmp_path):
    """proc.kill() would signal only the direct child, orphaning its children."""
    pidfile = tmp_path / "grandchild.pid"
    code = (
        "import os, sys, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    open(%r, 'w').write(str(os.getpid()))\n"
        "    while True: time.sleep(0.1)\n"
        "else:\n"
        "    while True: time.sleep(0.1)\n" % str(pidfile)
    )
    result = run_analyzer(_py(code), limits=FAST, **NO_DROP)
    assert result.status is AnalyzerStatus.timeout

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not pidfile.exists():
        time.sleep(0.05)
    assert pidfile.exists(), "grandchild never started; test is inconclusive"

    grandchild = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _pid_alive(grandchild):
            break
        time.sleep(0.05)
    assert not _pid_alive(grandchild), "grandchild survived the process-group kill"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_environment_is_scrubbed(monkeypatch):
    """The child must not inherit the worker's credentials."""
    secrets = {
        "AIPAM_API_TOKEN": "tok-should-not-leak",
        "DATABASE_URL": "sqlite:///should-not-leak.db",
        "CELERY_BROKER_URL": "redis://should-not-leak",
        "AIPAM_BLUESCRUB_SECRET_HMAC_KEY": "key-should-not-leak",
        "SECURITY_ONION_PASSWORD": "pw-should-not-leak",
    }
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)

    result = run_analyzer(
        _py("import os, json; print(json.dumps(dict(os.environ)))"),
        limits=FAST, **NO_DROP,
    )
    assert result.ok
    child_env = json.loads(result.stdout)

    for name in secrets:
        assert name not in child_env, f"{name} leaked into the analyzer environment"
    blob = json.dumps(child_env)
    for value in secrets.values():
        assert value not in blob
    assert "PATH" in child_env


def test_new_variables_do_not_leak_by_default(monkeypatch):
    """Allowlist, not copy-with-deletions: an unknown variable must not pass."""
    monkeypatch.setenv("SOME_FUTURE_SECRET", "leaked")
    result = run_analyzer(
        _py("import os, json; print(json.dumps(dict(os.environ)))"),
        limits=FAST, **NO_DROP,
    )
    assert "SOME_FUTURE_SECRET" not in json.loads(result.stdout)


def test_stdout_cap_marks_truncated():
    limits = ResourceLimits(
        wall_clock_seconds=10, grace_seconds=1, max_stdout_bytes=1024,
    )
    result = run_analyzer(
        _py("import sys; sys.stdout.write('x' * 100000)"), limits=limits, **NO_DROP,
    )
    assert result.status is AnalyzerStatus.completed_truncated
    assert len(result.stdout) == 1024
    assert result.ok  # truncated output is still usable, just flagged


def test_memory_limit_does_not_take_down_the_worker():
    limits = ResourceLimits(
        address_space_bytes=64 * 1024 * 1024, wall_clock_seconds=10, grace_seconds=1,
    )
    result = run_analyzer(
        _py("x = bytearray(512 * 1024 * 1024)"), limits=limits, **NO_DROP,
    )
    assert result.status in (AnalyzerStatus.oom, AnalyzerStatus.crashed)
    assert run_analyzer(_py("print('alive')"), limits=FAST, **NO_DROP).ok


def test_cpu_rlimit_classified_as_timeout():
    limits = ResourceLimits(cpu_seconds=1, wall_clock_seconds=30, grace_seconds=1)
    result = run_analyzer(_py("while True: pass"), limits=limits, **NO_DROP)

    assert result.status is AnalyzerStatus.timeout
    assert result.signal_number == signal.SIGXCPU


def test_privilege_drop_required_refuses_unknown_user():
    with pytest.raises(PrivilegeDropUnavailable):
        run_analyzer(
            _py("print('should not run')"),
            limits=FAST,
            drop_user="definitely-no-such-user-bluescrub",
            require_privilege_drop=True,
        )


@pytest.mark.skipif(os.geteuid() == 0, reason="requires a non-root worker")
def test_privilege_drop_required_refuses_non_root_worker():
    """Contract acceptance #6: refuse rather than run with worker privileges."""
    import pwd

    current = pwd.getpwuid(os.getuid()).pw_name
    with pytest.raises(PrivilegeDropUnavailable):
        run_analyzer(
            _py("print('should not run')"),
            limits=FAST, drop_user=current, require_privilege_drop=True,
        )


def test_no_shell_interpretation():
    """argv is never passed through a shell."""
    result = run_analyzer(
        _py("import sys; print(sys.argv[1])") + ["; touch /tmp/pwned"],
        limits=FAST, **NO_DROP,
    )
    assert result.ok
    assert result.stdout.strip() == b"; touch /tmp/pwned"
