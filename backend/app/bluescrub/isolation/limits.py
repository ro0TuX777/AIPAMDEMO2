"""Resource limits and the pre-exec hook that applies them.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md §2.2
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

#: Only these variables reach an analyzer. An allowlist, never a copy-with-
#: deletions: a deletion list silently fails to cover variables added later,
#: and the worker environment holds the API token, database URL, broker URL,
#: the secret HMAC key, and Security Onion / Arkime passwords.
ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "HOME", "TMPDIR")


@dataclass(frozen=True)
class ResourceLimits:
    """Per-invocation ceilings enforced by ``setrlimit`` before ``exec``."""

    #: RLIMIT_AS. ``None`` disables it — see ``for_external_tool``.
    address_space_bytes: int | None = 2 * 1024**3
    cpu_seconds: int = 120                     # RLIMIT_CPU
    max_processes: int = 64                    # RLIMIT_NPROC, per-UID; needs a dedicated uid
    cpu_hard_margin: int = 5                   # RLIMIT_CPU hard - soft, so SIGXCPU fires first
    output_file_bytes: int = 256 * 1024**2     # RLIMIT_FSIZE
    wall_clock_seconds: int = 120              # enforced by the runner, not rlimit
    grace_seconds: int = 5                     # SIGTERM -> SIGKILL window
    max_stdout_bytes: int = 64 * 1024**2
    #: RLIMIT_DATA. Bounds the data segment, which since Linux 4.7 includes
    #: anonymous mmap — so it measures memory a process actually asks to use,
    #: rather than address space it merely reserves.
    data_bytes: int | None = None

    @classmethod
    def for_external_tool(cls) -> "ResourceLimits":
        """Ceilings for a compiled third-party binary.

        **`RLIMIT_AS` is not set, and that is a measurement, not a
        concession.** Semgrep 1.175 fails to run under `RLIMIT_AS` at *any*
        value tested — 2, 4 and 8 GiB all produce "the engine was killed" and
        exit 2. Its OCaml core reserves an enormous virtual arena at startup,
        and `RLIMIT_AS` caps virtual address space rather than memory in use,
        so the two have almost no relationship. The same is true of Go
        runtimes, which is what Gitleaks, TruffleHog, OSV-Scanner, Grype and
        Syft are.

        `RLIMIT_DATA` is the control that means what was intended: under it
        semgrep runs at 8 GiB and is killed at 4. The other ceilings — wall
        clock, CPU, file size, no core dump — and the process-group kill are
        unchanged, and they are what actually bound a runaway tool.
        """
        return cls(
            address_space_bytes=None,
            data_bytes=8 * 1024**3,
            cpu_seconds=900,
            wall_clock_seconds=900,
        )

    @classmethod
    def for_emulation(cls) -> "ResourceLimits":
        """Extended ceilings for capa / FLOSS / Ghidra-class work (deep profile)."""
        return cls(
            address_space_bytes=8 * 1024**3,
            cpu_seconds=900,
            wall_clock_seconds=900,
        )


def build_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Construct the child environment from the allowlist plus explicit extras."""
    env = {name: os.environ[name] for name in ENV_ALLOWLIST if name in os.environ}
    if extra:
        env.update(extra)
    return env


def build_preexec(
    limits: ResourceLimits,
    uid: int | None,
    gid: int | None,
) -> Callable[[], None]:
    """Return a ``preexec_fn`` that detaches, drops privileges, and sets rlimits.

    Order matters: the new session comes first so a kill reaches the whole
    group even if a later step fails, and the group is dropped before the user
    because dropping the user first would revoke the right to drop the group.
    """

    def _preexec() -> None:  # pragma: no cover - runs only in the forked child
        import resource
        os.setsid()

        if gid is not None:
            os.setgroups([])
            os.setresgid(gid, gid, gid)
        if uid is not None:
            os.setresuid(uid, uid, uid)

        # A vendored Python analyzer is bounded by address space, which is the
        # right control for CPython. A compiled tool with a reserving runtime
        # is not: see `for_external_tool`.
        if limits.address_space_bytes is not None:
            resource.setrlimit(resource.RLIMIT_AS,
                               (limits.address_space_bytes, limits.address_space_bytes))
        if limits.data_bytes is not None:
            resource.setrlimit(resource.RLIMIT_DATA,
                               (limits.data_bytes, limits.data_bytes))

        # Soft must be strictly below hard. At the soft limit the kernel sends
        # SIGXCPU, which we classify as a timeout; at the hard limit it sends
        # SIGKILL, which is indistinguishable from an OOM kill. Setting them
        # equal skips SIGXCPU entirely and misreports CPU exhaustion as memory
        # exhaustion.
        resource.setrlimit(resource.RLIMIT_CPU,
                           (limits.cpu_seconds, limits.cpu_seconds + limits.cpu_hard_margin))

        # RLIMIT_NPROC counts every process owned by the UID, not the process
        # tree. It is only meaningful once we have dropped to a dedicated
        # account; applied to a shared UID it either blocks the first fork or
        # constrains unrelated work.
        if uid is not None:
            resource.setrlimit(resource.RLIMIT_NPROC,
                               (limits.max_processes, limits.max_processes))

        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (limits.output_file_bytes, limits.output_file_bytes))
        # A core dump of a crashed analyzer contains attacker-controlled data.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _preexec


def require_privilege_drop() -> bool:
    """Whether a missing uid drop should refuse the run rather than proceed.

    Defaults to refusing. Tests and local development opt out explicitly; a
    deployment that forgets to create the account gets a loud failure instead
    of analyzers quietly running with worker privileges.
    """
    return os.getenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true").strip().lower() not in (
        "0", "false", "no",
    )
