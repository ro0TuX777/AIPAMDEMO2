"""Resource limits and the pre-exec hook that applies them.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md §2.2
"""

from __future__ import annotations

import os
import resource
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

    address_space_bytes: int = 2 * 1024**3     # RLIMIT_AS
    cpu_seconds: int = 120                     # RLIMIT_CPU
    max_processes: int = 64                    # RLIMIT_NPROC, per-UID; needs a dedicated uid
    cpu_hard_margin: int = 5                   # RLIMIT_CPU hard - soft, so SIGXCPU fires first
    output_file_bytes: int = 256 * 1024**2     # RLIMIT_FSIZE
    wall_clock_seconds: int = 120              # enforced by the runner, not rlimit
    grace_seconds: int = 5                     # SIGTERM -> SIGKILL window
    max_stdout_bytes: int = 64 * 1024**2

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
        os.setsid()

        if gid is not None:
            os.setgroups([])
            os.setresgid(gid, gid, gid)
        if uid is not None:
            os.setresuid(uid, uid, uid)

        resource.setrlimit(resource.RLIMIT_AS,
                           (limits.address_space_bytes, limits.address_space_bytes))

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
