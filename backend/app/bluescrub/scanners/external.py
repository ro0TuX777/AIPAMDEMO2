"""Shared harness for external analysis binaries.

OSV-Scanner, Grype, Syft, Joern, and Weggli differ only in their argv and the
shape of their JSON. Everything else — availability probing, invocation through
the isolation boundary, exit-code classification, output-size handling, and
turning a tool's absence into honest coverage loss rather than a clean result —
is identical, and is written once here.

The per-tool parser is the part that carries bugs. The Semgrep adapter shipped
three defects that only surfaced when it was run against real output, so the
parsers here are pure functions tested against recorded tool output rather than
reached only through a subprocess.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md, docs/BLUESCRUB_SUPPLY_CHAIN.md
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import RawFinding
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

#: Parser contract: (payload, source_root) -> raw findings.
Parser = Callable[[dict, Path], list[RawFinding]]


@dataclass(frozen=True)
class ExternalTool:
    """A binary this pipeline can invoke, and how to read what it says."""

    sensor: str
    binary: str
    argv: Callable[[Path], Sequence[str]]
    parse: Parser
    #: Exit codes that mean "ran fine, found something". Several security tools
    #: signal findings with a non-zero exit, which a naive check reads as a
    #: crash and reports as a degraded pillar.
    finding_exit_codes: tuple[int, ...] = (0,)
    #: A version probe, when the tool supports one. Recorded in the report so a
    #: stale binary is visible rather than inferred.
    version_argv: tuple[str, ...] | None = None
    limits: ResourceLimits | None = None


def probe_version(tool: ExternalTool) -> str | None:
    if not tool.version_argv:
        return None
    binary = shutil.which(tool.binary)
    if not binary:
        return None
    result = run_analyzer(
        [binary, *tool.version_argv],
        limits=ResourceLimits(wall_clock_seconds=30, cpu_seconds=30),
        require_privilege_drop=_require_drop(),
    )
    if not result.ok:
        return None
    return (result.stdout or b"").decode("utf-8", "replace").strip()[:64] or None


def run_external(
    tool: ExternalTool, source_root: Path, output_dir: Path
) -> ScannerOutcome:
    """Invoke one external tool and normalise whatever it produced."""
    binary = shutil.which(tool.binary)
    if not binary:
        # Not a failure and not a clean result: the pillar loses coverage.
        return ScannerOutcome(
            sensor=tool.sensor,
            status=AnalyzerStatus.unavailable.value,
            reason=f"{tool.binary} not on PATH",
        )

    argv = [binary, *tool.argv(source_root)]
    result = run_analyzer(
        argv,
        cwd=source_root,
        limits=tool.limits or ResourceLimits(),
        require_privilege_drop=_require_drop(),
    )

    exit_ok = result.ok or (result.exit_code in tool.finding_exit_codes)
    if not exit_ok:
        return ScannerOutcome(
            sensor=tool.sensor, status=result.status.value,
            duration_ms=result.duration_ms, reason=result.reason,
        )

    raw = result.stdout or b"{}"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        # Quarantine the unreadable output rather than discarding it: an
        # unparseable result is a defect to diagnose, not a finding to drop.
        _quarantine(output_dir, tool.sensor, raw)
        return ScannerOutcome(
            sensor=tool.sensor, status=AnalyzerStatus.unparseable.value,
            duration_ms=result.duration_ms, reason=f"invalid JSON: {exc}",
        )

    try:
        findings = tool.parse(payload, source_root)
    except Exception as exc:  # a parser bug must not fail the job
        logger.warning("%s parser raised: %s", tool.sensor, exc, exc_info=True)
        _quarantine(output_dir, tool.sensor, raw)
        return ScannerOutcome(
            sensor=tool.sensor, status=AnalyzerStatus.unparseable.value,
            duration_ms=result.duration_ms, reason=f"parser error: {exc}"[:256],
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )

    status = (
        AnalyzerStatus.completed_truncated.value
        if result.status is AnalyzerStatus.completed_truncated
        else AnalyzerStatus.completed.value
    )
    return ScannerOutcome(
        sensor=tool.sensor, status=status, findings=findings,
        version=probe_version(tool), duration_ms=result.duration_ms,
        reason=result.reason,
    )


def _quarantine(output_dir: Path, sensor: str, raw: bytes) -> None:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / f"{sensor}.unparseable.raw").write_bytes(raw[:1024 * 1024])
    except OSError:  # pragma: no cover - best effort
        pass


def _require_drop() -> bool:
    return os.getenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true").lower() not in (
        "0", "false", "no"
    )
