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
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from backend.app.bluescrub.isolation import (
    AnalyzerStatus,
    ResourceLimits,
    require_privilege_drop,
    run_analyzer,
)
from backend.app.bluescrub.models import RawFinding
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

#: Parser contract: (payload, source_root) -> raw findings. The payload is
#: whatever the tool's JSON decodes to — Gitleaks reports a bare array.
Parser = Callable[[Any, Path], list[RawFinding]]


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
    #: One JSON object per line rather than one document. TruffleHog streams
    #: results this way, and ``json.loads`` on the whole stream fails on the
    #: second object — which presents as a tool that found nothing.
    json_lines: bool = False
    #: Its matches are credentials. The on-disk artefacts are then written
    #: under the rules for plaintext rather than the rules for findings.
    secret_bearing: bool = False


def probe_version(tool: ExternalTool) -> str | None:
    if not tool.version_argv:
        return None
    binary = shutil.which(tool.binary)
    if not binary:
        return None
    result = run_analyzer(
        [binary, *tool.version_argv],
        # A version probe still has to start the runtime, so it needs the same
        # memory control as a real invocation.
        limits=ResourceLimits(address_space_bytes=None, data_bytes=8 * 1024**3,
                              wall_clock_seconds=30, cpu_seconds=30),
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
        # Every tool reached through this harness is a compiled binary with a
        # reserving runtime, so the external profile is the right default.
        limits=tool.limits or ResourceLimits.for_external_tool(),
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
        payload = decode_payload(raw, json_lines=tool.json_lines)
    except json.JSONDecodeError as exc:
        # Quarantine the unreadable output rather than discarding it: an
        # unparseable result is a defect to diagnose, not a finding to drop.
        _quarantine(output_dir, tool.sensor, raw, tool.secret_bearing)
        return ScannerOutcome(
            sensor=tool.sensor, status=AnalyzerStatus.unparseable.value,
            duration_ms=result.duration_ms, reason=f"invalid JSON: {exc}",
        )

    try:
        findings = tool.parse(payload, source_root)
    except Exception as exc:  # a parser bug must not fail the job
        logger.warning("%s parser raised: %s", tool.sensor, exc, exc_info=True)
        _quarantine(output_dir, tool.sensor, raw, tool.secret_bearing)
        return ScannerOutcome(
            sensor=tool.sensor, status=AnalyzerStatus.unparseable.value,
            duration_ms=result.duration_ms, reason=f"parser error: {exc}"[:256],
        )

    write_results(output_dir, findings, sensor=tool.sensor,
                  secret_bearing=tool.secret_bearing)

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


def decode_payload(raw: bytes, *, json_lines: bool = False) -> Any:
    """Decode a tool's stdout.

    A JSON-lines stream is wrapped rather than concatenated so a parser sees
    one shape regardless of how its tool chose to frame the output. Blank lines
    and the progress banners some tools interleave are skipped; a line that is
    genuinely malformed still raises, because silently dropping results is how
    a broken adapter comes to look like a clean scan.
    """
    if not json_lines:
        return json.loads(raw or b"{}")

    records = []
    for line in (raw or b"").splitlines():
        line = line.strip()
        if not line or not line.startswith(b"{"):
            continue
        records.append(json.loads(line))
    return {"results": records}


def results_path(output_dir: Path, sensor: str, *, secret_bearing: bool) -> Path:
    """Where a tool's normalised output goes.

    Findings live beside the job and age out with it at 30 days. Anything
    holding a plaintext credential belongs in ``quarantine/``, which the policy
    sweeps at 72 hours — so a secret scanner's artefacts are written there
    instead of inheriting the longer clock.
    """
    if not secret_bearing:
        return output_dir / "sensor.results.jsonl"
    root = output_dir.parents[1] if len(output_dir.parents) >= 2 else output_dir
    return root / "quarantine" / f"{sensor}.results.jsonl"


def write_results(output_dir: Path, findings: list[RawFinding], *,
                  sensor: str | None = None, secret_bearing: bool = False) -> Path:
    """Write the normalised findings, withholding evidence where it is a secret.

    Central redaction runs later, in the service, over the findings still in
    memory. This file is written before that, so for a secret scanner it would
    be the one place a plaintext credential lands on disk and stays — under the
    30-day job clock rather than the 72-hour quarantine one. The evidence
    fields are dropped from the artefact rather than masked, because a masked
    value here would be mistaken for the value the analyst sees later.
    """
    name = sensor or (findings[0].sensor if findings else "unknown")
    path = results_path(output_dir, name, secret_bearing=secret_bearing)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    for finding in findings:
        record = finding.to_dict()
        if secret_bearing:
            record.pop("matched_tokens", None)
            record["description"] = "evidence withheld pending redaction"
        lines.append(json.dumps(record))
    path.write_text("\n".join(lines))
    return path


def _quarantine(output_dir: Path, sensor: str, raw: bytes,
                secret_bearing: bool = False) -> None:
    try:
        if secret_bearing:
            root = output_dir.parents[1] if len(output_dir.parents) >= 2 else output_dir
            target = root / "quarantine" / f"{sensor}.unparseable.raw"
        else:
            target = output_dir / f"{sensor}.unparseable.raw"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw[:1024 * 1024])
    except OSError:  # pragma: no cover - best effort
        pass


def _require_drop() -> bool:
    return require_privilege_drop()
