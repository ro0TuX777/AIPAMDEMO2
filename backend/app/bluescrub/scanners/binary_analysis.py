"""Vendored PE/ELF/Mach-O analysis.

Upstream guards every parsing library behind an ``*_AVAILABLE`` flag, so a
deployment missing ``pefile`` or ``pyelftools`` gets an analyzer that returns
nothing and looks exactly like a clean binary. This adapter refuses to present
that as a result: if the capabilities needed for the artifacts present are
absent, the scanner reports ``unavailable`` and the pillar degrades.

Reference: docs/BLUESCRUB_SUPPLY_CHAIN.md §2, §3
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from backend.app.bluescrub.enrich import autofix_for, mitre_for
from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.rulemap import normalize_label, resolve_family
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "binary_analyzer"

#: Capabilities without which binary analysis is not meaningfully running.
REQUIRED_CAPABILITIES = ("pe_analysis", "elf_analysis")


def capabilities() -> dict[str, bool]:
    from backend.app.bluescrub.vendored.scanners.binary import BinaryAnalyzer

    try:
        return dict(BinaryAnalyzer().get_capabilities())
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("binary analyzer capability probe failed: %s", exc)
        return {}


def missing_capabilities() -> list[str]:
    caps = capabilities()
    return [c for c in REQUIRED_CAPABILITIES if not caps.get(c)]


def to_raw_findings(records: list[dict], source_root: Path) -> list[RawFinding]:
    """Normalise per-artifact binary records into raw findings."""
    findings: list[RawFinding] = []

    for record in records:
        if not isinstance(record, dict):
            continue
        raw_path = str(record.get("file") or record.get("path") or "")
        try:
            rel = str(Path(raw_path).resolve().relative_to(source_root.resolve()))
        except (ValueError, OSError):
            rel = raw_path

        sha256 = str(record.get("sha256") or "") or None
        fmt = str(record.get("format") or record.get("type") or "") or None
        arch = str(record.get("architecture") or record.get("arch") or "") or None

        for issue in record.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            label = str(issue.get("type") or issue.get("category") or "")
            if not label:
                continue

            family = resolve_family(SENSOR, normalize_label(label))
            description = str(issue.get("description") or label)
            matched = str(issue.get("match") or issue.get("api") or issue.get("value") or "")

            findings.append(RawFinding(
                sensor=SENSOR,
                sensor_version="vendored",
                rule_namespace="BinaryAnalyzer",
                rule_id=f"BinaryAnalyzer.{normalize_label(label)}",
                issue_family=family,
                pillar_hint=FAMILY_PILLAR.get(family),
                detector_class=DetectorClass.heuristic,
                raw_severity=str(issue.get("severity") or "MEDIUM").upper(),
                confidence=0.65,
                source_facet="binary",
                title=label,
                description=description[:4096],
                # The tier model upstream already carries a per-API rationale;
                # preserve it rather than regenerating a generic one.
                recommendation=str(issue.get("severity_rationale") or "")[:2048] or None,
                mitre=mitre_for(matched, label, description),
                matched_tokens=matched[:4096],
                location=Location(
                    kind="binary", file=rel, artifact_sha256=sha256,
                    format=fmt, architecture=arch,
                    section=str(issue.get("section") or "") or None,
                    offset=issue.get("offset") if isinstance(issue.get("offset"), int) else None,
                ),
            ))

    return findings


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    missing = missing_capabilities()
    if missing:
        # Reporting "no findings" here would be a lie about an unexamined
        # artifact. Coverage drops instead.
        return ScannerOutcome(
            sensor=SENSOR,
            status=AnalyzerStatus.unavailable.value,
            reason=f"missing binary parsing capabilities: {', '.join(missing)}",
        )

    result = run_analyzer(
        [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
         "__binary__", str(source_root), "binary"],
        cwd=Path.cwd(),
        limits=limits or ResourceLimits.for_emulation(),
        require_privilege_drop=os.getenv(
            "AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true"
        ).lower() not in ("0", "false", "no"),
        env_extra={"PYTHONPATH": os.getcwd()},
    )

    if not result.ok:
        return ScannerOutcome(sensor=SENSOR, status=result.status.value,
                              duration_ms=result.duration_ms, reason=result.reason)

    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError as exc:
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.unparseable.value,
                              duration_ms=result.duration_ms, reason=str(exc))

    if not payload.get("ok"):
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.crashed.value,
                              duration_ms=result.duration_ms,
                              reason=str(payload.get("error"))[:256])

    findings = to_raw_findings(payload.get("findings") or [], source_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )
    return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.completed.value,
                          findings=findings, version="vendored",
                          duration_ms=result.duration_ms)
