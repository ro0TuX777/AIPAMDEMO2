"""Adapter for the vendored BlueScrub analyzer corpus.

Each analyzer runs in its own subprocess behind the isolation boundary and its
heterogeneous finding dicts are normalised onto the same raw contract every
other scanner uses. Pillar assignment goes through the shared family map, so
the vendored vocabulary does not grow a second taxonomy beside the Semgrep one.

Several analyzers legitimately report the same underlying issue — a hardcoded
key surfaces from OpsecAnalyzer, SecretsAnalyzer, and
CryptoVulnerabilityAnalyzer at once. That is what canonicalization collapses;
this layer does not attempt to deduplicate.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.rulemap import normalize_label, resolve_family
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "bluescrub_analyzers"

#: Analyzer classes exported by the vendored package, in deterministic order.
ANALYZERS: tuple[str, ...] = (
    "OpsecAnalyzer",
    "ExploitationToolAnalyzer",
    "SecretsAnalyzer",
    "InformationDisclosureAnalyzer",
    "MemorySafetyAnalyzer",
    "CryptoVulnerabilityAnalyzer",
    "SupplyChainAnalyzer",
)

_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
             "LOW": "LOW", "INFO": "INFO"}


def _label(item: dict) -> str:
    """The best available description of what the analyzer matched."""
    return str(item.get("category") or item.get("issue") or item.get("type") or "")


def to_raw_findings(analyzer: str, items: list[dict], source_root: Path) -> list[RawFinding]:
    """Normalise one analyzer's output. Pure, so it is testable without a subprocess."""
    findings: list[RawFinding] = []

    for item in items:
        label = _label(item)
        if not label:
            continue
        rule_id = f"{analyzer}.{normalize_label(label)}"
        family = resolve_family(SENSOR, normalize_label(label))

        raw_path = str(item.get("file") or "")
        try:
            rel = str(Path(raw_path).resolve().relative_to(source_root.resolve()))
        except (ValueError, OSError):
            rel = raw_path

        line = item.get("line")
        findings.append(RawFinding(
            sensor=SENSOR,
            sensor_version="vendored",
            rule_namespace=analyzer,
            rule_id=rule_id,
            issue_family=family,
            pillar_hint=FAMILY_PILLAR.get(family),
            # Every vendored analyzer is a regex matcher, which is the lowest
            # authority tier: a semantic detector disagreeing with one wins.
            detector_class=DetectorClass.regex_pattern,
            raw_severity=_SEVERITY.get(str(item.get("severity", "")).upper(), "MEDIUM"),
            confidence=0.6,
            source_facet="source",
            title=label,
            description=str(item.get("issue") or item.get("description") or label)[:4096],
            recommendation=str(item.get("recommended_fix") or "")[:2048] or None,
            matched_tokens=str(item.get("match") or item.get("pattern") or "")[:4096],
            location=Location(
                kind="source", file=rel,
                start_line=int(line) if isinstance(line, int) else None,
                start_column=0,
            ),
        ))

    return findings


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None) -> ScannerOutcome:
    """Run every vendored analyzer, each behind its own process boundary."""
    limits = limits or ResourceLimits()
    require_drop = os.getenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true").lower() not in (
        "0", "false", "no"
    )

    findings: list[RawFinding] = []
    failures: list[str] = []
    duration = 0

    for analyzer in ANALYZERS:
        result = run_analyzer(
            [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
             analyzer, str(source_root)],
            cwd=Path.cwd(),
            limits=limits,
            require_privilege_drop=require_drop,
            env_extra={"PYTHONPATH": os.getcwd()},
        )
        duration += result.duration_ms

        if not result.ok:
            # One analyzer failing degrades the pillar; it does not stop the rest.
            failures.append(f"{analyzer}:{result.status.value}")
            logger.warning("vendored analyzer %s: %s (%s)",
                           analyzer, result.status.value, result.reason)
            continue

        try:
            payload = json.loads(result.stdout or b"{}")
        except json.JSONDecodeError:
            failures.append(f"{analyzer}:unparseable")
            continue

        if not payload.get("ok"):
            failures.append(f"{analyzer}:{payload.get('error', 'error')}")
            continue

        findings.extend(to_raw_findings(analyzer, payload.get("findings") or [], source_root))

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )

    if failures and not findings:
        status = AnalyzerStatus.crashed.value
    elif failures:
        status = AnalyzerStatus.completed_truncated.value
    else:
        status = AnalyzerStatus.completed.value

    return ScannerOutcome(
        sensor=SENSOR, status=status, findings=findings,
        version="vendored", ruleset_version="bluescrub-analyzers",
        duration_ms=duration,
        reason=("; ".join(failures)[:256] or None),
    )
