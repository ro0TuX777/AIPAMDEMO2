"""Dependency inventory.

The vendored scanner is offline by design: it parses manifests and lockfiles
and never queries a vulnerability service. That means it reports *hygiene*
(unpinned versions, unparseable manifests) reliably, and reports CVEs only if
an offline database happens to be present.

Those are different claims, and conflating them is how a scan of a dependency
tree full of known CVEs comes back clean. The adapter emits hygiene findings
normally and marks the outcome degraded whenever no vulnerability source was
available, so the Co-Optability pillar shows reduced coverage rather than a
confident zero.

Reference: docs/BLUESCRUB_SUPPLY_CHAIN.md §1.2
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
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "dependency_inventory"


def _finding(rule: str, family: IssueFamily, severity: str, title: str,
             description: str, subject: str, matched: str = "") -> RawFinding:
    return RawFinding(
        sensor=SENSOR, sensor_version="vendored",
        rule_namespace="DependencyScanner", rule_id=f"DependencyScanner.{rule}",
        issue_family=family, pillar_hint=FAMILY_PILLAR.get(family),
        detector_class=DetectorClass.heuristic,
        raw_severity=severity, confidence=0.7, source_facet="vulnerability",
        title=title, description=description[:4096],
        matched_tokens=matched[:4096],
        location=Location(kind="project", subject=subject),
    )


def to_raw_findings(inventory: dict) -> list[RawFinding]:
    """Turn an inventory record into findings.

    Only states the scanner can actually establish offline become findings.
    """
    findings: list[RawFinding] = []

    for package in inventory.get("packages") or []:
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        subject = f"{name}@{version}" if version else name
        if not name:
            continue

        if package.get("unpinned") or not version:
            findings.append(_finding(
                "unpinned_dependency", IssueFamily.dependency_confusion, "MEDIUM",
                "Unpinned dependency",
                f"{name} is not pinned to a version. An unpinned dependency resolves "
                "differently at each build, so the artifact shipped is not the artifact "
                "audited, and a substituted package reaches the target unnoticed.",
                subject, name,
            ))

        for vuln in package.get("vulnerabilities") or []:
            ident = str(vuln.get("id") or vuln.get("cve") or "unknown")
            findings.append(_finding(
                "vulnerable_dependency", IssueFamily.dependency_vulnerable,
                str(vuln.get("severity") or "HIGH").upper(),
                f"Vulnerable dependency: {ident}",
                str(vuln.get("description") or
                    f"{subject} is affected by {ident}."),
                subject, ident,
            ))

    for error in inventory.get("parse_errors") or []:
        manifest = str(error.get("file") if isinstance(error, dict) else error)
        findings.append(_finding(
            "unparseable_manifest", IssueFamily.dependency_confusion, "LOW",
            "Unparseable dependency manifest",
            f"{manifest} could not be parsed, so its dependencies were not inventoried. "
            "The absence of findings for this manifest is not evidence of its safety.",
            manifest, manifest,
        ))

    return findings


def _has_vulnerability_source(inventory: dict) -> bool:
    tools = inventory.get("tools_available") or {}
    return bool(tools.get("dependency-check") or tools.get("safety") or
                tools.get("osv") or tools.get("grype"))


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    result = run_analyzer(
        [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
         "__deps__", str(source_root), "dependencies"],
        cwd=Path.cwd(),
        limits=limits or ResourceLimits(),
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

    inventory = payload.get("findings") or {}
    findings = to_raw_findings(inventory if isinstance(inventory, dict) else {})

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )

    if not _has_vulnerability_source(inventory):
        # Hygiene findings are sound; CVE coverage is not. Say so.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.completed_truncated.value,
            findings=findings, version="vendored",
            ruleset_state="database_stale", duration_ms=result.duration_ms,
            reason="no offline vulnerability database available — CVE coverage absent",
        )

    return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.completed.value,
                          findings=findings, version="vendored",
                          duration_ms=result.duration_ms)
