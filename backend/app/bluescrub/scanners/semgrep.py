"""Semgrep adapter.

Runs the OSS engine (LGPL-2.1, freely bundlable) over a staged source tree.
Semgrep-maintained registry rules carry a separate licence permitting internal,
non-competing use only, so they are an operator-supplied add-on rather than a
bundled dependency: the shipped configuration is BlueScrub's own rule pack, and
``AIPAM_BLUESCRUB_SEMGREP_CONFIG`` points at additional rules where the
deployment's use permits it.

Reference: docs/BLUESCRUB_SUPPLY_CHAIN.md §4
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path

from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.rulemap import detector_for, normalize_cwes, resolve_family
from backend.app.bluescrub.scanners.base import ScannerOutcome
from backend.app.bluescrub.pillars import FAMILY_PILLAR, IssueFamily

logger = logging.getLogger(__name__)

SENSOR = "semgrep"
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "bluescrub"

#: Semgrep confidence metadata, mapped onto the 0–1 scale.
_CONFIDENCE = {"HIGH": 0.85, "MEDIUM": 0.65, "LOW": 0.45}


def parse_output(payload: dict, source_root: Path) -> list[RawFinding]:
    """Convert Semgrep JSON into raw normalized findings.

    Pure and side-effect free so it can be tested against fixtures without
    Semgrep installed.
    """
    findings: list[RawFinding] = []

    for item in payload.get("results") or []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = str(item.get("check_id") or "").strip()
        if not rule_id:
            continue

        cwes = normalize_cwes(metadata.get("cwe"))
        family = resolve_family(SENSOR, rule_id, cwes)

        raw_path = str(item.get("path") or "")
        try:
            rel = str(Path(raw_path).resolve().relative_to(source_root.resolve()))
        except (ValueError, OSError):
            rel = raw_path

        start = item.get("start") or {}
        end = item.get("end") or {}

        namespace = rule_id.rsplit(".", 1)[0] if "." in rule_id else None
        confidence = _CONFIDENCE.get(str(metadata.get("confidence", "")).upper(), 0.65)

        findings.append(RawFinding(
            sensor=SENSOR,
            sensor_version=str(payload.get("version") or "unknown"),
            rule_namespace=namespace,
            rule_id=rule_id,
            issue_family=family,
            pillar_hint=FAMILY_PILLAR.get(family),
            detector_class=detector_for(SENSOR),
            raw_severity=str(extra.get("severity") or "WARNING"),
            confidence=confidence,
            source_facet="source",
            title=rule_id.rsplit(".", 1)[-1].replace("-", " "),
            description=str(extra.get("message") or "")[:4096],
            cwe=cwes,
            matched_tokens=str(extra.get("lines") or "")[:4096],
            location=Location(
                kind="source",
                file=rel,
                start_line=start.get("line"),
                end_line=end.get("line"),
                start_column=start.get("col"),
                end_column=end.get("col"),
            ),
        ))

    return findings


def _rules_config() -> str | None:
    configured = os.getenv("AIPAM_BLUESCRUB_SEMGREP_CONFIG")
    if configured:
        return configured
    if DEFAULT_RULES.exists():
        return str(DEFAULT_RULES)
    return None


def run(source_root: Path, output_dir: Path, *, limits: ResourceLimits | None = None) -> ScannerOutcome:
    """Run Semgrep over ``source_root`` inside the analyzer process boundary."""
    binary = shutil.which("semgrep")
    if not binary:
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason="semgrep not on PATH",
        )

    config = _rules_config()
    if not config:
        # No rules means no findings, which is indistinguishable from a clean
        # result unless it is reported as unavailable.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason="no rule pack configured (AIPAM_BLUESCRUB_SEMGREP_CONFIG unset)",
        )

    argv = [
        binary, "--json", "--quiet", "--no-git-ignore",
        "--metrics", "off",          # never phone home from an air-gapped host
        "--disable-version-check",
        "--config", config,
        str(source_root),
    ]

    result = run_analyzer(
        argv,
        cwd=source_root,
        limits=limits or ResourceLimits(),
        require_privilege_drop=_require_drop(),
    )

    if not result.ok:
        return ScannerOutcome(
            sensor=SENSOR, status=result.status.value,
            duration_ms=result.duration_ms, reason=result.reason,
        )

    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError as exc:
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unparseable.value,
            duration_ms=result.duration_ms, reason=f"invalid JSON: {exc}",
        )

    findings = parse_output(payload, source_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )

    return ScannerOutcome(
        sensor=SENSOR, status=result.status.value, findings=findings,
        version=str(payload.get("version") or "unknown"),
        ruleset_version=config, duration_ms=result.duration_ms,
        reason=result.reason,
    )


def _require_drop() -> bool:
    return os.getenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true").lower() not in (
        "0", "false", "no"
    )
