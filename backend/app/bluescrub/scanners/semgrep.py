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
from functools import lru_cache
from pathlib import Path

import yaml

from backend.app.bluescrub.enrich import mitre_for
from backend.app.bluescrub.isolation import (
    AnalyzerStatus,
    ResourceLimits,
    require_privilege_drop,
    run_analyzer,
)
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.rulemap import detector_for, normalize_cwes, resolve_family
from backend.app.bluescrub.scanners.base import ScannerOutcome
from backend.app.bluescrub.pillars import FAMILY_PILLAR, IssueFamily

logger = logging.getLogger(__name__)

SENSOR = "semgrep"
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "bluescrub"

#: Semgrep confidence metadata, mapped onto the 0–1 scale.
_CONFIDENCE = {"HIGH": 0.85, "MEDIUM": 0.65, "LOW": 0.45}


@lru_cache(maxsize=1)
def _shipped_rule_ids() -> tuple[str, ...]:
    """Rule ids declared by the shipped pack, longest first."""
    ids: list[str] = []
    if not DEFAULT_RULES.exists():
        return ()
    for path in sorted(DEFAULT_RULES.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - validated in tests
            logger.warning("unreadable rule file %s: %s", path.name, exc)
            continue
        ids.extend(str(r["id"]) for r in doc.get("rules") or [] if r.get("id"))
    return tuple(sorted(ids, key=len, reverse=True))


def normalize_check_id(check_id: str, config: str | None = None) -> str:
    """Recover a rule's declared id from the one Semgrep reports.

    Given ``--config <dir>``, Semgrep prefixes every ``check_id`` with the
    config path turned into dots:
    ``backend.app.bluescrub.rules.bluescrub.bluescrub.vuln.unchecked-memcpy``.

    That cannot be persisted as-is. ``rule_id`` is a fingerprint component, so
    relocating the rules directory would change every fingerprint and orphan
    every triage decision attached to them. Identity has to come from the rule.

    Matching against the pack's own declared ids rather than stripping a
    computed prefix: the reported path is repo-relative while the config passed
    in may be absolute, and a naive search for the namespace finds the
    occurrence inside the *path* first.
    """
    for rule_id in _shipped_rule_ids():
        if check_id == rule_id or check_id.endswith("." + rule_id):
            return rule_id

    if config:
        prefix = str(config).strip("/").replace("/", ".") + "."
        if check_id.startswith(prefix):
            return check_id[len(prefix):]

    # A third-party rule from a pack we do not ship: leave it untouched.
    return check_id


def parse_output(payload: dict, source_root: Path, config: str | None = None) -> list[RawFinding]:
    """Convert Semgrep JSON into raw normalized findings.

    Pure and side-effect free so it can be tested against fixtures without
    Semgrep installed.
    """
    findings: list[RawFinding] = []

    for item in payload.get("results") or []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = normalize_check_id(str(item.get("check_id") or "").strip(), config)
        if not rule_id:
            continue

        cwes = normalize_cwes(metadata.get("cwe"))
        # A shipped rule declares its own family; that is an authored decision
        # and outranks CWE or keyword inference. Reading it was missed when the
        # pack was written, so every BlueScrub rule was resolving by keyword and
        # some landed in "unmapped" despite declaring a family.
        declared = metadata.get("bluescrub_family")
        family = (
            _declared_family(declared)
            or resolve_family(SENSOR, rule_id, cwes)
        )

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
            mitre=mitre_for(str(extra.get("lines") or ""), rule_id),
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


def _declared_family(value: object) -> IssueFamily | None:
    """Resolve a rule's declared ``bluescrub_family``, if it names a real one."""
    if not value:
        return None
    try:
        return IssueFamily(str(value))
    except ValueError:
        logger.warning("rule declares unknown bluescrub_family %r", value)
        return None


def _rules_config() -> str | None:
    configured = os.getenv("AIPAM_BLUESCRUB_SEMGREP_CONFIG")
    if configured:
        return configured
    if DEFAULT_RULES.exists():
        return str(DEFAULT_RULES)
    return None


def run(source_root: Path, output_dir: Path, *, limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
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

    # Semgrep's built-in ignore list skips tests/, vendor/, and similar by
    # default. That is right for a developer scanning their own service and
    # wrong here: in offensive tooling the test directory is often where the
    # real C2 addresses, operator credentials, and sample payloads live, and
    # skipping it silently is the "looks clean" failure this pipeline exists to
    # avoid. An empty .semgrepignore in the scan root disables the defaults —
    # the operator uploaded the whole artifact to be audited.
    _neutralise_default_ignores(source_root)

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

    findings = parse_output(payload, source_root, config)
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


def _neutralise_default_ignores(source_root: Path) -> None:
    """Write an empty .semgrepignore so nothing in the artifact is skipped.

    Never overwrites one the artifact already carries — that would be editing
    the thing under audit. A supplied .semgrepignore is itself worth knowing
    about, since it tells the scanner what its author wanted unexamined.
    """
    marker = source_root / ".semgrepignore"
    if marker.exists():
        logger.info(
            "artifact ships its own .semgrepignore — leaving it in place; "
            "some paths will not be scanned"
        )
        return
    try:
        marker.write_text("")
    except OSError as exc:  # pragma: no cover - staged tree is writable
        logger.warning("could not neutralise semgrep default ignores: %s", exc)


def _require_drop() -> bool:
    return require_privilege_drop()
