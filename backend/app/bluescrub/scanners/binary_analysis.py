"""Vendored PE/ELF/Mach-O analysis.

Upstream guards every parsing library behind an ``*_AVAILABLE`` flag, so a
deployment missing ``pefile`` or ``pyelftools`` gets an analyzer that returns
nothing and looks exactly like a clean binary. This adapter refuses to present
that as a result: if the capabilities needed for the artifacts present are
absent, the scanner reports ``unavailable`` and the pillar degrades.

Reference: docs/BLUESCRUB_SUPPLY_CHAIN.md §2, §3
"""

from __future__ import annotations

from backend.app.pipeline.outcomes import PROPAGATE_ERRORS, public_failure

import json
import logging
import os
import re
import sys
from pathlib import Path

from backend.app.bluescrub.enrich import mitre_for
from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass
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
    except PROPAGATE_ERRORS:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("binary analyzer capability probe failed: %s", public_failure(exc))
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

        # The record is nested, and reading it flat cost every binary finding
        # its digest, its format and its offset — which the contract needs and
        # which an analyst needs to seek to. None of it showed while the
        # scanner reported `unavailable` for want of pefile and pyelftools.
        hashes = record.get("hashes") if isinstance(record.get("hashes"), dict) else {}
        sha256 = str(hashes.get("sha256") or record.get("sha256") or "") or None

        file_type = record.get("file_type") if isinstance(record.get("file_type"), dict) else {}
        fmt = _normalise_format(
            file_type.get("type") or record.get("format") or record.get("type") or ""
        )

        info = next(
            (record[key] for key in ("elf_info", "pe_info", "macho_info")
             if isinstance(record.get(key), dict)), {}
        )
        arch = str(
            info.get("machine") or record.get("architecture") or record.get("arch") or ""
        ) or None

        # The issue records carry a description and an offset; the values they
        # describe live in a sibling list. Correlating on offset recovers the
        # evidence without parsing English out of the description.
        by_offset = {
            _offset(entry.get("offset")): str(entry.get("value") or "")
            for entry in record.get("suspicious_strings") or []
            if isinstance(entry, dict) and entry.get("value")
        }

        for issue in record.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            label = str(issue.get("type") or issue.get("category") or "")
            if not label:
                continue

            family = resolve_family(SENSOR, normalize_label(label))
            description = str(issue.get("description") or label)
            offset = _offset(issue.get("offset"))
            matched = str(issue.get("match") or issue.get("api") or issue.get("value") or "")
            if not matched:
                matched = by_offset.get(offset, "")
            if not matched:
                # The offset moves on every rebuild, so it must not reach the
                # fingerprint through the evidence field.
                matched = _OFFSET_SUFFIX.sub("", description).strip()

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
                    offset=offset,
                ),
            ))

    return [f for f in findings if _has_valid_location(f)]


_SHA256 = re.compile(r"^[a-f0-9]{64}$")
#: Upstream appends " (at offset 0x…)" to several descriptions. It changes on
#: every rebuild, and the description reaches the evidence field.
_OFFSET_SUFFIX = re.compile(r"\s*\(at offset 0x[0-9a-fA-F]+\)\s*$")


#: Upstream describes the container in prose — "ELF Executable (Linux/Unix)" —
#: while `binstrings` reports a token. `binary_fingerprint` keys on this field,
#: so two scanners describing one artifact differently produce two fingerprints
#: and never group: the same address gets counted twice instead of once with a
#: corroborating sensor.
_FORMAT_TOKENS: tuple[tuple[str, str], ...] = (
    ("elf", "elf"), ("mach-o", "macho"), ("macho", "macho"),
    ("pe32", "pe"), ("portable executable", "pe"), ("ms-dos", "pe"),
    ("wasm", "wasm"), ("java", "class"), ("archive", "ar"),
)


def _normalise_format(value: object) -> str | None:
    """Map a container description onto the token `binstrings` reports."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    for needle, token in _FORMAT_TOKENS:
        if needle in text:
            return token
    # An unrecognised description is still better evidence than nothing, but it
    # is truncated to the contract's ceiling.
    return text[:32]


def _offset(value: object) -> int | None:
    """Parse an offset that upstream reports as ``"0x1111"`` as often as ``4369``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    return None


def _has_valid_location(finding: RawFinding) -> bool:
    """A binary location without the artifact digest is rejected by the
    contract, and nothing validates raw findings in production."""
    if finding.location.kind != "binary":
        return True
    if _SHA256.match(finding.location.artifact_sha256 or ""):
        return True
    logger.warning(
        "%s: dropping %s — the record carried no artifact digest",
        SENSOR, finding.rule_id,
    )
    return False


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
