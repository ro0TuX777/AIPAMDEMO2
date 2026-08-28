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

from backend.app.bluescrub.enrich import autofix_for, mitre_for
from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.rulemap import normalize_label, resolve_family
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "bluescrub_analyzers"

#: Pattern analyzers: BaseAnalyzer subclasses returning a flat finding list.
ANALYZERS: tuple[str, ...] = (
    "OpsecAnalyzer",
    "ExploitationToolAnalyzer",
    "SecretsAnalyzer",
    "InformationDisclosureAnalyzer",
    "MemorySafetyAnalyzer",
    "CryptoVulnerabilityAnalyzer",
    "SupplyChainAnalyzer",
)

#: Specialised scanners: module-level directory functions returning one record
#: per file, keyed by category, rather than a flat list. They are *not*
#: BaseAnalyzer subclasses despite upstream's README describing all ten as such
#: — only the seven above are. Hence two normalisation paths.
SPECIALISED: tuple[tuple[str, str], ...] = (
    ("ExploitReliabilityAnalyzer", "analyze_directory_for_exploits"),
    ("MetadataLeakageScanner", "analyze_directory_for_metadata"),
    ("NetworkTrafficAnalyzer", "analyze_directory_for_network"),
    ("ForensicArtifactDetector", "analyze_directory_for_artifacts"),
    ("PayloadObfuscationAnalyzer", "analyze_directory_for_payloads"),
    ("PrivilegeEscalationAnalyzer", "analyze_directory_for_privesc"),
    ("ShellcodeSecurityScanner", "scan_directory_for_shellcode"),
    ("CodeSimilarityDetector", "analyze_directory_for_attribution"),
    ("AntiAnalysisValidator", "analyze_directory_for_anti_analysis"),
)

_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
             "LOW": "LOW", "INFO": "INFO"}

#: Item fields that carry the matched text, in preference order.
_MATCH_KEYS = ("technique", "pattern", "path", "contact", "indicator",
               "reference", "signature", "match", "value", "issue")

#: Vendored category labels that reuse AIPAM's network vocabulary for what are
#: actually source-code patterns. AIPAM's `beaconing` sensor reports beaconing
#: observed in traffic; this reports a hardcoded sleep interval in a file. Left
#: side-by-side in a findings list the two are indistinguishable, so the title
#: says which kind of evidence it is.
_AMBIGUOUS_WITH_NETWORK_DOMAIN = {
    "beacon_patterns": "hardcoded beacon interval in source",
    "dns_patterns": "DNS pattern in source",
    "c2_references": "C2 reference in source",
    "network_indicators": "network indicator in source",
    "http_headers": "HTTP header set in source",
    "tls_issues": "TLS usage in source",
    "protocol_fingerprints": "protocol fingerprint in source",
    "unencrypted_traffic": "unencrypted transport in source",
}


def _disambiguate(category: str, title: str) -> str:
    """Prefix titles whose wording collides with AIPAM's network findings."""
    hint = _AMBIGUOUS_WITH_NETWORK_DOMAIN.get(category)
    return f"{title} ({hint})" if hint else title


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
            mitre=mitre_for(str(item.get("match") or ""), label),
            matched_tokens=str(item.get("match") or item.get("pattern") or "")[:4096],
            location=Location(
                kind="source", file=rel,
                start_line=int(line) if isinstance(line, int) else None,
                start_column=0,
            ),
        ))

    return findings


def _relative(raw_path: str, source_root: Path) -> str:
    try:
        return str(Path(raw_path).resolve().relative_to(source_root.resolve()))
    except (ValueError, OSError):
        return raw_path


def specialised_to_raw_findings(
    analyzer: str, records: list[dict], source_root: Path
) -> list[RawFinding]:
    """Normalise a specialised scanner's per-file records.

    Each record is ``{file, <category>: {found, <items>, count, risk, ...}}``
    where the item-list key varies by category. Scalar summary fields
    (``entropy``, ``detection_risk``, ``obfuscation_score``) are not findings
    and are skipped by construction: they are not dicts.
    """
    findings: list[RawFinding] = []

    for record in records:
        if not isinstance(record, dict):
            continue
        rel = _relative(str(record.get("file") or ""), source_root)

        for category, payload in record.items():
            if not isinstance(payload, dict) or not payload.get("found"):
                continue

            items = next(
                (v for k, v in payload.items()
                 if isinstance(v, list) and k not in ("count", "risk")),
                [],
            )
            category_risk = str(payload.get("risk") or "MEDIUM").upper()
            explanation = str(payload.get("explanation") or category)

            for item in items:
                if not isinstance(item, dict):
                    continue
                family = resolve_family(SENSOR, normalize_label(category))
                subtype = normalize_label(str(item.get("type") or ""))
                rule_id = f"{analyzer}.{category}" + (f".{subtype}" if subtype else "")

                matched = next(
                    (str(item[k]) for k in _MATCH_KEYS if item.get(k)), ""
                )
                if not matched.strip():
                    # 159 findings on a real 300-file codebase carried no
                    # matched text at all. A finding that cannot show what it
                    # matched is not reviewable, and it still consumed a slot
                    # in the score.
                    continue
                severity = str(
                    item.get("risk") or item.get("effectiveness") or category_risk
                ).upper()
                line = item.get("line")

                findings.append(RawFinding(
                    sensor=SENSOR,
                    sensor_version="vendored",
                    rule_namespace=analyzer,
                    rule_id=rule_id,
                    issue_family=family,
                    pillar_hint=FAMILY_PILLAR.get(family),
                    detector_class=DetectorClass.regex_pattern,
                    raw_severity=_SEVERITY.get(severity, "MEDIUM"),
                    confidence=0.6,
                    source_facet="source",
                    title=_disambiguate(
                        category, str(item.get("type") or category.replace("_", " "))
                    ),
                    description=str(item.get("explanation") or explanation)[:4096],
                    mitre=mitre_for(matched, str(item.get("type") or ""), category),
                    matched_tokens=matched[:4096],
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

    targets = [("pattern", a, a) for a in ANALYZERS] + [
        ("specialised", cls, fn) for cls, fn in SPECIALISED
    ]

    for mode, analyzer, entry in targets:
        result = run_analyzer(
            [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
             entry, str(source_root), mode],
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

        produced = payload.get("findings") or []
        findings.extend(
            to_raw_findings(analyzer, produced, source_root) if mode == "pattern"
            else specialised_to_raw_findings(analyzer, produced, source_root)
        )

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
