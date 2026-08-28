"""Dependency CVE scanning — OSV-Scanner and Grype.

These close the gap the offline dependency inventory reports as
``database_stale``: it can establish hygiene (unpinned versions, unparseable
manifests) without a network, but not whether a pinned version is vulnerable.

Both tools are run, not one. They draw on different databases — OSV aggregates
upstream advisories, Grype leans on distro and language feeds — and disagree
often enough that treating either as authoritative loses findings. Canonicalization
collapses the overlap, so running both costs a scan and no score inflation.

Reference: docs/BLUESCRUB_SUPPLY_CHAIN.md §1.2
"""

from __future__ import annotations

from pathlib import Path

from backend.app.bluescrub.isolation import ResourceLimits
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.external import ExternalTool, run_external

#: OSV and Grype both use CVSS-ish words; map onto the canonical ladder.
_SEVERITY = {
    "critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM",
    "medium": "MEDIUM", "low": "LOW", "negligible": "LOW",
    "unknown": "MEDIUM", "": "MEDIUM",
}


def _finding(sensor: str, rule_id: str, severity: str, title: str,
             description: str, subject: str, identifier: str) -> RawFinding:
    family = IssueFamily.dependency_vulnerable
    return RawFinding(
        sensor=sensor, sensor_version="external", rule_namespace=sensor,
        rule_id=rule_id, issue_family=family, pillar_hint=FAMILY_PILLAR[family],
        # A CVE lookup is a database match, not a code judgement: authoritative
        # about the advisory, silent about whether the path is reachable here.
        detector_class=DetectorClass.heuristic,
        raw_severity=_SEVERITY.get(severity.lower(), "MEDIUM"),
        confidence=0.85, source_facet="vulnerability",
        title=title, description=description[:4096],
        matched_tokens=identifier[:4096],
        location=Location(kind="project", subject=subject),
    )


# ── OSV-Scanner ───────────────────────────────────────────────────────────

def parse_osv(payload: dict, source_root: Path) -> list[RawFinding]:
    """Parse ``osv-scanner --format json``.

    Shape: results[] -> packages[] -> {package, vulnerabilities[], groups[]}.
    Severity lives on ``groups[].max_severity`` rather than on the vulnerability,
    which is easy to miss — reading it off the vulnerability yields "" for every
    finding and silently flattens the whole report to MEDIUM.
    """
    findings: list[RawFinding] = []

    for result in payload.get("results") or []:
        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            if not name:
                continue
            subject = f"{name}@{version}" if version else name

            worst = ""
            for group in entry.get("groups") or []:
                worst = str(group.get("max_severity") or worst)

            for vuln in entry.get("vulnerabilities") or []:
                ident = str(vuln.get("id") or "")
                if not ident:
                    continue
                aliases = ", ".join(str(a) for a in (vuln.get("aliases") or [])[:4])
                summary = str(vuln.get("summary") or vuln.get("details") or "")
                findings.append(_finding(
                    sensor="osv", rule_id=f"osv.{ident}",
                    severity=_osv_severity(vuln, worst),
                    title=f"{ident}: {name}",
                    description=(summary or f"{subject} is affected by {ident}.")
                                + (f" Aliases: {aliases}." if aliases else ""),
                    subject=subject, identifier=ident,
                ))

    return findings


def _osv_severity(vuln: dict, group_max: str) -> str:
    """Prefer an explicit database severity, then the group's CVSS score."""
    for entry in vuln.get("severity") or []:
        if entry.get("type", "").upper().startswith("CVSS"):
            return _cvss_band(str(entry.get("score") or ""))
    db = (vuln.get("database_specific") or {}).get("severity")
    if db:
        return str(db)
    return _cvss_band(group_max) if group_max else "MEDIUM"


def _cvss_band(score: str) -> str:
    """A CVSS vector string is not a number; only band an actual score."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


OSV = ExternalTool(
    sensor="osv",
    binary="osv-scanner",
    argv=lambda root: ["--format", "json", "--recursive", str(root)],
    parse=parse_osv,
    # osv-scanner exits 1 when it finds vulnerabilities.
    finding_exit_codes=(0, 1),
    version_argv=("--version",),
    limits=ResourceLimits(wall_clock_seconds=600, cpu_seconds=600),
)


# ── Grype ─────────────────────────────────────────────────────────────────

def parse_grype(payload: dict, source_root: Path) -> list[RawFinding]:
    """Parse ``grype -o json``.

    Shape: matches[] -> {vulnerability, artifact, relatedVulnerabilities}.
    """
    findings: list[RawFinding] = []

    for match in payload.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        ident = str(vuln.get("id") or "")
        name = str(artifact.get("name") or "")
        if not ident or not name:
            continue
        version = str(artifact.get("version") or "")
        subject = f"{name}@{version}" if version else name

        fix = (vuln.get("fix") or {}).get("versions") or []
        remedy = f" Fixed in {', '.join(str(v) for v in fix[:3])}." if fix else ""

        findings.append(_finding(
            sensor="grype", rule_id=f"grype.{ident}",
            severity=str(vuln.get("severity") or ""),
            title=f"{ident}: {name}",
            description=(str(vuln.get("description") or
                             f"{subject} is affected by {ident}.") + remedy),
            subject=subject, identifier=ident,
        ))

    return findings


GRYPE = ExternalTool(
    sensor="grype",
    binary="grype",
    argv=lambda root: ["-o", "json", "--quiet", f"dir:{root}"],
    parse=parse_grype,
    finding_exit_codes=(0, 1),
    version_argv=("version", "-o", "text"),
    limits=ResourceLimits(wall_clock_seconds=600, cpu_seconds=600),
)


def run_osv(source_root: Path, output_dir: Path, **_kw):
    return run_external(OSV, source_root, output_dir)


def run_grype(source_root: Path, output_dir: Path, **_kw):
    return run_external(GRYPE, source_root, output_dir)
