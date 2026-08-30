"""SBOM generation — Syft.

Syft produces an inventory, not findings, so it emits almost nothing on its own.
It earns its place two ways: the SBOM is a report deliverable in its own right,
and an inventory that disagrees with the manifest-based one is a supply-chain
signal — a package present in the tree but absent from any manifest is either
vendored without record or introduced outside the declared dependency set.

Reference: docs/BLUESCRUB_SUPPLY_CHAIN.md
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from backend.app.bluescrub.isolation import ResourceLimits
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.external import ExternalTool, run_external

logger = logging.getLogger(__name__)

SENSOR = "syft"

#: Ecosystems whose packages are normally declared in a manifest. A package
#: found outside one of these is not necessarily undeclared — a bare .so has no
#: manifest to be absent from — so the undeclared check only applies here.
_MANIFEST_ECOSYSTEMS = frozenset({
    "python", "javascript", "npm", "go", "rust", "java", "ruby", "php", "dotnet",
})


def parse_syft(payload: dict, source_root: Path) -> list[RawFinding]:
    """Parse ``syft -o syft-json``.

    Emits a finding only for a package with no locations tying it to a
    manifest. Emitting one per package would bury the report in inventory.
    """
    findings: list[RawFinding] = []

    for artifact in payload.get("artifacts") or []:
        name = str(artifact.get("name") or "")
        if not name:
            continue
        ecosystem = str(artifact.get("type") or artifact.get("language") or "").lower()
        if ecosystem not in _MANIFEST_ECOSYSTEMS:
            continue

        locations = artifact.get("locations") or []
        paths = [str(loc.get("path") or "") for loc in locations]
        if any(_looks_like_manifest(p) for p in paths):
            continue

        version = str(artifact.get("version") or "")
        subject = f"{name}@{version}" if version else name
        family = IssueFamily.dependency_confusion
        findings.append(RawFinding(
            sensor=SENSOR, sensor_version="external", rule_namespace=SENSOR,
            rule_id="syft.undeclared_package", issue_family=family,
            pillar_hint=FAMILY_PILLAR[family], detector_class=DetectorClass.heuristic,
            raw_severity="MEDIUM", confidence=0.6, source_facet="vulnerability",
            title="Package present but not declared in any manifest",
            description=_undeclared_description(subject, paths)[:4096],
            matched_tokens=subject,
            location=Location(kind="project", subject=subject),
        ))

    return findings


def _undeclared_description(subject: str, paths: list[str]) -> str:
    where = ", ".join(p for p in paths[:2] if p) or "an unrecorded location"
    return (
        f"{subject} was found in the tree at {where}, but no dependency manifest "
        "declares it. Either it was vendored without record, or it entered "
        "outside the declared dependency set — both mean the manifest does not "
        "describe what actually ships."
    )


def _looks_like_manifest(path: str) -> bool:
    lowered = path.lower()
    return any(
        marker in lowered
        for marker in (
            "requirements", "pyproject.toml", "setup.py", "pipfile", "poetry.lock",
            "package.json", "package-lock", "yarn.lock", "pnpm-lock",
            "go.mod", "go.sum", "cargo.toml", "cargo.lock",
            "pom.xml", "build.gradle", "gemfile", "composer.json", ".csproj",
        )
    )


def write_sbom(payload: dict, report_dir: Path) -> Path | None:
    """Persist the SBOM as a report artifact. Returns the path written."""
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        target = report_dir / "sbom.syft.json"
        target.write_text(json.dumps(payload, indent=1, sort_keys=True))
        return target
    except OSError as exc:  # pragma: no cover - report dir is writable
        logger.warning("could not write SBOM: %s", exc)
        return None


SYFT = ExternalTool(
    sensor=SENSOR,
    binary="syft",
    argv=lambda root: ["scan", f"dir:{root}", "-o", "syft-json", "-q"],
    parse=parse_syft,
    version_argv=("version", "-o", "text"),
    # Go binary: a Go runtime reserves a large virtual arena at startup, so
    # RLIMIT_AS bounds something unrelated to what it uses and kills it at
    # any value. See ResourceLimits.for_external_tool.
    limits=ResourceLimits.for_external_tool(),
)


def run_syft(source_root: Path, output_dir: Path, **_kw):
    return run_external(SYFT, source_root, output_dir)
