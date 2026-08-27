"""Scanner registry and profile gating.

Mirrors ``sensors/registry.py`` in shape so the two stay conceptually aligned.
Profiles use AIPAM's literals (``triage`` / ``standard`` / ``deep``); the UI
shows BlueScrub's labels (Quick / Standard / Deep) over the same values.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §5.8
"""

from __future__ import annotations

from backend.app.bluescrub.isolation import ResourceLimits
from backend.app.bluescrub.pillars import Pillar, RiskClass
from backend.app.bluescrub.scanners import (
    binary_analysis,
    dependencies,
    semgrep,
    vendored_analyzers,
)
from backend.app.bluescrub.scanners.base import ScannerSpec

#: Which pillars each profile attempts. A pillar outside this set is
#: ``not_assessed`` — never scored zero.
PROFILE_PILLARS: dict[str, tuple[Pillar, ...]] = {
    "triage": (Pillar.vulnerability,),
    "standard": (Pillar.vulnerability, Pillar.co_optability),
    "deep": (
        Pillar.vulnerability, Pillar.co_optability,
        Pillar.attribution, Pillar.detectability, Pillar.re_feasibility,
    ),
}

SCANNERS: dict[str, ScannerSpec] = {
    "bluescrub_analyzers": ScannerSpec(
        name="bluescrub_analyzers",
        run=vendored_analyzers.run,
        pillars=(
            Pillar.vulnerability, Pillar.attribution,
            Pillar.co_optability, Pillar.detectability,
        ),
        risk_class=RiskClass.parse_only,
        profiles=("triage", "standard", "deep"),
        optional=False,
        limits=ResourceLimits(),
    ),
    "binary_analyzer": ScannerSpec(
        name="binary_analyzer",
        run=binary_analysis.run,
        pillars=(Pillar.detectability, Pillar.re_feasibility),
        risk_class=RiskClass.emulation,
        profiles=("deep",),
        optional=False,
        limits=ResourceLimits.for_emulation(),
    ),
    "dependency_inventory": ScannerSpec(
        name="dependency_inventory",
        run=dependencies.run,
        pillars=(Pillar.co_optability,),
        risk_class=RiskClass.parse_only,
        profiles=("standard", "deep"),
        optional=False,
        limits=ResourceLimits(),
    ),
    "semgrep": ScannerSpec(
        name="semgrep",
        run=semgrep.run,
        pillars=(Pillar.vulnerability, Pillar.co_optability),
        risk_class=RiskClass.parse_only,
        profiles=("triage", "standard", "deep"),
        optional=False,
        limits=ResourceLimits(),
    ),
}


def scanners_for(profile: str) -> list[ScannerSpec]:
    """Scanners enabled for a profile, in deterministic order."""
    return [
        spec for name, spec in sorted(SCANNERS.items())
        if profile in spec.profiles
    ]


def optional_sensors() -> frozenset[str]:
    """Sensors that corroborate only.

    Canonicalization needs this so an optional detector can never become the
    primary and move a score by being installed.
    """
    return frozenset(name for name, spec in SCANNERS.items() if spec.optional)


def required_for(pillar: Pillar, profile: str) -> list[str]:
    """Non-optional scanners a pillar depends on under a profile."""
    return [
        spec.name for spec in scanners_for(profile)
        if pillar in spec.pillars and not spec.optional
    ]


def pillars_in_scope(profile: str) -> tuple[Pillar, ...]:
    return PROFILE_PILLARS.get(profile, PROFILE_PILLARS["standard"])
