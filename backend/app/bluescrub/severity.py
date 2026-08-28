"""Canonical severity and scoring-confidence resolution.

Raw scanner severity is never used directly. Vocabularies are inconsistent
across tools, and a regex detector asserting CRITICAL must not outrank a
dataflow detector asserting medium.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §2.3–2.4
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.app.bluescrub.models import RawFinding
from backend.app.bluescrub.pillars import SEVERITY_ORDER, detector_rank

#: Scanner vocabularies mapped onto the canonical ladder.
_RAW_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "critical", "crit": "critical", "blocker": "critical",
    "high": "high", "error": "high", "severe": "high", "major": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "minor": "low", "note": "low", "style": "low",
    "info": "info", "informational": "info", "unknown": "info",
}


@dataclass(frozen=True)
class SeverityDecision:
    severity: str
    source: str          # rule_mapping | impact_modifier | precedence | fallback
    rationale: str


def calibrate(raw: str | None) -> str:
    """Map a scanner's own severity string onto the canonical ladder."""
    if not raw:
        return "medium"
    return _RAW_SEVERITY_ALIASES.get(raw.strip().lower(), "medium")


def _clamp_adjacent(base: str, target: str) -> str:
    """Limit an impact modifier to one level of movement from ``base``."""
    bi, ti = SEVERITY_ORDER.index(base), SEVERITY_ORDER.index(target)
    if ti > bi:
        return SEVERITY_ORDER[min(bi + 1, len(SEVERITY_ORDER) - 1)]
    if ti < bi:
        return SEVERITY_ORDER[max(bi - 1, 0)]
    return base


def select_primary(
    members: list[RawFinding],
    optional_sensors: frozenset[str] = frozenset(),
) -> RawFinding:
    """Pick the member that decides severity and scoring confidence.

    Chosen by a fixed precedence table rather than by whichever installed tool
    reports the highest confidence. Optional detectors are excluded from the
    choice entirely: if an optional scanner could become primary, installing it
    would move the score of an unchanged artifact, which is precisely the
    machine-dependence the model exists to prevent. They still corroborate.

    When *every* member is optional the group only exists because an optional
    tool ran, so there is nothing required to defer to and the best optional
    detector decides.
    """
    required = [m for m in members if m.sensor not in optional_sensors]
    candidates = required or members
    return min(
        candidates,
        key=lambda m: (
            detector_rank(m.detector_class),
            -SEVERITY_ORDER.index(calibrate(m.raw_severity)),
            m.sensor,
            m.rule_id,
        ),
    )


def resolve(
    members: list[RawFinding],
    primary: RawFinding,
    *,
    rule_mapping: dict[str, str] | None = None,
    impact_modifier: str | None = None,
) -> SeverityDecision:
    """Resolve canonical severity through the four-tier precedence.

    Args:
        rule_mapping: Explicit canonical severity by ``rule_id`` (tier 1).
        impact_modifier: Contextual override — reachability, secret validity,
            exposure (tier 2). Bounded to one level of movement.
    """
    mapped = (rule_mapping or {}).get(primary.rule_id)

    if mapped:
        if impact_modifier and impact_modifier != mapped:
            adjusted = _clamp_adjacent(mapped, impact_modifier)
            return SeverityDecision(
                adjusted, "impact_modifier",
                f"rule mapping {mapped}, adjusted to {adjusted} by context",
            )
        return SeverityDecision(mapped, "rule_mapping", f"canonical mapping for {primary.rule_id}")

    if impact_modifier:
        return SeverityDecision(impact_modifier, "impact_modifier", "contextual impact assessment")

    if len(members) > 1:
        severity = calibrate(primary.raw_severity)
        return SeverityDecision(
            severity, "precedence",
            f"{primary.detector_class.value if primary.detector_class else 'unclassified'} "
            f"detector {primary.sensor} outranks {len(members) - 1} other detector(s)",
        )

    severity = calibrate(primary.raw_severity)
    return SeverityDecision(severity, "fallback", f"calibrated from {primary.sensor} severity")


def scoring_confidence(primary: RawFinding) -> float:
    """Confidence of the highest-precedence detector.

    Corroboration is recorded as evidence but has no numeric effect in v1;
    letting it raise confidence would make the score depend on which optional
    tools happen to be installed.
    """
    return primary.confidence
