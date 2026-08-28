"""Shared scanner adapter contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from backend.app.bluescrub.isolation import ResourceLimits
from backend.app.bluescrub.models import RawFinding
from backend.app.bluescrub.pillars import Pillar, RiskClass


@dataclass
class ScannerOutcome:
    """What one scanner produced, and how it ended."""

    sensor: str
    status: str
    findings: list[RawFinding] = field(default_factory=list)
    version: str | None = None
    ruleset_version: str | None = None
    ruleset_state: str | None = None
    duration_ms: int = 0
    reason: str | None = None


class ScannerRunner(Protocol):
    def __call__(self, source_root: Path, output_dir: Path) -> ScannerOutcome: ...


@dataclass(frozen=True)
class ScannerSpec:
    """Registry entry. Mirrors ``SensorDef`` so the two stay conceptually aligned."""

    name: str
    run: Callable[..., ScannerOutcome]
    pillars: tuple[Pillar, ...]
    risk_class: RiskClass
    profiles: tuple[str, ...] = ("triage", "standard", "deep")
    #: Optional scanners corroborate only. Their absence must never change a
    #: score or a coverage value — see docs/BLUESCRUB_SCORING_SPEC.md §5.
    optional: bool = False
    #: Run order, low first, name breaking ties so the sequence stays
    #: deterministic. Almost every scanner is independent and keeps the
    #: default; the exception is a scanner whose output another one consumes.
    #: FLOSS recovers strings that the dirty-word and build-path scanners then
    #: read, and `floss` sorts *after* both alphabetically — leaving that to
    #: the accident of a name would make the dependency invisible and one
    #: rename away from silently breaking.
    order: int = 100
    limits: ResourceLimits = field(default_factory=ResourceLimits)
