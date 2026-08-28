"""Internal dataclasses for the raw → canonical pipeline.

These mirror the JSON Schemas in ``contracts/`` exactly; ``to_dict`` output is
validated against them in the tests, so the schemas are enforced rather than
merely documented.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §1–§2
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar

LocationKind = Literal["source", "binary", "project"]


def _prune(data: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None, so optional fields stay absent."""
    return {k: v for k, v in data.items() if v is not None}


@dataclass
class Location:
    kind: LocationKind
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    symbol: str | None = None
    node_kind: str | None = None
    artifact_sha256: str | None = None
    format: str | None = None
    architecture: str | None = None
    section: str | None = None
    offset: int | None = None
    function_fingerprint: str | None = None
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _prune(self.__dict__)

    @property
    def sort_key(self) -> tuple:
        """Deterministic ordering key. Grouping must not depend on scan order."""
        return (
            self.file or "",
            self.artifact_sha256 or "",
            self.section or "",
            self.start_line if self.start_line is not None else -1,
            self.start_column if self.start_column is not None else -1,
            self.offset if self.offset is not None else -1,
            self.subject or "",
        )


@dataclass
class Observable:
    type: str
    value: str
    origin: str
    normalized: str | None = None
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return _prune(self.__dict__)


@dataclass
class SecretRef:
    """Never carries plaintext. See docs/BLUESCRUB_DATA_HANDLING_POLICY.md §3."""

    secret_type: str
    masked_value: str
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class RawFinding:
    """One scanner hit, normalised. Carries no scoring decision."""

    sensor: str
    sensor_version: str
    rule_id: str
    issue_family: IssueFamily
    confidence: float
    location: Location

    schema: str = "bluescrub.raw/1"
    ruleset_version: str | None = None
    rule_namespace: str | None = None
    rule_version: str | None = None
    detector_class: DetectorClass | None = None
    raw_severity: str | None = None
    pillar_hint: Pillar | None = None
    source_facet: str | None = None
    matched_tokens: str | None = None
    context_hash: str | None = None
    title: str | None = None
    description: str | None = None
    recommendation: str | None = None
    cwe: list[str] = field(default_factory=list)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    observables: list[Observable] = field(default_factory=list)
    typed_evidence: list[dict[str, str]] = field(default_factory=list)
    secret: SecretRef | None = None
    fp_filters_applied: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema": self.schema,
            "sensor": self.sensor,
            "sensor_version": self.sensor_version,
            "ruleset_version": self.ruleset_version,
            "rule_namespace": self.rule_namespace,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "detector_class": self.detector_class.value if self.detector_class else None,
            "raw_severity": self.raw_severity,
            "issue_family": self.issue_family.value,
            "pillar_hint": self.pillar_hint.value if self.pillar_hint else None,
            "source_facet": self.source_facet,
            "location": self.location.to_dict(),
            "matched_tokens": self.matched_tokens,
            "context_hash": self.context_hash,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "mitre": self.mitre,
            "observables": [o.to_dict() for o in self.observables],
            "typed_evidence": self.typed_evidence,
            "secret": self.secret.to_dict() if self.secret else None,
            "confidence": self.confidence,
            "fp_filters_applied": self.fp_filters_applied,
            "truncated": self.truncated,
        }
        # pillar_hint is explicitly nullable for unmapped rules, so it stays.
        pruned = _prune(data)
        if self.pillar_hint is None:
            pruned["pillar_hint"] = None
        return pruned

    @property
    def sort_key(self) -> tuple:
        return (*self.location.sort_key, self.sensor, self.rule_id)


@dataclass
class CanonicalGroup:
    """The unit of scoring and persistence. One ``Finding`` row per group."""

    canonical_id: str
    issue_family: IssueFamily
    pillar: Pillar
    severity: str
    severity_source: str
    scoring_confidence: float
    primary_sensor: str
    primary_rule_id: str
    occurrence_index: int
    members: list[RawFinding]
    location: Location

    schema: str = "bluescrub.canon/1"
    fingerprint_scheme: str = "fp/2"
    related_pillars: list[Pillar] = field(default_factory=list)
    severity_rationale: str | None = None
    primary_detector_class: DetectorClass | None = None
    scored: bool = True
    score_contribution: float | None = None
    capped_by: str | None = None

    @property
    def corroborating(self) -> list[RawFinding]:
        """Members other than the one that decided severity and confidence."""
        return [
            m for m in self.members
            if not (m.sensor == self.primary_sensor and m.rule_id == self.primary_rule_id)
        ]

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema": self.schema,
            "canonical_id": self.canonical_id,
            "fingerprint_scheme": self.fingerprint_scheme,
            "issue_family": self.issue_family.value,
            "pillar": self.pillar.value,
            "related_pillars": [p.value for p in self.related_pillars],
            "severity": self.severity,
            "severity_source": self.severity_source,
            "severity_rationale": self.severity_rationale,
            "scoring_confidence": self.scoring_confidence,
            "primary_sensor": self.primary_sensor,
            "primary_rule_id": self.primary_rule_id,
            "primary_detector_class": (
                self.primary_detector_class.value if self.primary_detector_class else None
            ),
            "corroborating_sensors": [
                _prune({
                    "sensor": m.sensor,
                    "rule_id": m.rule_id,
                    "detector_class": m.detector_class.value if m.detector_class else None,
                    "confidence": m.confidence,
                })
                for m in self.corroborating
            ],
            "occurrence_index": self.occurrence_index,
            "location": self.location.to_dict(),
            "members": [
                _prune({
                    "sensor": m.sensor,
                    "rule_id": m.rule_id,
                    "raw_severity": m.raw_severity,
                    "confidence": m.confidence,
                })
                for m in self.members
            ],
            "scored": self.scored,
            "score_contribution": self.score_contribution,
            "capped_by": self.capped_by,
        }
        pruned = _prune(data)
        # Both are explicitly nullable and meaningful when null.
        pruned["score_contribution"] = self.score_contribution
        pruned["capped_by"] = self.capped_by
        return pruned
