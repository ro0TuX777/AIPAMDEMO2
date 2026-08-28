"""Coverage-aware DACV+R scoring.

Two models coexist. Detectability, Attribution, Co-Optability and Vulnerability
accumulate canonical findings and saturate; RE-Feasibility measures a fixed set
of signals on one artifact. The plan read as though one formula covered all
five, which would have left an implementer guessing.

The invariant the whole design protects: installing or removing an *optional*
scanner must not change any score, coverage value, or grade for an unchanged
artifact.

Reference: docs/BLUESCRUB_SCORING_SPEC.md
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.app.bluescrub import CANONICALIZATION_VERSION, FINGERPRINT_SCHEME, SCORING_MODEL
from backend.app.bluescrub.models import CanonicalGroup
from backend.app.bluescrub.pillars import (
    ACCUMULATION_PILLARS,
    CALIBRATION_STATE,
    COVERAGE_THRESHOLD,
    FAMILY_CAP_FRACTION,
    GRADE_BANDS,
    INFO_CAP_FRACTION,
    K_P,
    PILLAR_WEIGHT,
    RULE_CAP_FULL_WEIGHT,
    SEV_WEIGHT,
    Pillar,
    PillarStatus,
)

#: RE-Feasibility signal weights. Fixed — never redistributed when a signal is
#: unavailable, because redistribution makes the same binary score differently
#: depending on how the host was provisioned.
RE_SIGNAL_WEIGHTS: dict[str, float] = {
    "symbols": 0.20,
    "packing": 0.15,
    "string_yield": 0.15,
    "anti_analysis": 0.15,
    "decompilation": 0.15,
    "runtime_language": 0.10,
    "import_table": 0.05,
    "config_exposure": 0.05,
}

EFFORT_BANDS: tuple[tuple[int, str], ...] = (
    (25, "Weeks"), (50, "Days"), (75, "Hours"), (100, "Trivial"),
)


@dataclass
class ScannerRun:
    """One scanner's outcome, as reported by the isolation runner."""

    sensor: str
    status: str
    required_for: tuple[Pillar, ...] = ()
    optional: bool = False
    version: str | None = None
    ruleset_version: str | None = None
    ruleset_state: str | None = None
    duration_ms: int | None = None
    reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status in ("completed", "completed_truncated")

    @property
    def truncated(self) -> bool:
        return self.status == "completed_truncated"


@dataclass
class ReSignal:
    signal: str
    normalized: float | None      # None when the signal could not be measured
    reason: str | None = None


@dataclass
class PillarResult:
    status: PillarStatus
    score: int | None
    coverage: float
    findings: int
    raw: float | None = None
    reason: str | None = None
    top_driver: dict[str, Any] | None = None
    unavailable_signals: list[dict[str, Any]] = field(default_factory=list)
    effort_band: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": self.status.value,
            "score": self.score,
            "coverage": round(self.coverage, 4),
            "findings": self.findings,
        }
        if self.raw is not None:
            data["raw"] = round(self.raw, 4)
        if self.reason:
            data["reason"] = self.reason
        if self.top_driver:
            data["top_driver"] = self.top_driver
        if self.unavailable_signals:
            data["unavailable_signals"] = self.unavailable_signals
        if self.effort_band:
            data["effort_band"] = self.effort_band
        return data


def _band(score: int, bands: Iterable[tuple[int, str]]) -> str:
    for upper, label in bands:
        if score <= upper:
            return label
    return bands[-1][1]  # pragma: no cover - bands always terminate at 100


def apply_caps(groups: list[CanonicalGroup]) -> tuple[float, dict[str, int]]:
    """Sum contributions with per-rule, per-family, and info caps applied.

    Volume must not substitute for severity, and one noisy rule must not own a
    pillar. Every capped group records why, so the scorecard never discards
    evidence silently.
    """
    caps = {"rule_cap": 0, "family_cap": 0, "info_cap": 0}
    scored = [g for g in groups if g.scored]

    by_rule: dict[str, list[CanonicalGroup]] = defaultdict(list)
    for group in scored:
        by_rule[group.primary_rule_id].append(group)

    for rule_groups in by_rule.values():
        rule_groups.sort(
            key=lambda g: SEV_WEIGHT[g.severity] * g.scoring_confidence, reverse=True
        )
        for position, group in enumerate(rule_groups, start=1):
            base = SEV_WEIGHT[group.severity] * group.scoring_confidence
            if position <= RULE_CAP_FULL_WEIGHT:
                group.score_contribution = base
            else:
                group.score_contribution = base / (1 + math.log(position - RULE_CAP_FULL_WEIGHT + 1))
                group.capped_by = "rule_cap"
                caps["rule_cap"] += 1

    total = sum(g.score_contribution or 0.0 for g in scored)
    if total <= 0:
        return 0.0, caps

    # Family cap
    by_family: dict[str, list[CanonicalGroup]] = defaultdict(list)
    for group in scored:
        by_family[group.issue_family.value].append(group)
    for family_groups in by_family.values():
        family_total = sum(g.score_contribution or 0.0 for g in family_groups)
        ceiling = total * FAMILY_CAP_FRACTION
        if family_total > ceiling and family_total > 0:
            scale = ceiling / family_total
            for group in family_groups:
                group.score_contribution = (group.score_contribution or 0.0) * scale
                group.capped_by = group.capped_by or "family_cap"
                caps["family_cap"] += 1

    # Info cap — retained rather than dropped, because the dirty-word category
    # ladder legitimately uses info for weak-but-real signal.
    total = sum(g.score_contribution or 0.0 for g in scored)
    info_groups = [g for g in scored if g.severity == "info"]
    info_total = sum(g.score_contribution or 0.0 for g in info_groups)
    ceiling = total * INFO_CAP_FRACTION
    if info_total > ceiling and info_total > 0:
        scale = ceiling / info_total
        for group in info_groups:
            group.score_contribution = (group.score_contribution or 0.0) * scale
            group.capped_by = group.capped_by or "info_cap"
            caps["info_cap"] += 1

    return sum(g.score_contribution or 0.0 for g in scored), caps


def coverage_for(pillar: Pillar, runs: list[ScannerRun]) -> tuple[float, bool, list[str]]:
    """Return (coverage, any_truncated, missing sensor names) for a pillar.

    Optional scanners are excluded deliberately: coverage must not move when an
    optional tool is installed, for the same reason the score must not.
    """
    required = [r for r in runs if pillar in r.required_for and not r.optional]
    if not required:
        return 0.0, False, []
    ok = [r for r in required if r.succeeded]
    missing = [r.sensor for r in required if not r.succeeded]
    truncated = any(r.truncated for r in ok) or any(
        r.ruleset_state in ("rules_stale", "database_stale") for r in ok
    )
    return len(ok) / len(required), truncated, missing


def score_accumulation_pillar(
    pillar: Pillar, groups: list[CanonicalGroup], runs: list[ScannerRun]
) -> PillarResult:
    coverage, degraded_flag, missing = coverage_for(pillar, runs)
    mine = [g for g in groups if g.pillar is pillar]

    if coverage == 0.0:
        reason = (
            f"required detectors unavailable: {', '.join(missing)}" if missing
            else "profile_excludes"
        )
        # score stays None. Zero would mean "measured, nothing found".
        return PillarResult(
            status=PillarStatus.not_assessed, score=None, coverage=0.0,
            findings=len(mine), reason=reason,
        )

    raw, _caps = apply_caps(mine)
    score = round(100 * (1 - math.exp(-raw / K_P[pillar])))

    top = max(
        (g for g in mine if g.scored and g.score_contribution),
        key=lambda g: g.score_contribution or 0.0,
        default=None,
    )
    status = (
        PillarStatus.assessed
        if coverage >= 1.0 and not degraded_flag
        else PillarStatus.degraded
    )
    return PillarResult(
        status=status, score=score, coverage=coverage, findings=len(mine), raw=raw,
        top_driver=(
            {
                "finding_id": top.canonical_id,
                "rule_id": top.primary_rule_id,
                "contribution": round(top.score_contribution or 0.0, 4),
            }
            if top else None
        ),
        reason=f"missing: {', '.join(missing)}" if missing else None,
    )


def score_re_pillar(
    signals: list[ReSignal], groups: list[CanonicalGroup]
) -> PillarResult:
    """Weighted-signal model. Weights are reported when absent, never reassigned."""
    mine = [g for g in groups if g.pillar is Pillar.re_feasibility]
    measured = [s for s in signals if s.normalized is not None]
    unavailable = [
        {
            "signal": s.signal,
            "weight": RE_SIGNAL_WEIGHTS.get(s.signal, 0.0),
            "reason": s.reason or "unavailable",
        }
        for s in signals if s.normalized is None
    ]

    if not measured:
        return PillarResult(
            status=PillarStatus.not_assessed, score=None, coverage=0.0,
            findings=len(mine), reason="no RE signals measured",
            unavailable_signals=unavailable,
        )

    available_weight = sum(RE_SIGNAL_WEIGHTS.get(s.signal, 0.0) for s in measured)
    if available_weight <= 0:
        return PillarResult(
            status=PillarStatus.not_assessed, score=None, coverage=0.0,
            findings=len(mine), reason="signals carry no weight",
            unavailable_signals=unavailable,
        )

    weighted = sum(
        RE_SIGNAL_WEIGHTS.get(s.signal, 0.0) * (s.normalized or 0.0) for s in measured
    )
    score = round(100 * weighted / available_weight)

    return PillarResult(
        status=PillarStatus.assessed if not unavailable else PillarStatus.degraded,
        score=score,
        coverage=available_weight,
        findings=len(mine),
        raw=round(weighted, 4),
        unavailable_signals=unavailable,
        effort_band=_band(score, EFFORT_BANDS),
    )


def compatibility_signature(
    *,
    profile: str,
    scanner_manifest_digest: str,
    ruleset_versions_digest: str,
    required_scanners: list[str],
    pillar_scope: list[Pillar],
    config_hash: str,
) -> str:
    """Baselines and trends compare only where this matches."""
    payload = {
        "profile": profile,
        "scoring_model": SCORING_MODEL,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "scanner_manifest_digest": scanner_manifest_digest,
        "ruleset_versions_digest": ruleset_versions_digest,
        "required_scanner_availability": sorted(required_scanners),
        "pillar_scope": sorted(p.value for p in pillar_scope),
        "coverage_threshold": COVERAGE_THRESHOLD,
        "config_hash": config_hash,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def score_job(
    groups: list[CanonicalGroup],
    runs: list[ScannerRun],
    *,
    profile: str,
    analysis_kind: str = "source_audit",
    project_id: str | None = None,
    re_signals: list[ReSignal] | None = None,
    files_scanned: int = 0,
    unmapped: int = 0,
    collisions: int = 0,
    compat_signature: str = "sha256:" + "0" * 64,
) -> dict[str, Any]:
    """Produce the ``dacv`` object for ``Job.metrics_json``."""
    pillars: dict[Pillar, PillarResult] = {}
    for pillar in ACCUMULATION_PILLARS:
        pillars[pillar] = score_accumulation_pillar(pillar, groups, runs)
    pillars[Pillar.re_feasibility] = score_re_pillar(re_signals or [], groups)

    _raw, caps = apply_caps(groups)

    assessed = [p for p, r in pillars.items() if r.status is not PillarStatus.not_assessed]
    complete = all(
        r.status is PillarStatus.assessed and r.coverage >= COVERAGE_THRESHOLD
        for r in pillars.values()
    )

    # Scoped grade covers only what was actually assessed, and is kept in a
    # separate object so a client that does not know the difference cannot
    # render it as an artifact-level grade.
    if assessed:
        weight_total = sum(PILLAR_WEIGHT[p] for p in assessed)
        scoped_score = round(
            sum(PILLAR_WEIGHT[p] * (pillars[p].score or 0) for p in assessed) / weight_total
        )
    else:
        scoped_score = 0
    scoped_grade = _band(scoped_score, GRADE_BANDS)

    overall_score = scoped_score if complete else None
    overall_grade = _band(overall_score, GRADE_BANDS) if complete else None

    disqualifier = next(
        (
            g for g in groups
            if g.pillar is Pillar.attribution and g.severity == "critical" and g.scored
        ),
        None,
    )
    disqualified = disqualifier is not None
    if disqualified:
        # A classification marking or operator handle is disqualifying outright.
        # It applies to the scoped grade too: a Quick scan that finds one must
        # not report "Quick profile: B".
        scoped_grade = "F"
        if complete:
            overall_grade = "F"

    dacv: dict[str, Any] = {
        "schema": "bluescrub/2",
        "scoring_model": SCORING_MODEL,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "calibration": CALIBRATION_STATE,
        "project_id": project_id,
        "analysis_kind": analysis_kind,
        "profile": profile,
        "compatibility_signature": compat_signature,
        "pillars": {p.value: r.to_dict() for p, r in pillars.items()},
        "overall": {
            "status": "complete" if complete else "incomplete",
            "score": overall_score,
            "grade": overall_grade,
        },
        "scoped": {
            "profile": profile,
            "score": scoped_score,
            "grade": scoped_grade,
            "pillars_assessed": len(assessed),
            "pillars_total": 5,
            "label": f"{profile} profile grade — {len(assessed)} of 5 pillars assessed",
        },
        "disqualified": disqualified,
        "caps_applied": caps,
        "unmapped_findings": unmapped,
        "fingerprint_collisions": collisions,
        "files_scanned": files_scanned,
        "scanners": [
            {
                k: v for k, v in {
                    "sensor": r.sensor,
                    "status": r.status,
                    "required_for": [p.value for p in r.required_for] or None,
                    "optional": r.optional,
                    "version": r.version,
                    "ruleset_version": r.ruleset_version,
                    "ruleset_state": r.ruleset_state,
                    "duration_ms": r.duration_ms,
                    "reason": r.reason,
                    "truncated": r.truncated,
                }.items() if v is not None
            }
            for r in runs
        ],
        "partial": any(not r.succeeded and r.status != "skipped" for r in runs),
        "partial_reasons": [
            {
                "sensor": r.sensor,
                "class": r.status if r.status != "unparseable" else "unparseable",
                "detail": r.reason,
                "pillars_affected": [p.value for p in r.required_for],
            }
            for r in runs if not r.succeeded and r.status != "skipped"
        ],
    }
    if disqualified:
        dacv["grade_override"] = {
            "finding_id": disqualifier.canonical_id,
            "reason": "critical_attribution_exposure",
        }
    return {"dacv": dacv}
