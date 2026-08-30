"""Baselines: freezing a comparison point, and refusing bad comparisons.

A baseline answers "what changed since we last accepted this artifact". It is
only meaningful when the two scans measured the same thing in the same way, and
the pipeline can already tell whether they did — `compatibility_signature`
exists for exactly this. What it could not do was say **why** two scans are
incomparable, and the contract is explicit that it must:

    A rejected comparison returns `incomparable` with the differing field
    named. "Incomparable" without a reason is an error message users cannot
    act on.  — SCORING_SPEC §6

You cannot recover a differing field from a SHA-256. So a baseline stores the
signature's *payload* alongside its digest, and a rejected comparison names the
fields that moved and shows both values. The digest still decides; the payload
only explains.

**The comparison is on canonical ids, not on counts.** "Three fewer findings"
is not progress if three were fixed and three appeared. New, fixed and
regressed are separate answers, and a severity that rose on a finding nobody
touched is the one an analyst most needs to see.

**A baseline outlives its job by design.** `bluescrub_baselines.job_id` is
`SET NULL`, so the snapshot survives the platform's 30-day job cleanup — which
means the diff must work entirely from what the row stores and must never read
back through `job_id`.

Reference: docs/BLUESCRUB_SCORING_SPEC.md §6 ·
docs/BLUESCRUB_DATA_CONTRACTS.md §0
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.bluescrub.models import CanonicalGroup
from backend.app.bluescrub.pillars import SEVERITY_ORDER
from backend.app.models.bluescrub import BlueScrubBaseline

logger = logging.getLogger(__name__)

#: Fields whose difference is worth explaining in plain words rather than as a
#: raw value pair. Everything else falls back to "before → after".
_FIELD_EXPLANATIONS: dict[str, str] = {
    "profile": "the two scans ran different profiles, so they looked for "
               "different things",
    "scoring_model": "the scoring model changed; scores across versions are "
                     "not comparable without recalculating",
    "canonicalization_version": "findings are grouped differently, so the same "
                                "issue may not have the same identity",
    "fingerprint_scheme": "finding identities are computed differently, so "
                          "nothing can be matched up",
    "required_scanner_availability": "a required scanner was present for one "
                                     "scan and not the other",
    "pillar_scope": "the two scans assessed different pillars",
    "config_hash": "a scoring-relevant setting changed — a cap, a K_P, or the "
                   "wordlist content",
    "coverage_threshold": "the bar for calling a pillar assessed moved",
    "scanner_manifest_digest": "the set or versions of required scanners changed",
    "ruleset_versions_digest": "the rule packs or vulnerability databases changed",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


@dataclass
class FindingDelta:
    """One finding's movement between the baseline and the current scan."""

    finding_id: str
    rule_id: str
    pillar: str
    severity: str
    was: str | None = None          # previous severity, for a regression

    def to_dict(self) -> dict[str, Any]:
        data = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "pillar": self.pillar,
            "severity": self.severity,
        }
        if self.was is not None:
            data["was"] = self.was
        return data


@dataclass
class Comparison:
    """The answer to "what changed", or why that question cannot be answered."""

    comparable: bool
    reason: str | None = None
    differing_fields: list[dict[str, Any]] = field(default_factory=list)
    new: list[FindingDelta] = field(default_factory=list)
    fixed: list[FindingDelta] = field(default_factory=list)
    regressed: list[FindingDelta] = field(default_factory=list)
    unchanged: int = 0
    baseline_label: str | None = None
    baseline_created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if not self.comparable:
            return {
                "status": "incomparable",
                "reason": self.reason,
                "differing_fields": self.differing_fields,
            }
        return {
            "status": "comparable",
            "baseline": {
                "label": self.baseline_label,
                "created_at": self.baseline_created_at,
            },
            "new": [d.to_dict() for d in self.new],
            "fixed": [d.to_dict() for d in self.fixed],
            "regressed": [d.to_dict() for d in self.regressed],
            "counts": {
                "new": len(self.new), "fixed": len(self.fixed),
                "regressed": len(self.regressed), "unchanged": self.unchanged,
            },
        }


def snapshot(groups: list[CanonicalGroup]) -> list[dict[str, str]]:
    """The minimum a diff needs, and nothing an analyst could not re-derive.

    Deliberately not the whole finding: a baseline is kept indefinitely while
    job evidence expires at thirty days, and freezing snippets here would
    quietly recreate the retention the policy removed.
    """
    return sorted(
        (
            {
                "finding_id": g.canonical_id,
                "rule_id": g.primary_rule_id,
                "pillar": g.pillar.value,
                "severity": g.severity,
            }
            for g in groups
        ),
        key=lambda row: row["finding_id"],
    )


def set_baseline(
    db: Session,
    *,
    project_id: str,
    job_id: str | None,
    dacv: dict[str, Any],
    groups: list[CanonicalGroup],
    signature_fields: dict[str, Any],
    label: str | None = None,
    actor: str | None = None,
) -> BlueScrubBaseline:
    """Freeze the current scan as the project's active baseline.

    Any previously active baseline is stood down rather than deleted: a
    superseded comparison point is still evidence of what was accepted, and the
    partial unique index permits exactly one active row per project.
    """
    for existing in db.scalars(
        select(BlueScrubBaseline).where(
            BlueScrubBaseline.project_id == project_id,
            BlueScrubBaseline.active.is_(True),
        )
    ).all():
        existing.active = False

    row = BlueScrubBaseline(
        project_id=project_id,
        job_id=job_id,
        active=True,
        label=label,
        compatibility_signature=str(dacv.get("compatibility_signature") or ""),
        findings_json=json.dumps({
            "schema": "bluescrub.baseline/1",
            "signature_fields": signature_fields,
            "findings": snapshot(groups),
        }),
        metrics_json=json.dumps(dacv),
        created_at=_now(),
        created_by=actor,
    )
    db.add(row)
    db.commit()
    logger.info("baseline set for project %s from job %s (%d findings)",
                project_id, job_id, len(groups))
    return row


def active_baseline(db: Session, project_id: str) -> BlueScrubBaseline | None:
    return db.scalar(
        select(BlueScrubBaseline).where(
            BlueScrubBaseline.project_id == project_id,
            BlueScrubBaseline.active.is_(True),
        )
    )


def _stored(row: BlueScrubBaseline) -> dict[str, Any] | None:
    """The baseline's frozen content, or ``None`` if it cannot be read.

    The distinction matters more than it looks. An empty dict and an
    unreadable row both yield no findings, and treating the second as the
    first reports every current finding as new — the same misleading answer
    that reporting an absent baseline as empty would give, arrived at from the
    other direction.
    """
    try:
        payload = json.loads(row.findings_json or "{}")
    except (TypeError, ValueError):
        logger.warning("baseline %s has unreadable findings_json", row.id)
        return None
    return payload if isinstance(payload, dict) else None


def compare_signatures(
    baseline_fields: dict[str, Any], current_fields: dict[str, Any]
) -> list[dict[str, Any]]:
    """Fields that differ, each with both values and why it matters."""
    differing: list[dict[str, Any]] = []
    for key in sorted(set(baseline_fields) | set(current_fields)):
        before = baseline_fields.get(key)
        after = current_fields.get(key)
        if before == after:
            continue
        differing.append({
            "field": key,
            "baseline": before,
            "current": after,
            "why": _FIELD_EXPLANATIONS.get(
                key, "a field the comparability signature covers changed"
            ),
        })
    return differing


def compare(
    db: Session,
    *,
    project_id: str,
    groups: list[CanonicalGroup],
    signature_fields: dict[str, Any],
) -> Comparison:
    """Diff the current scan against the project's active baseline."""
    row = active_baseline(db, project_id)
    if row is None:
        return Comparison(
            comparable=False,
            reason="no active baseline for this project",
            differing_fields=[],
        )

    stored = _stored(row)
    if stored is None:
        return Comparison(
            comparable=False,
            reason=(
                "the baseline's stored content is unreadable, so a diff would "
                "report every current finding as new"
            ),
            differing_fields=[],
        )

    baseline_fields = stored.get("signature_fields")
    if not isinstance(baseline_fields, dict) or not baseline_fields:
        # Written before the payload was stored, or corrupted. The digest can
        # still say whether they match, so fall back to that — and say that the
        # explanation is missing rather than inventing one.
        if row.compatibility_signature and row.compatibility_signature == \
                _digest_of(signature_fields):
            baseline_fields = dict(signature_fields)
        else:
            return Comparison(
                comparable=False,
                reason=(
                    "the baseline predates stored signature fields, and its "
                    "digest does not match this scan — which field differs "
                    "cannot be recovered from a digest alone"
                ),
                differing_fields=[],
            )

    differing = compare_signatures(baseline_fields, signature_fields)
    if differing:
        names = ", ".join(d["field"] for d in differing)
        return Comparison(
            comparable=False,
            reason=f"incomparable: {names} differ from the baseline",
            differing_fields=differing,
        )

    return _diff(row, stored.get("findings") or [], groups)


def _digest_of(fields: dict[str, Any]) -> str:
    from backend.app.bluescrub.scoring import digest_payload

    return digest_payload(fields)


def _diff(
    row: BlueScrubBaseline, before: list[dict], groups: list[CanonicalGroup]
) -> Comparison:
    """New, fixed and regressed as three separate answers.

    A net count cannot distinguish "three fixed, three appeared" from "nothing
    happened", and a severity that rose on a finding nobody touched is the one
    an analyst most needs to see.
    """
    baseline_rows = {
        str(entry.get("finding_id")): entry
        for entry in before
        if isinstance(entry, dict) and entry.get("finding_id")
    }
    current = {g.canonical_id: g for g in groups}

    comparison = Comparison(
        comparable=True,
        baseline_label=row.label,
        baseline_created_at=row.created_at,
    )

    for finding_id, group in current.items():
        previous = baseline_rows.get(finding_id)
        if previous is None:
            comparison.new.append(FindingDelta(
                finding_id=finding_id, rule_id=group.primary_rule_id,
                pillar=group.pillar.value, severity=group.severity,
            ))
            continue
        was = str(previous.get("severity") or "")
        if _severity_rank(group.severity) > _severity_rank(was):
            comparison.regressed.append(FindingDelta(
                finding_id=finding_id, rule_id=group.primary_rule_id,
                pillar=group.pillar.value, severity=group.severity, was=was,
            ))
        else:
            comparison.unchanged += 1

    for finding_id, entry in baseline_rows.items():
        if finding_id in current:
            continue
        comparison.fixed.append(FindingDelta(
            finding_id=finding_id,
            rule_id=str(entry.get("rule_id") or ""),
            pillar=str(entry.get("pillar") or ""),
            severity=str(entry.get("severity") or ""),
        ))

    for bucket in (comparison.new, comparison.fixed, comparison.regressed):
        bucket.sort(key=lambda d: (-_severity_rank(d.severity), d.finding_id))
    return comparison
