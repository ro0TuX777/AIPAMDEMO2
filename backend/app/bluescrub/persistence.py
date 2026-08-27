"""Canonical groups → ``Finding`` rows.

Upsert-safe and idempotent. ``findings`` carries
``UniqueConstraint("job_id", "finding_id")``, so re-persisting must update in
place rather than insert; the SELECT-then-skip pattern used elsewhere is racy
under that constraint.

Analyst-owned columns are never overwritten by a re-scan. Triage carry-forward
reads the ledger rather than a prior job's rows, because those rows are deleted
at the platform retention horizon.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §4
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.bluescrub import (
    CANONICALIZATION_VERSION,
    FINGERPRINT_SCHEME,
    SCHEMA_VERSION,
    SCORING_MODEL,
)
from backend.app.bluescrub.enrich import autofix_for
from backend.app.bluescrub.models import CanonicalGroup
from backend.app.models.bluescrub import BlueScrubTriageLedger
from backend.app.models.finding import Finding

logger = logging.getLogger(__name__)

#: Columns an analyst owns. A re-scan updates scanner evidence around them and
#: never replaces them.
ANALYST_OWNED = (
    "analyst_status", "analyst_notes", "reviewed_at", "reviewer_id",
    "feedback", "explanation_feedback",
)

MAX_CODE_BYTES = 4096
MAX_RATIONALE_BYTES = 2048


def _clip(value: str | None, limit: int) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    encoded = value.encode("utf-8", "surrogatepass")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", "ignore"), True


def build_evidence(group: CanonicalGroup) -> dict:
    """Assemble the versioned evidence envelope."""
    primary = next(
        (m for m in group.members
         if m.sensor == group.primary_sensor and m.rule_id == group.primary_rule_id),
        group.members[0],
    )
    code, code_clipped = _clip(primary.matched_tokens, MAX_CODE_BYTES)
    rationale, rationale_clipped = _clip(group.severity_rationale, MAX_RATIONALE_BYTES)

    envelope = {
        "schema": SCHEMA_VERSION,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "scoring_model": SCORING_MODEL,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "pillar": group.pillar.value,
        "related_pillars": [p.value for p in group.related_pillars],
        "issue_family": group.issue_family.value,
        "scored": group.scored,
        "primary_sensor": group.primary_sensor,
        "sensor_version": primary.sensor_version,
        "ruleset_version": primary.ruleset_version,
        "rule_id": group.primary_rule_id,
        "rule_version": primary.rule_version,
        "detector_class": (
            group.primary_detector_class.value if group.primary_detector_class else None
        ),
        "corroborating_sensors": [
            {
                "sensor": m.sensor,
                "rule_id": m.rule_id,
                "detector_class": m.detector_class.value if m.detector_class else None,
                "confidence": m.confidence,
            }
            for m in group.corroborating
        ],
        "location": group.location.to_dict(),
        "code": code,
        "occurrence_index": group.occurrence_index,
        "cwe": primary.cwe,
        "mitre": primary.mitre,
        "auto_fix": autofix_for(primary.matched_tokens, primary.title, group.primary_rule_id),
        "severity_source": group.severity_source,
        "severity_rationale": rationale,
        "recommendation": primary.recommendation,
        "fp_filters_applied": primary.fp_filters_applied,
        "observables": [o.to_dict() for o in primary.observables],
        "typed_evidence": primary.typed_evidence,
        "capped_by": group.capped_by,
        "evidence_status": "observed" if group.scored else "inferred",
        "truncated": code_clipped or rationale_clipped or primary.truncated,
    }
    if primary.source_facet:
        envelope["source"] = primary.source_facet
    if primary.secret:
        # Masked value and keyed fingerprint only. Plaintext never reaches here.
        envelope["secret"] = primary.secret.to_dict()
    return envelope


def carry_forward(
    db: Session, project_id: str | None, group: CanonicalGroup
) -> tuple[str, dict | None]:
    """Resolve the analyst status for a group from the triage ledger."""
    if not project_id:
        return "unreviewed", None

    row = db.scalar(
        select(BlueScrubTriageLedger).where(
            BlueScrubTriageLedger.project_id == project_id,
            BlueScrubTriageLedger.finding_id == group.canonical_id,
        )
    )
    if row is None:
        return "unreviewed", None

    if row.fingerprint_scheme != FINGERPRINT_SCHEME:
        # A scheme change invalidates the identity the decision was attached to.
        return "unreviewed", {"match": None, "origin_job_id": row.origin_job_id}

    primary = next(
        (m for m in group.members if m.rule_id == group.primary_rule_id),
        group.members[0],
    )
    changed = bool(
        row.rule_version and primary.rule_version and row.rule_version != primary.rule_version
    )
    return row.status, {
        "origin_job_id": row.origin_job_id,
        "match": "ambiguous" if changed else "exact",
        "prior_rule_version": row.rule_version,
        "current_rule_version": primary.rule_version,
        "requires_review": changed,
    }


def persist_groups(
    db: Session,
    job_id: str,
    groups: list[CanonicalGroup],
    *,
    project_id: str | None = None,
) -> tuple[int, int]:
    """Write one ``Finding`` per canonical group. Returns (created, updated)."""
    created = updated = 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    for group in groups:
        status, carry = carry_forward(db, project_id, group)
        evidence = build_evidence(group)
        if carry:
            evidence["triage_carry"] = carry

        existing = db.scalar(
            select(Finding).where(
                Finding.job_id == job_id,
                Finding.finding_id == group.canonical_id,
            )
        )

        if existing is not None:
            # Scanner-owned columns only. Analyst columns are left untouched
            # so a re-scan never discards a triage decision.
            existing.sensor = group.primary_sensor
            existing.severity = group.severity
            existing.category = group.pillar.value
            existing.title = _title(group)
            existing.summary = evidence.get("severity_rationale") or _title(group)
            existing.confidence = group.scoring_confidence
            existing.evidence_json = json.dumps(evidence)
            if _HAS_EVIDENCE_STATUS:
                existing.evidence_status = _evidence_status(group)
            updated += 1
            continue

        columns = dict(
            job_id=job_id,
            finding_id=group.canonical_id,
            sensor=group.primary_sensor,
            severity=group.severity,
            category=group.pillar.value,
            title=_title(group),
            summary=evidence.get("severity_rationale") or _title(group),
            confidence=group.scoring_confidence,
            evidence_json=json.dumps(evidence),
            analyst_status=status,
            reviewed_at=now if status != "unreviewed" else None,
        )
        if _HAS_EVIDENCE_STATUS:
            columns["evidence_status"] = _evidence_status(group)
        db.add(Finding(**columns))
        created += 1

    db.commit()
    return created, updated


def _evidence_status(group: CanonicalGroup) -> str:
    """Observed for direct tool hits; inferred for derived or unscored ones."""
    return "observed" if group.scored else "inferred"


#: ``Finding.evidence_status`` is part of the platform's evidence lifecycle and
#: its enum is committed, but the column itself is not yet on the model in every
#: checkout. BlueScrub is additive and must not require another change to land
#: first, so the value always goes into ``evidence_json`` — the source of truth
#: for BlueScrub metadata — and reaches the column only where it exists.
_HAS_EVIDENCE_STATUS = hasattr(Finding, "evidence_status")


def _title(group: CanonicalGroup) -> str:
    primary = next(
        (m for m in group.members if m.rule_id == group.primary_rule_id),
        group.members[0],
    )
    return primary.title or f"{group.issue_family.value}: {group.primary_rule_id}"
