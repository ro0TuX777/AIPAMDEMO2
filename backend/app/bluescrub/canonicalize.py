"""Raw findings → canonical issue groups.

Without this stage the score measures how many overlapping tools are installed
rather than how much risk the artifact carries: Semgrep, CodeQL, Joern, Weggli
and the vendored memory-safety analyzer can all report one buffer overflow, and
scoring raw hits would count it five times.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §2
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from backend.app.bluescrub import severity as sev
from backend.app.bluescrub.fingerprint import (
    binary_fingerprint,
    canonical_id,
    source_fingerprint,
)
from backend.app.bluescrub.models import CanonicalGroup, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, IssueFamily, Pillar

logger = logging.getLogger(__name__)

#: Binary findings within this many bytes are the same site.
BINARY_OFFSET_TOLERANCE = 64


@dataclass
class CanonicalizeResult:
    groups: list[CanonicalGroup] = field(default_factory=list)
    unmapped: int = 0
    collisions: int = 0


def _line_bucket(finding: RawFinding) -> int | None:
    return finding.location.start_line


def _grouping_key(finding: RawFinding) -> tuple:
    """Location equivalence class. Never crosses ``issue_family``."""
    loc = finding.location
    family = finding.issue_family.value

    if loc.kind == "source":
        # Prefer the enclosing symbol when the scanner reports one; two hits in
        # one function are the same site even if the lines differ slightly.
        scope = loc.symbol or f"line:{_line_bucket(finding)}"
        return ("source", family, loc.file or "", scope)

    if loc.kind == "binary":
        offset = loc.offset or 0
        return (
            "binary", family, loc.artifact_sha256 or "", loc.section or "",
            loc.function_fingerprint or f"off:{offset // BINARY_OFFSET_TOLERANCE}",
        )

    return ("project", family, loc.subject or "")


def _resolve_pillar(finding: RawFinding) -> Pillar | None:
    if finding.pillar_hint is not None:
        return finding.pillar_hint
    return FAMILY_PILLAR.get(finding.issue_family)


def canonicalize(
    findings: list[RawFinding],
    *,
    project_id: str,
    rule_mapping: dict[str, str] | None = None,
    impact_modifiers: dict[str, str] | None = None,
    optional_sensors: frozenset[str] = frozenset(),
) -> CanonicalizeResult:
    """Collapse raw findings into canonical groups.

    Ordering is fixed before grouping so membership — and therefore every
    fingerprint — is identical regardless of the order scanners finished in.
    """
    result = CanonicalizeResult()
    ordered = sorted(findings, key=lambda f: f.sort_key)

    buckets: dict[tuple, list[RawFinding]] = defaultdict(list)
    for finding in ordered:
        buckets[_grouping_key(finding)].append(finding)

    # Occurrence disambiguation is per fingerprint-identical site, and the
    # unique constraint on (job_id, finding_id) makes it a correctness
    # requirement rather than a nicety: two identical statements in one scope
    # would otherwise raise IntegrityError instead of persisting as two rows.
    occurrence: dict[str, int] = defaultdict(int)
    seen_ids: dict[str, tuple] = {}

    for key in sorted(buckets, key=lambda k: tuple(str(p) for p in k)):
        members = buckets[key]
        primary = sev.select_primary(members, optional_sensors)
        pillar = _resolve_pillar(primary)

        if primary.issue_family is IssueFamily.unmapped or pillar is None:
            # Persisted and displayed, never scored. Discarding would hide
            # scanner output; scoring would put an unreviewed rule in the grade.
            result.unmapped += 1
            pillar = pillar or Pillar.vulnerability
            scored = False
        else:
            scored = True

        decision = sev.resolve(
            members, primary,
            rule_mapping=rule_mapping,
            impact_modifier=(impact_modifiers or {}).get(primary.rule_id),
        )

        base_digest = _fingerprint_for(primary, project_id, occurrence_index=0)
        index = occurrence[base_digest]
        occurrence[base_digest] += 1
        digest = (
            base_digest if index == 0
            else _fingerprint_for(primary, project_id, occurrence_index=index)
        )

        cid = canonical_id(pillar.value, primary.sensor, digest)
        dup = 0
        while cid in seen_ids:
            # A distinct site producing an existing key means the scheme is
            # defective. Keep the job alive, but make the defect countable
            # rather than letting it surface as an IntegrityError.
            dup += 1
            result.collisions += 1
            logger.error(
                "fp/2 collision: %s already used by %s, now also %s",
                cid, seen_ids[cid], key,
            )
            cid = canonical_id(pillar.value, primary.sensor, digest, dup=dup)
        seen_ids[cid] = key

        result.groups.append(CanonicalGroup(
            canonical_id=cid,
            issue_family=primary.issue_family,
            pillar=pillar,
            severity=decision.severity,
            severity_source=decision.source,
            severity_rationale=decision.rationale,
            scoring_confidence=sev.scoring_confidence(primary),
            primary_sensor=primary.sensor,
            primary_rule_id=primary.rule_id,
            primary_detector_class=primary.detector_class,
            occurrence_index=index,
            members=members,
            location=primary.location,
            scored=scored,
        ))

    return result


def _fingerprint_for(finding: RawFinding, project_id: str, *, occurrence_index: int) -> str:
    loc = finding.location
    if loc.kind == "binary":
        return binary_fingerprint(
            project_id=project_id,
            rule_id=finding.rule_id,
            binary_format=loc.format,
            architecture=loc.architecture,
            section=loc.section,
            nearest_symbol=loc.symbol or loc.function_fingerprint,
            normalized_value=finding.matched_tokens or "",
            occurrence_index=occurrence_index,
        )
    return source_fingerprint(
        project_id=project_id,
        rule_namespace=finding.rule_namespace,
        rule_id=finding.rule_id,
        relative_path=loc.file or loc.subject or "",
        enclosing_symbol=loc.symbol,
        node_kind=loc.node_kind,
        normalized_tokens=finding.matched_tokens or "",
        context_digest=finding.context_hash or "",
        occurrence_index=occurrence_index,
    )
