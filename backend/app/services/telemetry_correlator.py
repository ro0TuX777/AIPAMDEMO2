"""
Telemetry Correlator — links NormalizedEvents across sources via shared keys.

Takes ParserResult objects, persists them as NormalizedEvent DB rows, and
builds correlation clusters by shared keys (IP, hostname, username,
process_guid, community_id). When events from 2+ independent sources share
keys, their EvidenceStatus is upgraded from observed → corroborated.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from backend.app.models.normalized_event import NormalizedEvent
from backend.app.parsers.base import ParserResult
from backend.app.schemas.common import EvidenceStatus

logger = logging.getLogger("aipam.telemetry_correlator")

# Correlation key names that matter for linking events across sources
CORRELATION_KEY_NAMES = (
    "community_id", "src_ip", "dest_ip", "hostname",
    "username", "process_guid", "session_id",
)

# Minimum number of distinct source systems to trigger corroboration
_MIN_SOURCES_FOR_CORROBORATION = 2

# Weight per correlation key type for scoring
_KEY_WEIGHTS: dict[str, float] = {
    "community_id": 0.30,
    "process_guid": 0.25,
    "session_id": 0.15,
    "src_ip": 0.10,
    "dest_ip": 0.10,
    "hostname": 0.05,
    "username": 0.05,
}


def _make_event_id() -> str:
    return f"NE-{uuid.uuid4().hex[:12]}"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parser_result_to_db(result: ParserResult, job_id: str) -> NormalizedEvent:
    """Convert a ParserResult dataclass into a NormalizedEvent DB row."""
    event_id = _make_event_id()
    # Build full correlation_keys dict from both explicit keys and top-level fields
    all_keys = dict(result.correlation_keys)
    for key_name in CORRELATION_KEY_NAMES:
        val = getattr(result, key_name, None)
        if val and key_name not in all_keys:
            all_keys[key_name] = str(val)

    return NormalizedEvent(
        event_id=event_id,
        job_id=job_id,
        event_type=result.event_type.value if hasattr(result.event_type, "value") else str(result.event_type),
        timestamp=_iso(result.timestamp),
        source_type=result.source_type.value if hasattr(result.source_type, "value") else str(result.source_type),
        source_system=result.source_system,
        source_filename=result.source_filename,
        parser_name=result.parser_name,
        parser_version=result.parser_version,
        raw_ref=result.raw_ref,
        evidence_status=result.evidence_status.value if hasattr(result.evidence_status, "value") else str(result.evidence_status),
        corroboration_score=0.0,
        community_id=result.community_id,
        hostname=result.hostname,
        username=result.username,
        session_id=result.session_id,
        process_guid=result.process_guid,
        src_ip=result.src_ip,
        src_port=result.src_port,
        dest_ip=result.dest_ip,
        dest_port=result.dest_port,
        proto=result.proto,
        exercise_id=result.exercise_id,
        data_json=json.dumps(result.data) if result.data else None,
        correlation_keys_json=json.dumps(all_keys) if all_keys else None,
        tags_json=json.dumps(result.tags) if result.tags else None,
        pcap_label=result.pcap_label,
    )


def persist_parser_results(
    results: list[ParserResult],
    job_id: str,
    db: Session,
) -> list[NormalizedEvent]:
    """Convert ParserResults to NormalizedEvent rows and persist them."""
    rows: list[NormalizedEvent] = []
    for r in results:
        row = parser_result_to_db(r, job_id)
        db.add(row)
        rows.append(row)
    db.flush()
    logger.info("Persisted %d NormalizedEvents for job %s", len(rows), job_id)
    return rows


# ---------------------------------------------------------------------------
# Correlation cluster builder
# ---------------------------------------------------------------------------

CorrelationCluster = dict[str, Any]
"""A cluster groups event_ids that share one or more correlation keys."""


def _build_key_index(events: list[NormalizedEvent]) -> dict[str, dict[str, list[str]]]:
    """Build key_name → {key_value → [event_id, ...]} index."""
    index: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for evt in events:
        for key_name in CORRELATION_KEY_NAMES:
            val = getattr(evt, key_name, None)
            if val:
                index[key_name][val].append(evt.event_id)
    return index


def _build_source_map(events: list[NormalizedEvent]) -> dict[str, str]:
    """event_id → source_system."""
    return {evt.event_id: (evt.source_system or evt.parser_name or "unknown") for evt in events}


def build_correlation_clusters(
    events: list[NormalizedEvent],
) -> list[CorrelationCluster]:
    """Group events into clusters where members share at least one key.

    Returns list of clusters, each with:
      - event_ids: set of linked event IDs
      - shared_keys: dict of {key_name: [values]}
      - sources: set of distinct source_systems
      - score: 0.0–1.0 corroboration score
    """
    key_index = _build_key_index(events)
    source_map = _build_source_map(events)

    # Union-Find to cluster event_ids
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Union events that share any key value
    for key_name, val_map in key_index.items():
        for val, eids in val_map.items():
            if len(eids) > 1:
                anchor = eids[0]
                for eid in eids[1:]:
                    union(anchor, eid)

    # Group by root
    groups: dict[str, set[str]] = defaultdict(set)
    all_ids = {evt.event_id for evt in events}
    for eid in all_ids:
        groups[find(eid)].add(eid)

    # Build cluster objects (skip singletons unless they have multi-source potential)
    clusters: list[CorrelationCluster] = []
    for root, members in groups.items():
        sources = {source_map[eid] for eid in members}
        # Find which keys are shared
        shared_keys: dict[str, set[str]] = defaultdict(set)
        for key_name, val_map in key_index.items():
            for val, eids in val_map.items():
                linked = members & set(eids)
                if len(linked) > 1:
                    shared_keys[key_name].add(val)

        # Score: weighted sum of shared key types, boosted by source diversity
        raw_score = sum(
            _KEY_WEIGHTS.get(k, 0.05) for k in shared_keys
        )
        source_bonus = min(len(sources) - 1, 3) * 0.15
        score = min(1.0, raw_score + source_bonus)

        clusters.append({
            "event_ids": members,
            "shared_keys": {k: sorted(v) for k, v in shared_keys.items()},
            "sources": sources,
            "score": round(score, 3),
            "size": len(members),
        })

    # Sort by score desc, then size desc
    clusters.sort(key=lambda c: (-c["score"], -c["size"]))
    return clusters


def correlate_and_upgrade(
    job_id: str,
    db: Session,
) -> dict[str, Any]:
    """Run correlation on all NormalizedEvents for a job.

    For clusters with 2+ independent sources, upgrades event evidence_status
    from 'observed' to 'corroborated' and writes the corroboration_score.

    Returns summary stats.
    """
    events = list(db.execute(
        select(NormalizedEvent).where(NormalizedEvent.job_id == job_id)
    ).scalars().all())

    if not events:
        return {"total_events": 0, "clusters": 0, "corroborated": 0}

    clusters = build_correlation_clusters(events)

    corroborated_count = 0
    multi_source_clusters = 0

    for cluster in clusters:
        if len(cluster["sources"]) >= _MIN_SOURCES_FOR_CORROBORATION:
            multi_source_clusters += 1
            # Upgrade all events in this cluster
            for eid in cluster["event_ids"]:
                db.execute(
                    update(NormalizedEvent)
                    .where(
                        NormalizedEvent.event_id == eid,
                        NormalizedEvent.evidence_status == EvidenceStatus.observed.value,
                    )
                    .values(
                        evidence_status=EvidenceStatus.corroborated.value,
                        corroboration_score=cluster["score"],
                    )
                )
                corroborated_count += 1

    db.flush()

    stats = {
        "total_events": len(events),
        "clusters": len(clusters),
        "multi_source_clusters": multi_source_clusters,
        "corroborated": corroborated_count,
    }
    logger.info("Correlation complete for job %s: %s", job_id, stats)
    return stats

