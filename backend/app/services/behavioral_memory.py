"""Behavioral Memory — extracts reusable fingerprints from confirmed investigations.

Converts confirmed findings, telemetry events, and storyline stages into
structured behavioral fingerprints that can be indexed in forensic memory
for cross-exercise learning.

Fingerprint types:
  - beacon_profile: C2 beacon cadence, jitter, dest IPs/ports
  - auth_abuse: credential spraying, brute-force, lateral auth patterns
  - sequence_motif: multi-step attack chain templates
  - operator_timing: C2 operator work patterns (timing, task types)
  - infrastructure: JA3/SNI/cert combinations, C2 framework signatures
"""

from __future__ import annotations

from backend.app.pipeline.runtime_control import checkpoint
from backend.app.pipeline.outcomes import PROPAGATE_ERRORS

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.normalized_event import NormalizedEvent

logger = logging.getLogger("aipam.behavioral_memory")


@dataclass
class BehavioralFingerprint:
    """A single behavioral fingerprint extracted from confirmed evidence."""
    fingerprint_type: str          # beacon_profile, auth_abuse, sequence_motif, etc.
    label: str                     # Human-readable short label
    text: str                      # Full text for embedding/search
    metadata: dict[str, Any] = field(default_factory=dict)
    source_job_id: str = ""
    source_exercise_id: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint_type": self.fingerprint_type,
            "label": self.label,
            "text": self.text,
            "metadata": self.metadata,
            "source_job_id": self.source_job_id,
            "source_exercise_id": self.source_exercise_id,
            "confidence": self.confidence,
        }


# ── Fingerprint Extractors ──────────────────────────────────────────────


def extract_beacon_profiles(
    db: Session, job_id: str, exercise_id: str = "",
) -> list[BehavioralFingerprint]:
    """Extract beacon profiles from confirmed beaconing findings."""
    findings = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            Finding.category.in_(["beaconing", "c2", "c2_fusion"]),
            Finding.confidence >= 0.6,
        )
    ).scalars().all()

    fingerprints: list[BehavioralFingerprint] = []
    for f in findings:
        checkpoint()
        evidence = _parse_evidence(f.evidence_json)
        if not evidence:
            continue

        # Extract beacon characteristics
        dest_ip = evidence.get("dest_ip") or evidence.get("c2_ip", "")
        dest_port = evidence.get("dest_port") or evidence.get("c2_port", "")
        interval = evidence.get("interval") or evidence.get("sleep_seconds", "")
        jitter = evidence.get("jitter") or evidence.get("jitter_pct", "")
        framework = evidence.get("c2_framework", "")
        agent_id = evidence.get("agent_id", "")
        match_count = evidence.get("match_count", evidence.get("confirmed_connections", 0))

        text_parts = [f"Beacon profile: {dest_ip}:{dest_port}"]
        if interval:
            text_parts.append(f"interval={interval}s")
        if jitter:
            text_parts.append(f"jitter={jitter}%")
        if framework:
            text_parts.append(f"framework={framework}")
        text_parts.append(f"confidence={f.confidence}")
        if f.summary:
            text_parts.append(f.summary)

        fingerprints.append(BehavioralFingerprint(
            fingerprint_type="beacon_profile",
            label=f"Beacon → {dest_ip}:{dest_port}",
            text=" | ".join(text_parts),
            metadata={
                "dest_ip": str(dest_ip),
                "dest_port": str(dest_port),
                "interval": str(interval),
                "jitter": str(jitter),
                "framework": framework,
                "agent_id": agent_id,
                "match_count": int(match_count) if match_count else 0,
                "finding_id": f.finding_id,
            },
            source_job_id=job_id,
            source_exercise_id=exercise_id,
            confidence=f.confidence or 0.0,
        ))

    logger.info("Extracted %d beacon profiles from job %s", len(fingerprints), job_id)
    return fingerprints


def extract_auth_abuse_patterns(
    db: Session, job_id: str, exercise_id: str = "",
) -> list[BehavioralFingerprint]:
    """Extract authentication abuse patterns from confirmed findings."""
    findings = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            Finding.category.in_([
                "brute_force", "credential_spraying", "lateral_auth",
                "privilege_escalation", "credential_abuse",
            ]),
            Finding.confidence >= 0.5,
        )
    ).scalars().all()

    fingerprints: list[BehavioralFingerprint] = []
    for f in findings:
        checkpoint()
        evidence = _parse_evidence(f.evidence_json)
        meta: dict[str, Any] = {
            "category": f.category or "",
            "severity": f.severity or "",
            "finding_id": f.finding_id,
        }
        if evidence:
            for key in ("src_ip", "target_hosts", "username", "attempt_count",
                        "unique_targets", "unique_users", "time_span_seconds"):
                checkpoint()
                if key in evidence:
                    meta[key] = evidence[key]

        text = f"Auth abuse pattern: {f.category} | {f.title}"
        if f.summary:
            text += f" | {f.summary}"

        fingerprints.append(BehavioralFingerprint(
            fingerprint_type="auth_abuse",
            label=f"Auth: {f.category} — {f.title}",
            text=text,
            metadata=meta,
            source_job_id=job_id,
            source_exercise_id=exercise_id,
            confidence=f.confidence or 0.5,
        ))

    return fingerprints


def extract_sequence_motifs(
    db: Session, job_id: str, exercise_id: str = "",
) -> list[BehavioralFingerprint]:
    """Extract multi-step attack sequence motifs from confirmed findings."""
    findings = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            Finding.sensor == "sequence_detector",
            Finding.confidence >= 0.5,
        )
    ).scalars().all()

    fingerprints: list[BehavioralFingerprint] = []
    for f in findings:
        checkpoint()
        evidence = _parse_evidence(f.evidence_json)
        meta: dict[str, Any] = {
            "category": f.category or "",
            "severity": f.severity or "",
            "finding_id": f.finding_id,
        }
        if evidence:
            for key in ("chain_type", "steps", "hosts_involved",
                        "step_count", "time_span"):
                checkpoint()
                if key in evidence:
                    meta[key] = evidence[key]

        text = f"Attack sequence: {f.category} | {f.title}"
        if f.summary:
            text += f" | {f.summary}"

        fingerprints.append(BehavioralFingerprint(
            fingerprint_type="sequence_motif",
            label=f"Sequence: {f.title[:60]}",
            text=text,
            metadata=meta,
            source_job_id=job_id,
            source_exercise_id=exercise_id,
            confidence=f.confidence or 0.0,
        ))

    logger.info("Extracted %d sequence motifs from job %s", len(fingerprints), job_id)
    return fingerprints


def extract_operator_timing(
    db: Session, job_id: str, exercise_id: str = "",
) -> list[BehavioralFingerprint]:
    """Extract operator timing patterns from C2 task events."""
    c2_tasks = db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_type == "c2_task",
        ).order_by(NormalizedEvent.timestamp)
    ).scalars().all()

    if len(c2_tasks) < 2:
        return []

    # Group tasks by operator/user
    by_operator: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for evt in c2_tasks:
        checkpoint()
        operator = evt.username or "unknown"
        by_operator[operator].append(evt)

    fingerprints: list[BehavioralFingerprint] = []
    for operator, events in by_operator.items():
        checkpoint()
        data = _parse_event_data(events)
        task_types = [d.get("task_type", "unknown") for d in data]
        task_type_counts = defaultdict(int)
        for tt in task_types:
            checkpoint()
            task_type_counts[tt] += 1

        hours = _extract_hours(events)
        hour_counts = defaultdict(int)
        for h in hours:
            checkpoint()
            hour_counts[h] += 1
        peak_hours = sorted(hour_counts, key=hour_counts.get, reverse=True)[:3]  # type: ignore[arg-type]

        text_parts = [
            f"Operator timing: {operator}",
            f"tasks={len(events)}",
            f"task_types={dict(task_type_counts)}",
            f"peak_hours={peak_hours}",
        ]

        fingerprints.append(BehavioralFingerprint(
            fingerprint_type="operator_timing",
            label=f"Operator: {operator} ({len(events)} tasks)",
            text=" | ".join(text_parts),
            metadata={
                "operator": operator,
                "task_count": len(events),
                "task_types": dict(task_type_counts),
                "peak_hours": peak_hours,
                "hour_distribution": dict(hour_counts),
            },
            source_job_id=job_id,
            source_exercise_id=exercise_id,
            confidence=0.7,
        ))

    logger.info("Extracted %d operator timing profiles from job %s", len(fingerprints), job_id)
    return fingerprints


def extract_infrastructure_fingerprints(
    db: Session, job_id: str, exercise_id: str = "",
) -> list[BehavioralFingerprint]:
    """Extract infrastructure fingerprints (JA3/SNI/cert combos) from confirmed C2 events."""
    c2_callbacks = db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_type == "c2_callback",
            NormalizedEvent.evidence_status == "confirmed",
        )
    ).scalars().all()

    if not c2_callbacks:
        return []

    # Aggregate unique infrastructure signatures
    infra_sigs: dict[str, dict[str, Any]] = {}
    for evt in c2_callbacks:
        checkpoint()
        data = _safe_json(evt.data_json)
        dest = evt.dest_ip or data.get("c2_ip", "")
        port = str(evt.dest_port or data.get("c2_port", ""))
        framework = data.get("c2_framework", "")
        ja3 = data.get("ja3", "")
        sni = data.get("sni", "")

        sig_key = f"{dest}:{port}:{framework}"
        if sig_key not in infra_sigs:
            infra_sigs[sig_key] = {
                "dest_ip": dest, "dest_port": port, "framework": framework,
                "ja3": ja3, "sni": sni, "count": 0,
            }
        infra_sigs[sig_key]["count"] += 1

    fingerprints: list[BehavioralFingerprint] = []
    for sig_key, sig in infra_sigs.items():
        checkpoint()
        text = f"Infrastructure: {sig['dest_ip']}:{sig['dest_port']}"
        if sig["framework"]:
            text += f" framework={sig['framework']}"
        if sig["ja3"]:
            text += f" ja3={sig['ja3']}"
        if sig["sni"]:
            text += f" sni={sig['sni']}"
        text += f" callbacks={sig['count']}"

        fingerprints.append(BehavioralFingerprint(
            fingerprint_type="infrastructure",
            label=f"Infra: {sig['dest_ip']}:{sig['dest_port']}",
            text=text,
            metadata=sig,
            source_job_id=job_id,
            source_exercise_id=exercise_id,
            confidence=0.8,
        ))

    logger.info("Extracted %d infrastructure fingerprints from job %s", len(fingerprints), job_id)
    return fingerprints


# ── Orchestrator ─────────────────────────────────────────────────────────


def extract_all_fingerprints(
    db: Session, job_id: str, exercise_id: str = "",
) -> list[BehavioralFingerprint]:
    """Run all fingerprint extractors and return combined results.

    Only produces fingerprints from confirmed or high-confidence evidence.
    """
    all_fps: list[BehavioralFingerprint] = []

    extractors = [
        ("beacon_profiles", extract_beacon_profiles),
        ("auth_abuse", extract_auth_abuse_patterns),
        ("sequence_motifs", extract_sequence_motifs),
        ("operator_timing", extract_operator_timing),
        ("infrastructure", extract_infrastructure_fingerprints),
    ]

    for name, fn in extractors:
        checkpoint()
        try:
            fps = fn(db, job_id, exercise_id)
            all_fps.extend(fps)
        except PROPAGATE_ERRORS:
            raise
        except Exception:
            logger.exception("Fingerprint extractor %s failed for job %s", name, job_id)

    logger.info(
        "Total fingerprints extracted for job %s: %d (beacon=%d, auth=%d, seq=%d, op=%d, infra=%d)",
        job_id, len(all_fps),
        sum(1 for f in all_fps if f.fingerprint_type == "beacon_profile"),
        sum(1 for f in all_fps if f.fingerprint_type == "auth_abuse"),
        sum(1 for f in all_fps if f.fingerprint_type == "sequence_motif"),
        sum(1 for f in all_fps if f.fingerprint_type == "operator_timing"),
        sum(1 for f in all_fps if f.fingerprint_type == "infrastructure"),
    )
    return all_fps


# ── Helpers ──────────────────────────────────────────────────────────────


def _parse_evidence(evidence_json: str | None) -> dict[str, Any]:
    """Safely parse finding evidence JSON."""
    if not evidence_json:
        return {}
    try:
        return json.loads(evidence_json)
    except (json.JSONDecodeError, TypeError):
        return {}


def _safe_json(data_json: str | None) -> dict[str, Any]:
    """Safely parse NormalizedEvent data_json."""
    if not data_json:
        return {}
    try:
        return json.loads(data_json)
    except (json.JSONDecodeError, TypeError):
        return {}


def _parse_event_data(events: list[NormalizedEvent]) -> list[dict[str, Any]]:
    """Parse data_json from a list of events."""
    return [_safe_json(e.data_json) for e in events]


def _extract_hours(events: list[NormalizedEvent]) -> list[int]:
    """Extract hour-of-day from event timestamps."""
    hours = []
    for e in events:
        checkpoint()
        if e.timestamp:
            try:
                ts = e.timestamp
                # Handle ISO-8601 timestamps
                if "T" in ts and len(ts) >= 13:
                    hour = int(ts[11:13])
                    hours.append(hour)
            except (ValueError, IndexError):
                pass
    return hours
