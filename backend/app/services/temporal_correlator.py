"""Cross-source temporal correlator.

Joins NormalizedEvents (from logs) with PCAP-derived entities (Alerts,
Connections) when they share an IP address within a configurable time window.

This bridges the gap between host-level telemetry (C2 logs, command output)
and network-level evidence (IDS alerts, flow records), producing
TemporalCorrelation rows that link the two.

Called after both PCAP and telemetry pipelines complete for hybrid jobs.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.temporal_correlation import TemporalCorrelation

logger = logging.getLogger("aipam.temporal_correlator")

# ── Configuration ─────────────────────────────────────────────────────────

DEFAULT_WINDOW_SECONDS = 30.0   # ±30 seconds
MAX_MATCHES_PER_EVENT = 10      # cap per log event to avoid explosion
MAX_TOTAL_CORRELATIONS = 5000   # safety cap per job


# ── Helpers ───────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string into a datetime."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


class _PcapEvent(NamedTuple):
    """Lightweight representation of a PCAP-derived entity for matching."""
    entity_type: str        # "alert" | "connection"
    entity_id: str
    summary: str
    ts: datetime
    ips: frozenset[str]     # all IPs associated with this entity


def _score_match(delta_seconds: float, window: float) -> float:
    """Compute a 0–1 proximity score. Closer in time = higher score."""
    if delta_seconds >= window:
        return 0.0
    return round(1.0 - (delta_seconds / window), 3)


# Max length for rendered summaries saved to the DB
_MAX_SUMMARY_LEN = 500

# Keys we prefer when building a log summary from a JSON payload.  Order matters.
_PREFERRED_LOG_KEYS = (
    "raw", "message", "msg", "command", "cmd", "cmdline", "command_line",
    "query", "url", "uri", "request", "action", "event", "description",
    "summary", "title", "signature",
)

# Keys we skip when falling back to a key=value digest (already shown elsewhere
# or not useful as a summary).
_SKIPPED_LOG_KEYS = {
    "src_ip", "dest_ip", "dst_ip", "source_ip", "destination_ip",
    "src_port", "dest_port", "dst_port", "timestamp", "ts", "time",
    "id", "uuid",
}


def _build_log_summary(evt: NormalizedEvent) -> str | None:
    """Derive a human-readable one-liner from a NormalizedEvent payload.

    Prefers a raw log line when the parser captured one; otherwise builds a
    compact ``key=value`` digest from the most informative fields.
    """
    if not evt.data_json:
        return None
    try:
        data = json.loads(evt.data_json)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return str(data)[:_MAX_SUMMARY_LEN]

    # 1. Preferred keys — use the first one with a non-empty string value.
    for key in _PREFERRED_LOG_KEYS:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:_MAX_SUMMARY_LEN]

    # 2. Fallback: compact key=value digest of remaining scalar fields.
    parts: list[str] = []
    for key, val in data.items():
        if key in _SKIPPED_LOG_KEYS:
            continue
        if isinstance(val, (str, int, float, bool)):
            text = str(val).strip()
            if text:
                parts.append(f"{key}={text}")
        if len(parts) >= 6:
            break
    if parts:
        return " ".join(parts)[:_MAX_SUMMARY_LEN]
    return None


def _build_alert_summary(alert: Alert) -> str:
    """Format an Alert into a readable summary including severity + endpoints."""
    sig = (alert.signature or "").strip() or "(no signature)"
    parts: list[str] = []
    if alert.severity:
        parts.append(f"[{alert.severity.upper()}]")
    parts.append(sig)
    endpoint_bits: list[str] = []
    if alert.src_ip:
        src = alert.src_ip
        if alert.src_port:
            src = f"{src}:{alert.src_port}"
        endpoint_bits.append(src)
    if alert.dest_ip:
        dst = alert.dest_ip
        if alert.dest_port:
            dst = f"{dst}:{alert.dest_port}"
        endpoint_bits.append(dst)
    if endpoint_bits:
        parts.append("(" + " → ".join(endpoint_bits) + ")")
    return " ".join(parts)[:_MAX_SUMMARY_LEN]


# ── Main entry point ─────────────────────────────────────────────────────

def correlate_temporal(
    db: Session,
    job_id: str,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> dict[str, Any]:
    """Run cross-source temporal correlation for a job.

    Returns a summary dict with counts.
    """
    # 1. Load all NormalizedEvents with at least one IP
    log_events = db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
        )
    ).scalars().all()

    # Filter to events with IPs and valid timestamps
    log_with_ip = []
    for evt in log_events:
        ts = _parse_ts(evt.timestamp)
        if not ts:
            continue
        ips: set[str] = set()
        if evt.src_ip:
            ips.add(evt.src_ip)
        if evt.dest_ip:
            ips.add(evt.dest_ip)
        if not ips:
            continue
        log_with_ip.append((evt, ts, ips))

    if not log_with_ip:
        logger.info("Job %s: no log events with IPs — skipping temporal correlation", job_id)
        return {"log_events": 0, "pcap_events": 0, "matches": 0}

    # 2. Load PCAP-derived entities (alerts + connections)
    pcap_events: list[_PcapEvent] = []

    alerts = db.execute(
        select(Alert).where(Alert.job_id == job_id)
    ).scalars().all()
    for a in alerts:
        ts = _parse_ts(a.ts)
        if not ts:
            continue
        ips = frozenset(ip for ip in (a.src_ip, a.dest_ip, a.host_ip) if ip)
        if ips:
            pcap_events.append(_PcapEvent("alert", a.alert_id, _build_alert_summary(a), ts, ips))

    connections = db.execute(
        select(Connection).where(Connection.job_id == job_id)
    ).scalars().all()
    for c in connections:
        ts = _parse_ts(c.ts)
        if not ts:
            continue
        ips = frozenset(ip for ip in (c.src_ip, c.dest_ip) if ip)
        if ips:
            summary = f"{c.src_ip}:{c.src_port} → {c.dest_ip}:{c.dest_port} ({c.proto or '?'})"
            pcap_events.append(_PcapEvent("connection", c.connection_id, summary, ts, ips))

    if not pcap_events:
        logger.info("Job %s: no PCAP events with IPs — skipping temporal correlation", job_id)
        return {"log_events": len(log_with_ip), "pcap_events": 0, "matches": 0}

    logger.info(
        "Job %s: temporal correlation — %d log events × %d PCAP events (window=±%.0fs)",
        job_id, len(log_with_ip), len(pcap_events), window_seconds,
    )

    # 3. Build IP → PCAP events index for fast lookup
    ip_to_pcap: dict[str, list[_PcapEvent]] = {}
    for pe in pcap_events:
        for ip in pe.ips:
            ip_to_pcap.setdefault(ip, []).append(pe)


    # 4. Clear previous temporal correlations for this job
    db.query(TemporalCorrelation).filter(TemporalCorrelation.job_id == job_id).delete()
    db.flush()

    # 5. Match log events against PCAP events by shared IP + time window
    total_matches = 0
    upgraded_events: set[str] = set()
    seen_pairs: set[tuple[str, str, str]] = set()  # (log_event_id, pcap_type, pcap_id)

    for evt, log_ts, log_ips in log_with_ip:
        matches_for_event = 0

        for ip in log_ips:
            candidates = ip_to_pcap.get(ip, [])
            for pe in candidates:
                # Dedup
                pair_key = (evt.event_id, pe.entity_type, pe.entity_id)
                if pair_key in seen_pairs:
                    continue

                delta = abs((log_ts - pe.ts).total_seconds())
                if delta > window_seconds:
                    continue

                score = _score_match(delta, window_seconds)
                if score <= 0:
                    continue

                seen_pairs.add(pair_key)

                tc = TemporalCorrelation(
                    job_id=job_id,
                    log_event_id=evt.event_id,
                    log_source=evt.source_system,
                    log_source_filename=evt.source_filename,
                    log_event_type=evt.event_type,
                    log_timestamp=evt.timestamp,
                    log_summary=_build_log_summary(evt),
                    pcap_entity_type=pe.entity_type,
                    pcap_entity_id=pe.entity_id,
                    pcap_summary=pe.summary[:_MAX_SUMMARY_LEN] if pe.summary else None,
                    pcap_timestamp=pe.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    shared_ip=ip,
                    time_delta_seconds=round(delta, 3),
                    match_score=score,
                    match_type="ip_temporal",
                )
                db.add(tc)
                total_matches += 1
                matches_for_event += 1
                upgraded_events.add(evt.event_id)

                if matches_for_event >= MAX_MATCHES_PER_EVENT:
                    break
            if matches_for_event >= MAX_MATCHES_PER_EVENT:
                break

        if total_matches >= MAX_TOTAL_CORRELATIONS:
            logger.warning("Job %s: hit temporal correlation cap (%d)", job_id, MAX_TOTAL_CORRELATIONS)
            break

    # 6. Upgrade evidence status for matched NormalizedEvents
    if upgraded_events:
        for evt, _, _ in log_with_ip:
            if evt.event_id in upgraded_events:
                if evt.evidence_status == "observed":
                    evt.evidence_status = "corroborated"
                    evt.corroboration_score = min(
                        1.0, (evt.corroboration_score or 0.0) + 0.3
                    )

    db.commit()

    summary = {
        "log_events": len(log_with_ip),
        "pcap_events": len(pcap_events),
        "matches": total_matches,
        "upgraded_events": len(upgraded_events),
    }
    logger.info("Job %s: temporal correlation complete — %s", job_id, summary)
    return summary