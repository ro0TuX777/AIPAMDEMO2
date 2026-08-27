"""Cross-source temporal correlator — enhanced alignment framework.

Joins NormalizedEvents (from logs) with PCAP-derived entities (Alerts,
Connections) using a layered evidence model rather than IP + time alone:

  1. Source alignment / clock-offset estimation — strong anchors
     (community_id, then 5-tuple) are used to estimate a per-log-source clock
     offset relative to the PCAP timeline, so log and PCAP timestamps are
     compared on a common clock.
  2. Multi-key correlation — candidates are matched on community_id (strongest),
     5-tuple (src/dest/proto, direction-agnostic), then shared IP (weakest).
  3. Explainable scoring — a composite of key strength, post-alignment time
     proximity, label agreement, and directionality.
  4. Label-aware matching — phase labels (before/during/after/baseline/exploit)
     on both sides reduce the score when they disagree.

This bridges host-level telemetry (C2 logs, command output) and network-level
evidence (IDS alerts, flow records), producing TemporalCorrelation rows.

Called after both PCAP and telemetry pipelines complete for hybrid jobs.
Backward compatible: the legacy shared-IP + ±30s behaviour remains the
fallback when no strong keys are present.
"""

from __future__ import annotations

import json
import logging
import statistics
from datetime import datetime
from typing import Any, NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.finding import Finding
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.temporal_correlation import TemporalCorrelation
from backend.app.normalize.network_events import PCAP_NORMALIZER_PARSER

logger = logging.getLogger("aipam.temporal_correlator")

# ── Configuration ─────────────────────────────────────────────────────────

DEFAULT_WINDOW_SECONDS = 30.0       # ±30 s gate for IP-only matches
STRONG_KEY_WINDOW_SECONDS = 300.0   # ±5 min gate for community_id / 5-tuple
MAX_MATCHES_PER_EVENT = 10          # cap per log event to avoid explosion
MAX_TOTAL_CORRELATIONS = 5000       # safety cap per job

# Findings are aggregates (a beaconing verdict, an alert group), not point-in-time
# packets — their ts is only an anchor into a span, so the gate is widened rather
# than applied as if it were an exact observation.
FINDING_WINDOW_MULTIPLIER = 6.0

# Uploaded telemetry that constitutes ground truth about attacker activity: a C2
# operator log states what was actually run, so a detection it lines up with is
# confirmed rather than merely corroborated by a second sensor.
GROUND_TRUTH_EVENT_TYPES = frozenset({"c2_callback", "c2_task"})
GROUND_TRUTH_SOURCE_TYPES = frozenset({"c2_bundle"})

# Ranking nudge so ground-truth matches surface above ordinary ones.
_GROUND_TRUTH_BONUS = 1.15

# "Confirmed" is the strongest claim the system makes — it tells an analyst to
# stop asking whether a detection is a false positive. A ground-truth log that
# merely shares a host IP somewhere inside the (widened) finding window is not
# enough: on a busy victim host every uploaded event overlaps every finding, and
# confirming all of them confirms nothing. Weaker ground-truth matches still
# corroborate, they just don't promote.
MIN_SCORE_FOR_CONFIRMATION = 0.45

# Cap on hosts read out of a finding's evidence blob — an alert group can name
# hundreds, and each one widens the candidate fan-out.
_MAX_EVIDENCE_IPS = 32

MIN_ANCHORS_FOR_OFFSET = 3          # min strong anchors to trust a clock offset
MAX_OFFSET_SECONDS = 3600.0         # ignore absurd (>1 h) estimated offsets

# Match-key identifiers, strongest → weakest.
KEY_COMMUNITY = "community_id"
KEY_FIVE_TUPLE = "five_tuple"
KEY_IP = "ip"

# Relative strength of each key as standalone evidence.
_KEY_STRENGTH: dict[str, float] = {
    KEY_COMMUNITY: 1.0,
    KEY_FIVE_TUPLE: 0.85,
    KEY_IP: 0.5,
}

_CONFIDENCE_HIGH = 0.75
_CONFIDENCE_MEDIUM = 0.45


# ── Helpers ───────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string into a datetime."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _tuple_key(
    a_ip: str | None, a_port: int | None,
    b_ip: str | None, b_port: int | None,
    proto: str | None,
) -> tuple | None:
    """Build a direction-agnostic 5-tuple key, or None if endpoints are missing.

    Endpoints are sorted so that (A→B) and (B→A) produce the same key; this
    lets a log that records a flow from either perspective match the PCAP.
    """
    if not a_ip or not b_ip:
        return None
    endpoints = tuple(sorted([(a_ip, a_port or 0), (b_ip, b_port or 0)]))
    return (proto or "").lower(), endpoints


class _PcapEvent(NamedTuple):
    """Lightweight representation of a PCAP-derived entity for matching."""
    entity_type: str        # "alert" | "connection" | "finding"
    entity_id: str
    summary: str
    ts: datetime
    ips: frozenset[str]         # all IPs associated with this entity
    community_id: str | None
    tuple_key: tuple | None
    src_ip: str | None
    dest_ip: str | None
    label: str | None
    window_multiplier: float = 1.0   # widens the time gate for aggregate entities


class _LogEvent(NamedTuple):
    """Lightweight representation of a NormalizedEvent for matching."""
    event: NormalizedEvent
    ts: datetime
    ips: frozenset[str]
    community_id: str | None
    tuple_key: tuple | None
    src_ip: str | None
    dest_ip: str | None
    label: str | None
    source: str | None          # log source_system, used for offset grouping
    is_ground_truth: bool = False


def _is_ground_truth(evt: NormalizedEvent) -> bool:
    """True when this uploaded event attests to attacker activity directly."""
    return (
        (evt.event_type or "") in GROUND_TRUTH_EVENT_TYPES
        or (evt.source_type or "") in GROUND_TRUTH_SOURCE_TYPES
    )


def _label_factor(log_label: str | None, pcap_label: str | None) -> float:
    """Penalise matches whose phase labels disagree; neutral when unknown."""
    if log_label and pcap_label:
        return 1.0 if log_label == pcap_label else 0.7
    return 1.0


def _direction_factor(log_evt: _LogEvent, pe: _PcapEvent) -> float:
    """Small bonus when src/dest orientation agrees between the two sides."""
    if log_evt.src_ip and log_evt.dest_ip and pe.src_ip and pe.dest_ip:
        same = log_evt.src_ip == pe.src_ip and log_evt.dest_ip == pe.dest_ip
        return 1.0 if same else 0.95
    return 1.0


def _matched_keys(log_evt: _LogEvent, pe: _PcapEvent) -> list[str]:
    """Return every correlation key shared by a log/PCAP pair, strongest first."""
    keys: list[str] = []
    if log_evt.community_id and pe.community_id and log_evt.community_id == pe.community_id:
        keys.append(KEY_COMMUNITY)
    if log_evt.tuple_key and pe.tuple_key and log_evt.tuple_key == pe.tuple_key:
        keys.append(KEY_FIVE_TUPLE)
    if log_evt.ips & pe.ips:
        keys.append(KEY_IP)
    return keys


def _shared_ip(log_evt: _LogEvent, pe: _PcapEvent) -> str:
    """Best representative shared IP, falling back to community_id then '-'."""
    common = log_evt.ips & pe.ips
    if common:
        return sorted(common)[0]
    if log_evt.community_id and log_evt.community_id == pe.community_id:
        return log_evt.community_id
    return log_evt.src_ip or pe.src_ip or pe.dest_ip or "-"


def _confidence_band(score: float) -> str:
    if score >= _CONFIDENCE_HIGH:
        return "high"
    if score >= _CONFIDENCE_MEDIUM:
        return "medium"
    return "low"


def _score_match(
    strongest_key: str,
    adjusted_delta: float,
    window: float,
    log_evt: _LogEvent,
    pe: _PcapEvent,
) -> float:
    """Composite 0–1 score: key strength × time × label × directionality.

    Strong keys retain a score floor even when timestamps are far apart, since
    the key itself is authoritative; weak IP-only matches are dominated by time.
    """
    if adjusted_delta >= window:
        return 0.0
    time_factor = 1.0 - (adjusted_delta / window)
    key_strength = _KEY_STRENGTH[strongest_key]
    # Strong keys: 0.4 floor + 0.6 time-weighted. IP-only: time is the gate.
    if strongest_key == KEY_IP:
        time_component = time_factor
    else:
        time_component = 0.4 + 0.6 * time_factor
    score = (
        key_strength
        * time_component
        * _label_factor(log_evt.label, pe.label)
        * _direction_factor(log_evt, pe)
    )
    if log_evt.is_ground_truth:
        score *= _GROUND_TRUTH_BONUS
    return round(max(0.0, min(1.0, score)), 3)


def _estimate_clock_offsets(
    log_events: list[_LogEvent],
    pcap_events: list[_PcapEvent],
) -> dict[str, float]:
    """Estimate a per-log-source clock offset (log_ts - pcap_ts) in seconds.

    Uses strong anchors only: community_id matches first, then 5-tuple. The
    median signed delta across anchors is the offset. Sources with too few
    anchors, or an implausibly large offset, are treated as un-aligned (0.0).
    """
    pcap_by_community: dict[str, list[_PcapEvent]] = {}
    pcap_by_tuple: dict[tuple, list[_PcapEvent]] = {}
    for pe in pcap_events:
        if pe.community_id:
            pcap_by_community.setdefault(pe.community_id, []).append(pe)
        if pe.tuple_key:
            pcap_by_tuple.setdefault(pe.tuple_key, []).append(pe)

    deltas_by_source: dict[str, list[float]] = {}
    for le in log_events:
        source = le.source or "_unknown"
        anchors: list[_PcapEvent] = []
        if le.community_id:
            anchors = pcap_by_community.get(le.community_id, [])
        if not anchors and le.tuple_key:
            anchors = pcap_by_tuple.get(le.tuple_key, [])
        if not anchors:
            continue
        # Nearest anchor by raw delta is the most reliable per-event signal.
        nearest = min(anchors, key=lambda pe: abs((le.ts - pe.ts).total_seconds()))
        deltas_by_source.setdefault(source, []).append(
            (le.ts - nearest.ts).total_seconds()
        )

    offsets: dict[str, float] = {}
    for source, deltas in deltas_by_source.items():
        if len(deltas) < MIN_ANCHORS_FOR_OFFSET:
            continue
        offset = statistics.median(deltas)
        if abs(offset) > MAX_OFFSET_SECONDS:
            continue
        offsets[source] = round(offset, 3)
    if offsets:
        logger.info("Estimated clock offsets (log→PCAP, s): %s", offsets)
    return offsets


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


# ── Builders ──────────────────────────────────────────────────────────────

def _build_log_events(db: Session, job_id: str) -> list[_LogEvent]:
    """Load log-derived NormalizedEvents that carry a correlation handle.

    PCAP-derived rows are excluded. ``normalize_network_events`` writes zeek /
    suricata records into the same table so the Raw Events explorer works for
    plain captures — but the PCAP side of this join (Alert/Connection) is built
    from those very same sensor records. Leaving them in makes every zeek flow
    correlate with itself on an exact ``community_id`` at a zero time delta,
    which scores at the ceiling and buries (or, past MAX_TOTAL_CORRELATIONS,
    evicts) the real log ↔ PCAP matches this stage exists to find.
    """
    rows = db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.parser_name.is_distinct_from(PCAP_NORMALIZER_PARSER),
        )
    ).scalars().all()

    out: list[_LogEvent] = []
    for evt in rows:
        ts = _parse_ts(evt.timestamp)
        if not ts:
            continue
        ips = frozenset(ip for ip in (evt.src_ip, evt.dest_ip) if ip)
        tuple_key = _tuple_key(evt.src_ip, evt.src_port, evt.dest_ip, evt.dest_port, evt.proto)
        if not ips and not evt.community_id and not tuple_key:
            continue
        out.append(_LogEvent(
            event=evt,
            ts=ts,
            ips=ips,
            community_id=evt.community_id,
            tuple_key=tuple_key,
            src_ip=evt.src_ip,
            dest_ip=evt.dest_ip,
            label=evt.pcap_label,
            source=evt.source_system,
            is_ground_truth=_is_ground_truth(evt),
        ))
    return out


def _build_pcap_events(db: Session, job_id: str) -> list[_PcapEvent]:
    """Load PCAP-derived alerts, connections and findings with correlation handles.

    Findings are the entity users actually act on — "is this detection real?" —
    so they are counterparties in their own right, not just via the alerts that
    produced them. A finding with no ``ts`` is skipped: sensors emit one, but
    rows written before the column existed have nothing to anchor a window on.
    """
    out: list[_PcapEvent] = []

    for a in db.execute(select(Alert).where(Alert.job_id == job_id)).scalars().all():
        ts = _parse_ts(a.ts)
        if not ts:
            continue
        ips = frozenset(ip for ip in (a.src_ip, a.dest_ip, a.host_ip) if ip)
        tuple_key = _tuple_key(a.src_ip, a.src_port, a.dest_ip, a.dest_port, a.proto)
        if not ips and not a.community_id and not tuple_key:
            continue
        out.append(_PcapEvent(
            entity_type="alert",
            entity_id=a.alert_id,
            summary=_build_alert_summary(a),
            ts=ts,
            ips=ips,
            community_id=a.community_id,
            tuple_key=tuple_key,
            src_ip=a.src_ip,
            dest_ip=a.dest_ip,
            label=a.pcap_label,
        ))

    for c in db.execute(select(Connection).where(Connection.job_id == job_id)).scalars().all():
        ts = _parse_ts(c.ts)
        if not ts:
            continue
        ips = frozenset(ip for ip in (c.src_ip, c.dest_ip) if ip)
        tuple_key = _tuple_key(c.src_ip, c.src_port, c.dest_ip, c.dest_port, c.proto)
        if not ips and not c.community_id and not tuple_key:
            continue
        summary = f"{c.src_ip}:{c.src_port} → {c.dest_ip}:{c.dest_port} ({c.proto or '?'})"
        out.append(_PcapEvent(
            entity_type="connection",
            entity_id=c.connection_id,
            summary=summary,
            ts=ts,
            ips=ips,
            community_id=c.community_id,
            tuple_key=tuple_key,
            src_ip=c.src_ip,
            dest_ip=c.dest_ip,
            label=c.pcap_label,
        ))

    for f in db.execute(select(Finding).where(Finding.job_id == job_id)).scalars().all():
        ts = _parse_ts(f.ts)
        if not ts:
            continue
        ips = frozenset(ip for ip in (f.src_ip, f.dest_ip, *_finding_evidence_ips(f)) if ip)
        if not ips and not f.community_id:
            continue
        out.append(_PcapEvent(
            entity_type="finding",
            entity_id=f.finding_id,
            summary=f"[{f.severity}] {f.title}",
            ts=ts,
            ips=ips,
            community_id=f.community_id,
            tuple_key=None,     # findings carry no ports, so no 5-tuple
            src_ip=f.src_ip,
            dest_ip=f.dest_ip,
            label=f.pcap_label,
            window_multiplier=FINDING_WINDOW_MULTIPLIER,
        ))

    return out


def _finding_evidence_ips(finding: Finding) -> list[str]:
    """Pull affected hosts out of a finding's evidence blob.

    Alert-group findings list every host that fired the rule under
    ``affected_hosts``; matching only on src_ip/dest_ip would miss the rest.
    """
    if not finding.evidence_json:
        return []
    try:
        ev = json.loads(finding.evidence_json)
    except (ValueError, TypeError):
        return []
    if not isinstance(ev, dict):
        return []
    hosts = ev.get("affected_hosts")
    if not isinstance(hosts, list):
        return []
    return [h for h in hosts if isinstance(h, str) and h][:_MAX_EVIDENCE_IPS]


# ── Main entry point ─────────────────────────────────────────────────────

def correlate_temporal(
    db: Session,
    job_id: str,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> dict[str, Any]:
    """Run enhanced cross-source temporal correlation for a job.

    Aligns log/PCAP clocks via strong anchors, then correlates on
    community_id → 5-tuple → shared IP with an explainable composite score.
    Returns a summary dict with counts.
    """
    log_events = _build_log_events(db, job_id)
    if not log_events:
        logger.info("Job %s: no correlatable log events — skipping temporal correlation", job_id)
        return {"log_events": 0, "pcap_events": 0, "matches": 0}

    pcap_events = _build_pcap_events(db, job_id)
    if not pcap_events:
        logger.info("Job %s: no correlatable PCAP events — skipping temporal correlation", job_id)
        return {"log_events": len(log_events), "pcap_events": 0, "matches": 0}

    logger.info(
        "Job %s: temporal correlation — %d log events × %d PCAP events "
        "(ip window=±%.0fs, strong-key window=±%.0fs)",
        job_id, len(log_events), len(pcap_events), window_seconds, STRONG_KEY_WINDOW_SECONDS,
    )

    # Source alignment: estimate per-log-source clock offsets from strong anchors.
    offsets = _estimate_clock_offsets(log_events, pcap_events)

    # Candidate indexes for fast lookup.
    pcap_by_community: dict[str, list[_PcapEvent]] = {}
    pcap_by_tuple: dict[tuple, list[_PcapEvent]] = {}
    ip_to_pcap: dict[str, list[_PcapEvent]] = {}
    for pe in pcap_events:
        if pe.community_id:
            pcap_by_community.setdefault(pe.community_id, []).append(pe)
        if pe.tuple_key:
            pcap_by_tuple.setdefault(pe.tuple_key, []).append(pe)
        for ip in pe.ips:
            ip_to_pcap.setdefault(ip, []).append(pe)

    # Clear previous correlations for this job (idempotent re-run).
    db.query(TemporalCorrelation).filter(TemporalCorrelation.job_id == job_id).delete()
    db.flush()

    total_matches = 0
    upgraded: dict[str, float] = {}   # event_id → best score
    # finding_id → (best score, attesting source_systems, any ground truth?)
    finding_support: dict[str, tuple[float, set[str], bool]] = {}
    capped = False

    for le in log_events:
        offset = offsets.get(le.source or "_unknown", 0.0)

        # Gather unique candidate PCAP events across all key indexes.
        candidates: dict[tuple[str, str], _PcapEvent] = {}
        if le.community_id:
            for pe in pcap_by_community.get(le.community_id, []):
                candidates[(pe.entity_type, pe.entity_id)] = pe
        if le.tuple_key:
            for pe in pcap_by_tuple.get(le.tuple_key, []):
                candidates[(pe.entity_type, pe.entity_id)] = pe
        for ip in le.ips:
            for pe in ip_to_pcap.get(ip, []):
                candidates[(pe.entity_type, pe.entity_id)] = pe

        scored: list[tuple[float, _PcapEvent, list[str], float]] = []
        for pe in candidates.values():
            keys = _matched_keys(le, pe)
            if not keys:
                continue
            strongest = keys[0]
            window = window_seconds if strongest == KEY_IP else STRONG_KEY_WINDOW_SECONDS
            window *= pe.window_multiplier
            adjusted_delta = abs((le.ts - pe.ts).total_seconds() - offset)
            score = _score_match(strongest, adjusted_delta, window, le, pe)
            if score <= 0:
                continue
            scored.append((score, pe, keys, adjusted_delta))

        scored.sort(key=lambda t: t[0], reverse=True)
        for score, pe, keys, adjusted_delta in scored[:MAX_MATCHES_PER_EVENT]:
            raw_delta = abs((le.ts - pe.ts).total_seconds())
            strongest = keys[0]
            match_type = "ip_temporal" if strongest == KEY_IP else strongest
            shared_community = (
                le.community_id if (le.community_id and le.community_id == pe.community_id) else None
            )
            db.add(TemporalCorrelation(
                job_id=job_id,
                log_event_id=le.event.event_id,
                log_source=le.event.source_system,
                log_source_filename=le.event.source_filename,
                log_event_type=le.event.event_type,
                log_timestamp=le.event.timestamp,
                log_summary=_build_log_summary(le.event),
                pcap_entity_type=pe.entity_type,
                pcap_entity_id=pe.entity_id,
                pcap_summary=pe.summary[:_MAX_SUMMARY_LEN] if pe.summary else None,
                pcap_timestamp=pe.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                shared_ip=_shared_ip(le, pe),
                time_delta_seconds=round(raw_delta, 3),
                match_score=score,
                match_type=match_type,
                community_id=shared_community,
                match_keys_json=json.dumps(keys),
                log_label=le.label,
                pcap_label=pe.label,
                clock_offset_seconds=round(offset, 3),
                adjusted_time_delta_seconds=round(adjusted_delta, 3),
                confidence_band=_confidence_band(score),
            ))
            total_matches += 1
            prev = upgraded.get(le.event.event_id, 0.0)
            upgraded[le.event.event_id] = max(prev, score)

            if pe.entity_type == "finding":
                best, sources, truth = finding_support.get(pe.entity_id, (0.0, set(), False))
                sources.add(le.source or le.event.parser_name or "unknown")
                attests = le.is_ground_truth and score >= MIN_SCORE_FOR_CONFIRMATION
                finding_support[pe.entity_id] = (
                    max(best, score), sources, truth or attests,
                )

            if total_matches >= MAX_TOTAL_CORRELATIONS:
                capped = True
                break
        if capped:
            logger.warning("Job %s: hit temporal correlation cap (%d)", job_id, MAX_TOTAL_CORRELATIONS)
            break

    # Upgrade evidence status for matched NormalizedEvents, weighted by score.
    for le in log_events:
        best = upgraded.get(le.event.event_id)
        if best is None:
            continue
        if le.event.evidence_status == "observed":
            le.event.evidence_status = "corroborated"
            le.event.corroboration_score = min(
                1.0, (le.event.corroboration_score or 0.0) + round(0.3 * best, 3)
            )

    confirmed_findings = _apply_finding_support(db, job_id, finding_support)

    db.commit()

    summary = {
        "log_events": len(log_events),
        "pcap_events": len(pcap_events),
        "matches": total_matches,
        "upgraded_events": len(upgraded),
        "supported_findings": len(finding_support),
        "confirmed_findings": confirmed_findings,
        "clock_offsets": offsets,
    }
    logger.info("Job %s: temporal correlation complete — %s", job_id, summary)
    return summary


def _apply_finding_support(
    db: Session,
    job_id: str,
    support: dict[str, tuple[float, set[str], bool]],
) -> int:
    """Write uploaded-log attestation back onto the findings it supports.

    A finding an uploaded log lines up with is *corroborated*; one a ground-truth
    source attests to (a C2 operator log recording the task that was actually
    run) is *confirmed* — the analyst can stop asking whether the detection is a
    false positive. Returns the number promoted to confirmed.
    """
    if not support:
        return 0

    rows = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            Finding.finding_id.in_(list(support)),
        )
    ).scalars().all()

    confirmed = 0
    for finding in rows:
        best, sources, ground_truth = support[finding.finding_id]
        finding.evidence_status = "confirmed" if ground_truth else "corroborated"
        finding.corroboration_score = best
        finding.corroborating_sources_json = json.dumps(sorted(sources))
        # An independently attested detection is worth more than the sensor's
        # own confidence; ground truth pins it outright.
        if ground_truth:
            finding.confidence = 1.0
            confirmed += 1
        else:
            finding.confidence = round(
                min(1.0, (finding.confidence or 0.0) + 0.2 * best), 2
            )
    return confirmed