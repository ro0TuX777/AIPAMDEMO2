"""
Incident Slicer — groups related alerts, findings, and connections into
logical attack threads ("slices").

Grouping strategy (deterministic, no LLM):
  1. Seed slices from community_id — alerts and connections sharing a
     community_id belong to the same network conversation.
  2. Merge by host overlap + time proximity — if two proto-slices share
     a host IP and their time ranges overlap (within a configurable window),
     they are merged into one slice.
  3. Attach findings — findings are matched to slices via community_id
     or host IP mention in title/summary/evidence.
  4. Attach IOCs — IOCs are matched to slices by value appearing in
     member alert signatures or finding text.
  5. Rank slices by severity and evidence count.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.finding import Finding
from backend.app.models.ioc import Ioc
from backend.app.models.slice import IncidentSlice

logger = logging.getLogger(__name__)

# Time window for merging slices that share host IPs (seconds)
_MERGE_WINDOW_SECONDS = 600  # 10 minutes

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_SLICE_TYPE_KEYWORDS: dict[str, list[str]] = {
    "c2_session": ["beacon", "c2", "command", "control", "callback", "cobalt"],
    "recon_phase": ["scan", "recon", "discovery", "probe", "enumerat"],
    "lateral": ["lateral", "pivot", "psexec", "smb", "wmi", "rdp"],
    "exfil": ["exfil", "tunnel", "upload", "staging", "leak"],
}


# ── Internal proto-slice ─────────────────────────────────────────────

@dataclass
class _ProtoSlice:
    """Mutable working slice during grouping."""
    community_ids: set[str] = field(default_factory=set)
    host_ips: set[str] = field(default_factory=set)
    alert_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    ioc_ids: list[str] = field(default_factory=list)
    connection_ids: list[str] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)  # for type classification


def _parse_ts(ts: str | None) -> float:
    """Parse an ISO timestamp to epoch seconds. Returns 0 on failure."""
    if not ts:
        return 0.0
    try:
        # Handle various ISO formats
        ts_clean = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        return dt.timestamp()
    except Exception:
        return 0.0


def _time_overlap(a_times: list[str], b_times: list[str], window: float) -> bool:
    """Check if two sets of timestamps are within `window` seconds of each other."""
    a_epochs = [_parse_ts(t) for t in a_times if _parse_ts(t) > 0]
    b_epochs = [_parse_ts(t) for t in b_times if _parse_ts(t) > 0]
    if not a_epochs or not b_epochs:
        return True  # If we can't parse timestamps, assume overlap
    a_min, a_max = min(a_epochs), max(a_epochs)
    b_min, b_max = min(b_epochs), max(b_epochs)
    # Ranges overlap if they are within `window` of each other
    return a_min <= b_max + window and b_min <= a_max + window


def _classify_slice(texts: list[str]) -> str:
    """Determine slice_type from member text content."""
    combined = " ".join(texts).lower()
    for stype, keywords in _SLICE_TYPE_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return stype
    return "attack_thread"


def _overall_severity(severities: list[str]) -> str:
    """Return the highest severity from the list."""
    if not severities:
        return "info"
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))


def _compute_confidence(proto: _ProtoSlice) -> float:
    """Compute grouping confidence based on evidence density."""
    evidence_count = (
        len(proto.alert_ids)
        + len(proto.finding_ids)
        + len(proto.connection_ids)
    )
    cid_count = len(proto.community_ids)
    # More community_ids and evidence = higher confidence
    if cid_count >= 2 and evidence_count >= 4:
        return 0.9
    elif cid_count >= 1 and evidence_count >= 3:
        return 0.7
    elif evidence_count >= 2:
        return 0.5
    return 0.3


# ── Core slicing logic ───────────────────────────────────────────────

def _seed_from_community_ids(
    alerts: list[Alert],
    connections: list[Connection],
) -> dict[str, _ProtoSlice]:
    """Create initial proto-slices keyed by community_id."""
    cid_map: dict[str, _ProtoSlice] = {}

    for alert in alerts:
        cid = alert.community_id
        if not cid:
            continue
        if cid not in cid_map:
            cid_map[cid] = _ProtoSlice()
        proto = cid_map[cid]
        proto.community_ids.add(cid)
        proto.alert_ids.append(alert.alert_id)
        proto.severities.append(alert.severity)
        proto.texts.append(f"{alert.signature} {alert.category or ''}")
        if alert.ts:
            proto.timestamps.append(alert.ts)
        # Collect host IPs from alert
        for ip in [alert.host_ip, alert.src_ip, alert.dest_ip]:
            if ip:
                proto.host_ips.add(ip)

    for conn in connections:
        cid = conn.community_id
        if not cid:
            continue
        if cid not in cid_map:
            cid_map[cid] = _ProtoSlice()
        proto = cid_map[cid]
        proto.community_ids.add(cid)
        proto.connection_ids.append(conn.connection_id)
        if conn.ts:
            proto.timestamps.append(conn.ts)
        for ip in [conn.src_ip, conn.dest_ip]:
            if ip:
                proto.host_ips.add(ip)

    return cid_map


def _merge_proto_slices(protos: list[_ProtoSlice]) -> list[_ProtoSlice]:
    """Merge proto-slices that share host IPs and have overlapping time windows."""
    if len(protos) <= 1:
        return protos

    merged = True
    while merged:
        merged = False
        new_protos: list[_ProtoSlice] = []
        used: set[int] = set()
        for i, a in enumerate(protos):
            if i in used:
                continue
            for j in range(i + 1, len(protos)):
                if j in used:
                    continue
                b = protos[j]
                # Check host overlap
                shared_hosts = a.host_ips & b.host_ips
                if shared_hosts and _time_overlap(a.timestamps, b.timestamps, _MERGE_WINDOW_SECONDS):
                    # Merge b into a
                    a.community_ids |= b.community_ids
                    a.host_ips |= b.host_ips
                    a.alert_ids.extend(b.alert_ids)
                    a.finding_ids.extend(b.finding_ids)
                    a.ioc_ids.extend(b.ioc_ids)
                    a.connection_ids.extend(b.connection_ids)
                    a.timestamps.extend(b.timestamps)
                    a.severities.extend(b.severities)
                    a.texts.extend(b.texts)
                    used.add(j)
                    merged = True
            new_protos.append(a)
        protos = new_protos
    return protos


def _attach_findings(protos: list[_ProtoSlice], findings: list[Finding]) -> None:
    """Match findings to proto-slices by community_id or host IP mention."""
    for finding in findings:
        best_match: _ProtoSlice | None = None
        best_overlap = 0

        for proto in protos:
            overlap = 0
            # Check community_id match
            if finding.community_id and finding.community_id in proto.community_ids:
                overlap += 3

            # Check host IP mention in text
            text = f"{finding.title} {finding.summary or ''} {finding.evidence_json or ''}"
            for ip in proto.host_ips:
                if ip in text:
                    overlap += 1

            if overlap > best_overlap:
                best_overlap = overlap
                best_match = proto

        if best_match and best_overlap > 0:
            best_match.finding_ids.append(finding.finding_id)
            best_match.severities.append(finding.severity)
            best_match.texts.append(f"{finding.title} {finding.summary or ''}")


def _attach_iocs(protos: list[_ProtoSlice], iocs: list[Ioc]) -> None:
    """Match IOCs to proto-slices by value appearing in member text."""
    for ioc in iocs:
        for proto in protos:
            # Check if IOC value appears in any of the slice's text
            combined = " ".join(proto.texts).lower()
            if ioc.value.lower() in combined:
                proto.ioc_ids.append(ioc.ioc_id)
                break
            # Also check if IOC value is a host IP in the slice
            if ioc.value in proto.host_ips:
                proto.ioc_ids.append(ioc.ioc_id)
                break


def _generate_label(proto: _ProtoSlice) -> str:
    """Generate a human-readable label for a slice."""
    stype = _classify_slice(proto.texts)
    hosts = sorted(proto.host_ips)[:3]
    host_str = ", ".join(hosts)
    if len(proto.host_ips) > 3:
        host_str += f" (+{len(proto.host_ips) - 3} more)"

    type_labels = {
        "c2_session": "C2 Session",
        "recon_phase": "Reconnaissance Activity",
        "lateral": "Lateral Movement",
        "exfil": "Data Exfiltration",
        "attack_thread": "Attack Thread",
        "misc": "Related Activity",
    }
    label = type_labels.get(stype, "Attack Thread")
    if host_str:
        label += f" — {host_str}"
    return label


def _generate_summary(proto: _ProtoSlice) -> str:
    """Generate a brief summary of what the slice contains."""
    parts = []
    if proto.alert_ids:
        parts.append(f"{len(proto.alert_ids)} alert(s)")
    if proto.finding_ids:
        parts.append(f"{len(proto.finding_ids)} finding(s)")
    if proto.connection_ids:
        parts.append(f"{len(proto.connection_ids)} connection(s)")
    if proto.ioc_ids:
        parts.append(f"{len(proto.ioc_ids)} IOC(s)")

    severity = _overall_severity(proto.severities)
    summary = f"[{severity.upper()}] Grouped by "
    if proto.community_ids:
        summary += f"{len(proto.community_ids)} shared community ID(s)"
    else:
        summary += "host overlap"
    summary += f" involving {len(proto.host_ips)} host(s). Contains {', '.join(parts)}."
    return summary



# ── Public API ───────────────────────────────────────────────────────

def generate_slices(db: Session, job_id: str, pcap_label: str | None = None) -> list[IncidentSlice]:
    """Generate incident slices for a job.

    Main entry point. Steps:
      1. Gather all alerts, connections, findings, IOCs for the job.
      2. Seed proto-slices from community_id grouping.
      3. Merge proto-slices with shared hosts + time overlap.
      4. Attach orphan alerts (no community_id) to closest slice or create new ones.
      5. Attach findings and IOCs to slices.
      6. Rank, persist, and return.
    """
    # Delete existing slices for this job + label (re-generation)
    del_q = db.query(IncidentSlice).filter(IncidentSlice.job_id == job_id)
    if pcap_label:
        del_q = del_q.filter(IncidentSlice.pcap_label == pcap_label)
    del_q.delete()
    db.flush()

    # Gather evidence (filtered by pcap_label if provided)
    aq = select(Alert).where(Alert.job_id == job_id)
    cq = select(Connection).where(Connection.job_id == job_id)
    fq = select(Finding).where(Finding.job_id == job_id)
    ioq = select(Ioc).where(Ioc.job_id == job_id)
    if pcap_label:
        aq = aq.where(Alert.pcap_label == pcap_label)
        fq = fq.where(Finding.pcap_label == pcap_label)
    alerts = db.execute(aq).scalars().all()
    connections = db.execute(cq).scalars().all()
    findings = db.execute(fq).scalars().all()
    iocs = db.execute(ioq).scalars().all()

    if not alerts and not connections:
        logger.info("No alerts or connections for job=%s, skipping slice generation", job_id)
        return []

    # Step 1: Seed from community_id
    cid_map = _seed_from_community_ids(alerts, connections)
    protos = list(cid_map.values())

    # Step 2: Handle orphan alerts (no community_id)
    for alert in alerts:
        if alert.community_id:
            continue  # Already handled
        # Try to match to existing proto by host IP
        matched = False
        for proto in protos:
            alert_ips = {ip for ip in [alert.host_ip, alert.src_ip, alert.dest_ip] if ip}
            if alert_ips & proto.host_ips:
                if alert.ts and _time_overlap([alert.ts], proto.timestamps, _MERGE_WINDOW_SECONDS):
                    proto.alert_ids.append(alert.alert_id)
                    proto.severities.append(alert.severity)
                    proto.texts.append(f"{alert.signature} {alert.category or ''}")
                    if alert.ts:
                        proto.timestamps.append(alert.ts)
                    proto.host_ips |= alert_ips
                    matched = True
                    break
        if not matched:
            # Create a new proto-slice for this orphan alert
            p = _ProtoSlice()
            p.alert_ids.append(alert.alert_id)
            p.severities.append(alert.severity)
            p.texts.append(f"{alert.signature} {alert.category or ''}")
            if alert.ts:
                p.timestamps.append(alert.ts)
            for ip in [alert.host_ip, alert.src_ip, alert.dest_ip]:
                if ip:
                    p.host_ips.add(ip)
            protos.append(p)

    # Step 3: Merge by host overlap + time proximity
    protos = _merge_proto_slices(protos)

    # Step 4: Attach findings and IOCs
    _attach_findings(protos, findings)
    _attach_iocs(protos, iocs)

    # Step 5: Rank by severity and evidence count
    def _rank_key(p: _ProtoSlice) -> tuple:
        sev = _SEVERITY_RANK.get(_overall_severity(p.severities), 0)
        count = len(p.alert_ids) + len(p.finding_ids) + len(p.connection_ids)
        return (sev, count)

    protos.sort(key=_rank_key, reverse=True)

    # Step 6: Persist
    now = datetime.now(timezone.utc).isoformat()
    slices: list[IncidentSlice] = []
    for rank, proto in enumerate(protos, 1):
        # Skip trivial slices (single connection, no alerts/findings)
        if not proto.alert_ids and not proto.finding_ids:
            continue

        timestamps_parsed = sorted([t for t in proto.timestamps if t])
        incident_slice = IncidentSlice(
            job_id=job_id,
            slice_id=f"SL-{uuid4().hex[:8]}",
            label=_generate_label(proto),
            slice_type=_classify_slice(proto.texts),
            severity=_overall_severity(proto.severities),
            confidence=_compute_confidence(proto),
            community_ids_json=json.dumps(sorted(proto.community_ids)) if proto.community_ids else None,
            host_ips_json=json.dumps(sorted(proto.host_ips)) if proto.host_ips else None,
            time_start=timestamps_parsed[0] if timestamps_parsed else None,
            time_end=timestamps_parsed[-1] if timestamps_parsed else None,
            alert_ids_json=json.dumps(proto.alert_ids) if proto.alert_ids else None,
            finding_ids_json=json.dumps(proto.finding_ids) if proto.finding_ids else None,
            ioc_ids_json=json.dumps(proto.ioc_ids) if proto.ioc_ids else None,
            connection_ids_json=json.dumps(proto.connection_ids) if proto.connection_ids else None,
            summary=_generate_summary(proto),
            rank=rank,
            pcap_label=pcap_label,
            created_at=now,
        )
        db.add(incident_slice)
        slices.append(incident_slice)

    db.commit()
    logger.info(
        "Generated %d slices for job=%s (from %d alerts, %d connections)",
        len(slices), job_id, len(alerts), len(connections),
    )
    return slices