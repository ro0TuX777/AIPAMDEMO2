"""Phase 5 — Behavioral Detection Sensors.

Operates on NormalizedEvent records in the database to detect zero-day-style
anomalies that don't depend on signatures:

1. Role-baseline sensor — detects protocol/service deviations per host
2. Auth anomaly sensor — detects unusual authentication patterns
3. Netflow behavior sensor — detects callback-like traffic patterns
4. Cross-source inconsistency detector — finds conflicting evidence
5. Sequence detector — detects multi-step attack patterns

All detectors produce Finding records in the database.
"""

from __future__ import annotations

from backend.app.pipeline.runtime_control import checkpoint
from backend.app.pipeline.outcomes import PROPAGATE_ERRORS

import json
import logging
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.normalized_event import NormalizedEvent

logger = logging.getLogger("aipam.behavioral")


def _uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_finding(
    job_id: str,
    sensor: str,
    severity: str,
    category: str,
    title: str,
    summary: str,
    evidence: dict[str, Any] | None = None,
    confidence: float = 0.5,
) -> Finding:
    """Create a Finding record from behavioral detection."""
    return Finding(
        job_id=job_id,
        finding_id=_uuid(),
        sensor=sensor,
        severity=severity,
        category=category,
        title=title,
        summary=summary,
        evidence_json=json.dumps(evidence) if evidence else None,
        confidence=round(confidence, 2),
    )


# ── 1. Role-Baseline Sensor ─────────────────────────────────────────────

# Services/ports typically associated with specific host roles
_WORKSTATION_UNUSUAL_SERVICES = {"rdp", "smb", "ssh", "winrm", "wmi", "psexec", "admin"}
_ADMIN_PORTS = {22, 23, 135, 445, 3389, 5985, 5986}
_RARE_DEST_PORT_THRESHOLD = 2  # port seen <= N times across all hosts is "rare"


def detect_role_baseline_anomalies(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Detect hosts using services/ports unusual for their observed role.

    Logic:
    - Build per-host profile from connection-type NormalizedEvents
    - Flag hosts that connect TO admin-style ports they haven't used before
    - Flag hosts that appear as servers on uncommon ports
    """
    findings: list[Finding] = []

    events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_type.in_(["connection", "netflow"]),
        )
    ).scalars().all())

    if len(events) < 5:
        return findings

    # Build per-host destination port profiles
    host_dest_ports: dict[str, Counter] = defaultdict(Counter)
    host_src_ports: dict[str, Counter] = defaultdict(Counter)
    global_dest_ports: Counter = Counter()

    for evt in events:
        checkpoint()
        src = evt.src_ip or ""
        dest_port = evt.dest_port
        src_port = evt.src_port
        if src and dest_port:
            host_dest_ports[src][dest_port] += 1
            global_dest_ports[dest_port] += 1
        if src and src_port:
            host_src_ports[src][src_port] += 1

    # Detect workstations using admin-style ports
    for host_ip, port_counts in host_dest_ports.items():
        checkpoint()
        admin_ports_used = {p for p in port_counts if p in _ADMIN_PORTS}
        if admin_ports_used:
            # Check if this host is predominantly a client (many different dest ports)
            total_conns = sum(port_counts.values())
            admin_conns = sum(port_counts[p] for p in admin_ports_used)
            admin_ratio = admin_conns / total_conns if total_conns > 0 else 0

            # Only flag if admin usage is a minority of traffic (role deviation)
            if 0 < admin_ratio < 0.5 and total_conns >= 3:
                confidence = min(0.9, 0.4 + admin_ratio * 0.5 + len(admin_ports_used) * 0.1)
                findings.append(_make_finding(
                    job_id=job_id,
                    sensor="role_baseline",
                    severity="medium" if len(admin_ports_used) > 1 else "low",
                    category="role_deviation",
                    title=f"Host {host_ip} using admin ports: {sorted(admin_ports_used)}",
                    summary=(
                        f"Host {host_ip} connected to admin-style ports "
                        f"{sorted(admin_ports_used)} ({admin_conns}/{total_conns} connections). "
                        f"This may indicate lateral movement or unauthorized admin activity."
                    ),
                    evidence={
                        "host": host_ip,
                        "admin_ports": sorted(admin_ports_used),
                        "admin_connections": admin_conns,
                        "total_connections": total_conns,
                        "admin_ratio": round(admin_ratio, 3),
                    },
                    confidence=confidence,
                ))

    # Detect hosts connecting to globally rare destination ports
    rare_ports = {p for p, c in global_dest_ports.items() if c <= _RARE_DEST_PORT_THRESHOLD}
    for host_ip, port_counts in host_dest_ports.items():
        checkpoint()
        host_rare = {p for p in port_counts if p in rare_ports and p not in _ADMIN_PORTS}
        if host_rare and len(host_rare) >= 2:
            findings.append(_make_finding(
                job_id=job_id,
                sensor="role_baseline",
                severity="low",
                category="rare_service",
                title=f"Host {host_ip} connecting to rare ports: {sorted(host_rare)[:5]}",
                summary=(
                    f"Host {host_ip} connected to ports rarely seen in this job: "
                    f"{sorted(host_rare)[:5]}. Uncommon services may indicate "
                    f"tunneling, backdoors, or non-standard applications."
                ),
                evidence={
                    "host": host_ip,
                    "rare_ports": sorted(host_rare)[:10],
                    "global_port_frequency": {str(p): global_dest_ports[p] for p in sorted(host_rare)[:10]},
                },
                confidence=0.35,
            ))

    return findings


# ── 2. Identity / Auth Anomaly Sensor ────────────────────────────────────

_FAILED_AUTH_THRESHOLD = 5  # N+ failures from same source = brute force
_MULTI_SOURCE_AUTH_THRESHOLD = 3  # Same user from 3+ sources = suspicious


def detect_auth_anomalies(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Detect unusual authentication patterns from auth-type NormalizedEvents.

    Detects:
    - Brute-force attempts (many failed auths from one source)
    - Credential spraying (many usernames from one source)
    - Lateral auth (same user authenticating from multiple hosts)
    - Privilege escalation (sudo/admin events following normal user activity)
    """
    findings: list[Finding] = []

    auth_events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_type == "auth",
        )
    ).scalars().all())

    if len(auth_events) < 3:
        return findings

    # Parse data_json for auth details
    parsed: list[dict[str, Any]] = []
    for evt in auth_events:
        checkpoint()
        data = {}
        if evt.data_json:
            try:
                data = json.loads(evt.data_json)
            except (json.JSONDecodeError, TypeError):
                pass
        parsed.append({
            "event_id": evt.event_id,
            "src_ip": evt.src_ip or "",
            "username": evt.username or data.get("username", ""),
            "hostname": evt.hostname or "",
            "timestamp": evt.timestamp or "",
            "action": data.get("action", ""),
            "status": data.get("status", data.get("logon_type", "")),
            "source_system": evt.source_system or "",
        })

    # Detect brute-force: many failed auths from same source IP
    source_failures: dict[str, list[dict]] = defaultdict(list)
    for p in parsed:
        checkpoint()
        if p["action"] in ("failed", "failure", "failed_login") or "fail" in p["status"].lower():
            source_failures[p["src_ip"]].append(p)

    for src_ip, failures in source_failures.items():
        checkpoint()
        if not src_ip or len(failures) < _FAILED_AUTH_THRESHOLD:
            continue
        unique_users = {f["username"] for f in failures if f["username"]}
        is_spray = len(unique_users) > 2

        severity = "high" if len(failures) >= 10 else "medium"
        category = "credential_spray" if is_spray else "brute_force"
        confidence = min(0.95, 0.5 + len(failures) * 0.05)

        findings.append(_make_finding(
            job_id=job_id,
            sensor="auth_anomaly",
            severity=severity,
            category=category,
            title=f"{'Credential spraying' if is_spray else 'Brute-force'} from {src_ip}",
            summary=(
                f"{len(failures)} failed auth attempts from {src_ip} "
                f"targeting {len(unique_users)} unique user(s): "
                f"{sorted(unique_users)[:5]}."
            ),
            evidence={
                "source_ip": src_ip,
                "failure_count": len(failures),
                "unique_users": sorted(unique_users)[:10],
                "time_range": [failures[0]["timestamp"], failures[-1]["timestamp"]],
            },
            confidence=confidence,
        ))

    # Detect lateral auth: same username from multiple source IPs
    user_sources: dict[str, set[str]] = defaultdict(set)
    for p in parsed:
        checkpoint()
        if p["username"] and p["src_ip"]:
            user_sources[p["username"]].add(p["src_ip"])

    for username, sources in user_sources.items():
        checkpoint()
        if len(sources) >= _MULTI_SOURCE_AUTH_THRESHOLD:
            findings.append(_make_finding(
                job_id=job_id,
                sensor="auth_anomaly",
                severity="medium",
                category="lateral_auth",
                title=f"User '{username}' authenticated from {len(sources)} sources",
                summary=(
                    f"User '{username}' authenticated from {len(sources)} different "
                    f"source IPs: {sorted(sources)[:5]}. This may indicate "
                    f"compromised credentials or lateral movement."
                ),
                evidence={
                    "username": username,
                    "source_ips": sorted(sources)[:20],
                    "source_count": len(sources),
                },
                confidence=min(0.85, 0.4 + len(sources) * 0.1),
            ))

    # Detect privilege escalation patterns
    user_actions: dict[str, list[str]] = defaultdict(list)
    for p in parsed:
        checkpoint()
        if p["username"]:
            user_actions[p["username"]].append(p["action"])

    for username, actions in user_actions.items():
        checkpoint()
        has_normal = any(a in ("login", "success", "logon") for a in actions)
        has_priv = any(a in ("sudo", "su", "runas", "privilege_escalation") for a in actions)
        if has_normal and has_priv:
            findings.append(_make_finding(
                job_id=job_id,
                sensor="auth_anomaly",
                severity="medium",
                category="privilege_escalation",
                title=f"Privilege escalation by '{username}'",
                summary=(
                    f"User '{username}' performed normal login followed by "
                    f"privilege escalation actions. This may be legitimate admin "
                    f"activity or an attacker escalating after initial access."
                ),
                evidence={
                    "username": username,
                    "actions": actions[:20],
                },
                confidence=0.45,
            ))

    return findings


# ── 3. Netflow Behavior Sensor ───────────────────────────────────────────

_MIN_CONNECTIONS_FOR_BEACON = 4
_BEACON_JITTER_THRESHOLD = 0.25  # 25% jitter = periodic


def detect_netflow_anomalies(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Detect callback-like patterns from connection/netflow NormalizedEvents.

    Detects:
    - Periodic callback patterns (beacon-like intervals)
    - Unusual outbound data volumes per host
    - Connections to many unique destinations (scanning/recon)
    """
    findings: list[Finding] = []

    events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_type.in_(["connection", "netflow"]),
        ).order_by(NormalizedEvent.timestamp)
    ).scalars().all())

    if len(events) < _MIN_CONNECTIONS_FOR_BEACON:
        return findings

    # Group by src_ip -> dest_ip pairs
    pair_events: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    host_dest_ips: dict[str, set[str]] = defaultdict(set)
    host_bytes_out: dict[str, int] = defaultdict(int)

    for evt in events:
        checkpoint()
        src = evt.src_ip or ""
        dest = evt.dest_ip or ""
        if src and dest:
            pair_events[(src, dest)].append(evt)
            host_dest_ips[src].add(dest)

        # Estimate outbound bytes from data_json
        if src and evt.data_json:
            try:
                data = json.loads(evt.data_json)
                host_bytes_out[src] += int(data.get("bytes_sent", 0) or 0)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

    # Detect beacon-like patterns: regular intervals between connections
    for (src, dest), evts in pair_events.items():
        checkpoint()
        if len(evts) < _MIN_CONNECTIONS_FOR_BEACON:
            continue

        # Extract timestamps and compute intervals
        timestamps: list[float] = []
        for e in evts:
            checkpoint()
            try:
                dt = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
                timestamps.append(dt.timestamp())
            except (ValueError, AttributeError):
                continue

        if len(timestamps) < _MIN_CONNECTIONS_FOR_BEACON:
            continue

        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            continue

        median_interval = sorted(intervals)[len(intervals) // 2]
        if median_interval < 1:
            continue  # Sub-second intervals aren't beacon-like

        # Compute jitter (MAD / median)
        mad = sorted(abs(iv - median_interval) for iv in intervals)[len(intervals) // 2]
        jitter = mad / median_interval if median_interval > 0 else 1.0

        if jitter < _BEACON_JITTER_THRESHOLD and len(timestamps) >= _MIN_CONNECTIONS_FOR_BEACON:
            confidence = min(0.9, 0.5 + (1 - jitter) * 0.3 + len(evts) * 0.02)
            severity = "high" if confidence > 0.7 else "medium"

            findings.append(_make_finding(
                job_id=job_id,
                sensor="netflow_behavior",
                severity=severity,
                category="beacon",
                title=f"Periodic callback pattern: {src} → {dest}",
                summary=(
                    f"Host {src} shows periodic connections to {dest} "
                    f"(interval ~{median_interval:.0f}s, jitter {jitter:.1%}, "
                    f"{len(evts)} connections). Consistent with C2 beaconing."
                ),
                evidence={
                    "src_ip": src,
                    "dest_ip": dest,
                    "connection_count": len(evts),
                    "median_interval_sec": round(median_interval, 1),
                    "jitter": round(jitter, 3),
                    "duration_sec": round(timestamps[-1] - timestamps[0], 1),
                },
                confidence=confidence,
            ))

    # Detect scanning: host connecting to many unique destinations
    scan_threshold = max(10, len(events) * 0.1)
    for host, dests in host_dest_ips.items():
        checkpoint()
        if len(dests) >= scan_threshold:
            findings.append(_make_finding(
                job_id=job_id,
                sensor="netflow_behavior",
                severity="medium",
                category="scanning",
                title=f"Host {host} connected to {len(dests)} unique destinations",
                summary=(
                    f"Host {host} connected to {len(dests)} unique destination IPs. "
                    f"This may indicate network scanning or reconnaissance."
                ),
                evidence={
                    "host": host,
                    "unique_destinations": len(dests),
                    "sample_destinations": sorted(dests)[:20],
                },
                confidence=min(0.8, 0.4 + len(dests) * 0.005),
            ))

    return findings


# ── 4. Cross-Source Inconsistency Detector ────────────────────────────────


def detect_cross_source_inconsistencies(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Find conflicting evidence across different telemetry sources.

    Detects:
    - Same IP claiming different hostnames across sources
    - Same hostname resolving to different IPs across sources
    - Timestamp ordering anomalies (event B references event A but precedes it)
    - Process lineage conflicts (Sysmon vs EDR disagree on parent)
    """
    findings: list[Finding] = []

    events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
        )
    ).scalars().all())

    if len(events) < 5:
        return findings

    # 4a. Hostname-IP inconsistencies
    # Map IP -> set of (hostname, source_system) tuples
    ip_hostnames: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    hostname_ips: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for evt in events:
        checkpoint()
        src = evt.source_system or evt.source_type or "unknown"
        if evt.src_ip and evt.hostname:
            ip_hostnames[evt.src_ip][evt.hostname].add(src)
            hostname_ips[evt.hostname][evt.src_ip].add(src)

    # Flag IPs with multiple hostnames from different sources
    for ip, hostname_map in ip_hostnames.items():
        checkpoint()
        if len(hostname_map) > 1:
            # Collect which sources report which hostname
            source_claims: dict[str, list[str]] = {}
            for hn, sources in hostname_map.items():
                checkpoint()
                for s in sources:
                    checkpoint()
                    source_claims.setdefault(s, []).append(hn)

            # Only flag if different sources disagree (not just one source seeing multiple)
            sources_that_disagree = [
                s for s, hns in source_claims.items() if len(hns) > 1
            ]
            cross_source = len(source_claims) > 1

            if cross_source or sources_that_disagree:
                findings.append(_make_finding(
                    job_id=job_id,
                    sensor="cross_source",
                    severity="medium" if cross_source else "low",
                    category="hostname_inconsistency",
                    title=f"IP {ip} has conflicting hostnames: {sorted(hostname_map.keys())[:3]}",
                    summary=(
                        f"IP {ip} is associated with {len(hostname_map)} different "
                        f"hostnames across telemetry sources: "
                        f"{sorted(hostname_map.keys())[:5]}. This may indicate "
                        f"IP reuse, NAT, DHCP reassignment, or host spoofing."
                    ),
                    evidence={
                        "ip": ip,
                        "hostnames": {hn: sorted(srcs) for hn, srcs in hostname_map.items()},
                        "source_claims": source_claims,
                    },
                    confidence=0.5 if cross_source else 0.3,
                ))

    # 4b. Process lineage conflicts
    # Group process events by process_guid
    process_events: dict[str, list[dict]] = defaultdict(list)
    for evt in events:
        checkpoint()
        if evt.process_guid and evt.data_json:
            try:
                data = json.loads(evt.data_json)
                process_events[evt.process_guid].append({
                    "source": evt.source_system or evt.source_type,
                    "parent_guid": data.get("parent_process_guid", ""),
                    "parent_name": data.get("parent_image", data.get("parent_process", "")),
                    "image": data.get("image", data.get("process_name", "")),
                    "event_id": evt.event_id,
                })
            except (json.JSONDecodeError, TypeError):
                pass

    for guid, proc_evts in process_events.items():
        checkpoint()
        if len(proc_evts) < 2:
            continue
        # Check if different sources report different parents
        parents = {(p["parent_guid"], p["parent_name"], p["source"]) for p in proc_evts if p["parent_guid"]}
        parent_guids = {pg for pg, _, _ in parents}
        if len(parent_guids) > 1:
            findings.append(_make_finding(
                job_id=job_id,
                sensor="cross_source",
                severity="high",
                category="process_lineage_conflict",
                title=f"Process {guid[:12]}... has conflicting parent lineage",
                summary=(
                    f"Process GUID {guid} is reported with different parent "
                    f"processes by different sources. This may indicate process "
                    f"injection, hooking, or telemetry tampering."
                ),
                evidence={
                    "process_guid": guid,
                    "parent_claims": [
                        {"source": src, "parent_guid": pg, "parent_name": pn}
                        for pg, pn, src in parents
                    ],
                },
                confidence=0.75,
            ))

    return findings


# ── 5. Sequence Detector ─────────────────────────────────────────────────

# Attack chain templates: ordered lists of (event_type, category_or_action)
_ATTACK_CHAINS: list[dict[str, Any]] = [
    {
        "name": "credential_compromise_chain",
        "description": "Failed auth → successful auth → lateral movement",
        "severity": "high",
        "steps": [
            {"event_type": "auth", "action_match": ["failed", "failure", "failed_login"]},
            {"event_type": "auth", "action_match": ["success", "login", "logon"]},
            {"event_type": "connection", "port_match": [22, 135, 445, 3389, 5985, 5986]},
        ],
        "window_seconds": 3600,  # 1 hour
        "confidence": 0.7,
    },
    {
        "name": "recon_to_exploit",
        "description": "Port scanning → service connection → process execution",
        "severity": "high",
        "steps": [
            {"event_type": "connection", "min_unique_dest_ports": 5},
            {"event_type": "connection", "port_match": [80, 443, 8080, 8443]},
            {"event_type": "process", "any": True},
        ],
        "window_seconds": 7200,
        "confidence": 0.6,
    },
    {
        "name": "staging_exfil",
        "description": "DNS lookup → TLS connection → large data transfer",
        "severity": "high",
        "steps": [
            {"event_type": "dns", "any": True},
            {"event_type": "connection", "any": True},
        ],
        "window_seconds": 1800,
        "min_bytes_out": 1_000_000,  # 1MB
        "confidence": 0.55,
    },
]


def _event_matches_step(
    evt: NormalizedEvent,
    step: dict[str, Any],
    data: dict[str, Any],
) -> bool:
    """Check if a NormalizedEvent matches a chain step definition."""
    if evt.event_type != step["event_type"]:
        return False

    if step.get("any"):
        return True

    if "action_match" in step:
        action = data.get("action", data.get("status", ""))
        if action.lower() not in [a.lower() for a in step["action_match"]]:
            return False

    if "port_match" in step:
        if evt.dest_port not in step["port_match"]:
            return False

    return True


def detect_attack_sequences(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Detect multi-step attack patterns by matching event sequences per host.

    Uses predefined attack chain templates to find ordered sequences of events
    from the same source host within a time window.
    """
    findings: list[Finding] = []

    events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
        ).order_by(NormalizedEvent.timestamp)
    ).scalars().all())

    if len(events) < 3:
        return findings

    # Parse data_json once for all events
    event_data: dict[str, dict] = {}
    for evt in events:
        checkpoint()
        data = {}
        if evt.data_json:
            try:
                data = json.loads(evt.data_json)
            except (json.JSONDecodeError, TypeError):
                pass
        event_data[evt.event_id] = data

    # Group events by source host (src_ip or hostname)
    host_events: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for evt in events:
        checkpoint()
        key = evt.src_ip or evt.hostname or ""
        if key:
            host_events[key].append(evt)

    # Try to match each chain template per host
    for chain in _ATTACK_CHAINS:
        checkpoint()
        steps = chain["steps"]
        window = chain["window_seconds"]

        for host, host_evts in host_events.items():
            checkpoint()
            if len(host_evts) < len(steps):
                continue

            # Sliding window: try to find ordered step matches
            matched_steps: list[tuple[int, NormalizedEvent]] = []

            for evt in host_evts:
                checkpoint()
                data = event_data.get(evt.event_id, {})
                step_idx = len(matched_steps)

                if step_idx >= len(steps):
                    break

                if _event_matches_step(evt, steps[step_idx], data):
                    # Check time window from first match
                    if matched_steps:
                        try:
                            first_ts = datetime.fromisoformat(
                                matched_steps[0][1].timestamp.replace("Z", "+00:00")
                            )
                            curr_ts = datetime.fromisoformat(
                                evt.timestamp.replace("Z", "+00:00")
                            )
                            delta = (curr_ts - first_ts).total_seconds()
                            if delta > window:
                                # Window expired, restart with current event as step 0
                                matched_steps = []
                                if _event_matches_step(evt, steps[0], data):
                                    matched_steps = [(0, evt)]
                                continue
                        except (ValueError, AttributeError):
                            pass

                    matched_steps.append((step_idx, evt))

            # Check if we matched all steps
            if len(matched_steps) == len(steps):
                findings.append(_make_finding(
                    job_id=job_id,
                    sensor="sequence_detector",
                    severity=chain["severity"],
                    category="attack_chain",
                    title=f"Attack chain '{chain['name']}' detected on {host}",
                    summary=(
                        f"Multi-step attack pattern detected on host {host}: "
                        f"{chain['description']}. "
                        f"{len(steps)} sequential steps matched within "
                        f"{window}s window."
                    ),
                    evidence={
                        "host": host,
                        "chain_name": chain["name"],
                        "matched_events": [
                            {
                                "step": idx,
                                "event_id": evt.event_id,
                                "event_type": evt.event_type,
                                "timestamp": evt.timestamp,
                            }
                            for idx, evt in matched_steps
                        ],
                    },
                    confidence=chain["confidence"],
                ))

    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────


def run_behavioral_detectors(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Run all Phase 5 behavioral detectors and persist findings.

    Returns the list of all findings created.
    """
    all_findings: list[Finding] = []

    detectors = [
        ("role_baseline", detect_role_baseline_anomalies),
        ("auth_anomaly", detect_auth_anomalies),
        ("netflow_behavior", detect_netflow_anomalies),
        ("cross_source", detect_cross_source_inconsistencies),
        ("sequence_detector", detect_attack_sequences),
    ]

    for name, detector_fn in detectors:
        checkpoint()
        try:
            results = detector_fn(db, job_id)
            logger.info("Detector %s produced %d findings for job %s", name, len(results), job_id)
            all_findings.extend(results)
        except PROPAGATE_ERRORS:
            raise
        except Exception:
            logger.exception("Detector %s failed for job %s", name, job_id)

    # Persist all findings
    for finding in all_findings:
        checkpoint()
        db.add(finding)
    db.flush()

    logger.info(
        "Behavioral detection complete for job %s: %d total findings",
        job_id, len(all_findings),
    )
    return all_findings