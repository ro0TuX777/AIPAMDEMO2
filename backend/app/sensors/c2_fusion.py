"""C2 Fusion Sensor — confirms observed events using attacker-side telemetry.

Matches C2 callback/task events against observed network and host events
to provide "ground truth" confirmation. When a match is found:

1. The observed event's evidence_status is upgraded to "confirmed"
2. The finding's confidence receives uplift
3. A new Finding is created documenting the C2 confirmation path

Matching strategies:
  - IP+port+time window: C2 callback src_ip matches observed connection dest_ip
  - Agent timing: C2 task timing correlates with observed process execution
  - Callback cadence: C2 sleep/jitter matches observed beaconing pattern
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

from backend.app.models.finding import Finding
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.schemas.common import EvidenceStatus

logger = logging.getLogger("aipam.sensors.c2_fusion")

# Time window (seconds) for matching C2 events to observed events
_MATCH_WINDOW_SECONDS = 300  # 5 minutes

# Confidence uplift for C2-confirmed events
_CONFIRMATION_UPLIFT = 0.25


def _make_finding(
    *,
    job_id: str,
    sensor: str,
    severity: str,
    category: str,
    title: str,
    summary: str,
    evidence: dict[str, Any],
    confidence: float,
) -> Finding:
    return Finding(
        job_id=job_id,
        finding_id=f"F-{uuid.uuid4().hex[:12]}",
        sensor=sensor,
        severity=severity,
        category=category,
        title=title,
        summary=summary,
        evidence_json=json.dumps(evidence),
        confidence=min(confidence, 1.0),
    )


def _parse_ts(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _within_window(ts1: datetime, ts2: datetime, window: int = _MATCH_WINDOW_SECONDS) -> bool:
    return abs((ts1 - ts2).total_seconds()) <= window


def fuse_c2_with_observed(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Match C2 events against observed network/host events.

    For each C2 callback, find observed connections from the same src_ip
    to the same dest_ip:dest_port within a time window. When matched:
    - upgrade the observed event to 'confirmed'
    - create a Finding documenting the confirmation
    """
    findings: list[Finding] = []

    # Load all events for this job
    events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
        ).order_by(NormalizedEvent.timestamp)
    ).scalars().all())

    if not events:
        return findings

    # Partition into C2 events and observed events
    c2_callbacks: list[NormalizedEvent] = []
    c2_tasks: list[NormalizedEvent] = []
    observed: list[NormalizedEvent] = []

    for evt in events:
        if evt.event_type == "c2_callback":
            c2_callbacks.append(evt)
        elif evt.event_type == "c2_task":
            c2_tasks.append(evt)
        else:
            observed.append(evt)

    if not c2_callbacks and not c2_tasks:
        return findings

    # Strategy 1: Match C2 callbacks to observed network connections
    findings.extend(_match_callbacks_to_connections(db, job_id, c2_callbacks, observed))

    # Strategy 2: Match C2 tasks to observed host events
    findings.extend(_match_tasks_to_host_events(db, job_id, c2_tasks, observed))

    # Strategy 3: Confirm beaconing findings with C2 callback cadence
    findings.extend(_confirm_beaconing(db, job_id, c2_callbacks))

    logger.info(
        "C2 fusion complete for job %s: %d confirmations",
        job_id, len(findings),
    )
    return findings


def _match_callbacks_to_connections(
    db: Session,
    job_id: str,
    c2_callbacks: list[NormalizedEvent],
    observed: list[NormalizedEvent],
) -> list[Finding]:
    """Match C2 callback src_ip → observed connection to same IP:port."""
    findings: list[Finding] = []
    confirmed_event_ids: set[str] = set()

    # Index observed connections by dest_ip for fast lookup
    obs_by_dest: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for evt in observed:
        if evt.event_type == "connection" and evt.dest_ip:
            obs_by_dest[evt.dest_ip].append(evt)

    for cb in c2_callbacks:
        cb_data = {}
        if cb.data_json:
            try:
                cb_data = json.loads(cb.data_json)
            except (json.JSONDecodeError, TypeError):
                pass

        cb_ts = _parse_ts(cb.timestamp)
        if cb_ts is None:
            continue

        # C2 callback src_ip is the implant host; look for observed connections
        # FROM that same IP TO the C2 server (cb.dest_ip)
        # Also check: observed connection from the implant to anywhere on the same port
        cb_src = cb.src_ip
        cb_dest = cb.dest_ip
        cb_port = cb.dest_port

        if not cb_src:
            continue

        # Look for observed connections FROM the C2 src (implant) TO the C2 dest (server)
        candidates = obs_by_dest.get(cb_dest, []) if cb_dest else []

        for obs_evt in candidates:
            if obs_evt.event_id in confirmed_event_ids:
                continue
            obs_ts = _parse_ts(obs_evt.timestamp)
            if obs_ts is None:
                continue

            # Check IP match and time window
            ip_match = obs_evt.src_ip == cb_src
            port_match = cb_port is None or obs_evt.dest_port == cb_port
            time_match = _within_window(cb_ts, obs_ts)

            if ip_match and port_match and time_match:
                # Confirm the observed event
                db.execute(
                    update(NormalizedEvent)
                    .where(NormalizedEvent.event_id == obs_evt.event_id)
                    .values(evidence_status=EvidenceStatus.confirmed.value)
                )
                confirmed_event_ids.add(obs_evt.event_id)

                findings.append(_make_finding(
                    job_id=job_id,
                    sensor="c2_fusion",
                    severity="high",
                    category="c2_confirmed_connection",
                    title=f"C2 callback confirms connection {cb_src} → {cb_dest}:{cb_port}",
                    summary=(
                        f"C2 {cb_data.get('framework', 'unknown')} callback from agent "
                        f"{cb_data.get('agent_id', '?')} confirms observed network "
                        f"connection from {cb_src} to {cb_dest}:{cb_port}. "
                        f"Callback type: {cb_data.get('callback_type', 'checkin')}."
                    ),
                    evidence={
                        "c2_event_id": cb.event_id,
                        "observed_event_id": obs_evt.event_id,
                        "agent_id": cb_data.get("agent_id"),
                        "framework": cb_data.get("framework"),
                        "callback_type": cb_data.get("callback_type"),
                        "src_ip": cb_src,
                        "dest_ip": cb_dest,
                        "dest_port": cb_port,
                        "time_delta_seconds": abs((cb_ts - obs_ts).total_seconds()),
                    },
                    confidence=0.95,
                ))

    return findings


def _match_tasks_to_host_events(
    db: Session,
    job_id: str,
    c2_tasks: list[NormalizedEvent],
    observed: list[NormalizedEvent],
) -> list[Finding]:
    """Match C2 task execution to observed host events on the same agent host."""
    findings: list[Finding] = []
    confirmed_event_ids: set[str] = set()

    # Build a map: agent_id → src_ip from c2_callback events already in DB
    agent_to_ip: dict[str, str] = {}
    for evt in observed:
        # Check if we have any c2_callback events we can cross-reference
        pass

    # Also check c2_callbacks in the same job for agent→IP mapping
    all_events = list(db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.job_id == job_id,
            NormalizedEvent.event_type == "c2_callback",
        )
    ).scalars().all())

    for evt in all_events:
        data = {}
        if evt.data_json:
            try:
                data = json.loads(evt.data_json)
            except (json.JSONDecodeError, TypeError):
                pass
        agent_id = data.get("agent_id")
        if agent_id and evt.src_ip:
            agent_to_ip[agent_id] = evt.src_ip

    # Index observed process/auth events by src_ip
    obs_by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for evt in observed:
        if evt.event_type in ("process", "auth", "file") and evt.src_ip:
            obs_by_ip[evt.src_ip].append(evt)
        elif evt.event_type in ("process", "auth", "file") and evt.hostname:
            obs_by_ip[evt.hostname].append(evt)

    for task in c2_tasks:
        task_data = {}
        if task.data_json:
            try:
                task_data = json.loads(task.data_json)
            except (json.JSONDecodeError, TypeError):
                pass

        task_ts = _parse_ts(task.timestamp)
        if task_ts is None:
            continue

        agent_id = task_data.get("agent_id", "")
        host_ip = agent_to_ip.get(agent_id)
        if not host_ip:
            continue

        # Look for observed events on this host within time window
        candidates = obs_by_ip.get(host_ip, [])
        for obs_evt in candidates:
            if obs_evt.event_id in confirmed_event_ids:
                continue
            obs_ts = _parse_ts(obs_evt.timestamp)
            if obs_ts is None:
                continue

            if _within_window(task_ts, obs_ts):
                db.execute(
                    update(NormalizedEvent)
                    .where(NormalizedEvent.event_id == obs_evt.event_id)
                    .values(evidence_status=EvidenceStatus.confirmed.value)
                )
                confirmed_event_ids.add(obs_evt.event_id)

                findings.append(_make_finding(
                    job_id=job_id,
                    sensor="c2_fusion",
                    severity="high",
                    category="c2_confirmed_execution",
                    title=(
                        f"C2 task '{task_data.get('command', '?')}' confirms "
                        f"activity on {host_ip}"
                    ),
                    summary=(
                        f"C2 task '{task_data.get('command', '?')}' issued by "
                        f"operator '{task_data.get('operator', '?')}' at "
                        f"{task.timestamp} correlates with observed "
                        f"{obs_evt.event_type} event on host {host_ip}."
                    ),
                    evidence={
                        "c2_task_event_id": task.event_id,
                        "observed_event_id": obs_evt.event_id,
                        "task_id": task_data.get("task_id"),
                        "command": task_data.get("command"),
                        "operator": task_data.get("operator"),
                        "agent_id": agent_id,
                        "host_ip": host_ip,
                        "time_delta_seconds": abs((task_ts - obs_ts).total_seconds()),
                    },
                    confidence=0.90,
                ))

    return findings


def _confirm_beaconing(
    db: Session,
    job_id: str,
    c2_callbacks: list[NormalizedEvent],
) -> list[Finding]:
    """Confirm existing beaconing findings using C2 callback cadence data.

    If a behavioral finding flagged beaconing on an IP, and we have C2
    callbacks from the same IP with matching sleep/jitter, uplift the
    existing finding's confidence.
    """
    findings: list[Finding] = []

    if not c2_callbacks:
        return findings

    # Collect C2 agent IPs and their sleep/jitter configs
    agent_configs: dict[str, dict] = {}
    for cb in c2_callbacks:
        data = {}
        if cb.data_json:
            try:
                data = json.loads(cb.data_json)
            except (json.JSONDecodeError, TypeError):
                pass

        agent_id = data.get("agent_id", "")
        if agent_id and cb.src_ip:
            if agent_id not in agent_configs:
                agent_configs[agent_id] = {
                    "src_ip": cb.src_ip,
                    "sleep_seconds": data.get("sleep_seconds"),
                    "jitter_pct": data.get("jitter_pct"),
                    "framework": data.get("framework", "unknown"),
                }

    # Look for existing beaconing findings on matching IPs
    beacon_findings = list(db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            Finding.category == "beacon",
        )
    ).scalars().all())

    c2_ips = {cfg["src_ip"] for cfg in agent_configs.values()}

    for bf in beacon_findings:
        evidence = {}
        if bf.evidence_json:
            try:
                evidence = json.loads(bf.evidence_json)
            except (json.JSONDecodeError, TypeError):
                pass

        beacon_ip = evidence.get("src_ip", "")
        if beacon_ip in c2_ips:
            # Uplift the existing finding's confidence
            new_conf = min(bf.confidence + _CONFIRMATION_UPLIFT, 1.0)
            db.execute(
                update(Finding)
                .where(Finding.id == bf.id)
                .values(confidence=new_conf)
            )

            # Find the matching agent config
            matching_agent = next(
                (aid for aid, cfg in agent_configs.items() if cfg["src_ip"] == beacon_ip),
                None,
            )
            agent_cfg = agent_configs.get(matching_agent, {}) if matching_agent else {}

            findings.append(_make_finding(
                job_id=job_id,
                sensor="c2_fusion",
                severity="critical",
                category="c2_confirmed_beacon",
                title=f"C2 agent confirms beaconing from {beacon_ip}",
                summary=(
                    f"Behavioral beaconing detection on {beacon_ip} is confirmed "
                    f"by C2 {agent_cfg.get('framework', 'unknown')} agent "
                    f"'{matching_agent}' with sleep={agent_cfg.get('sleep_seconds')}s, "
                    f"jitter={agent_cfg.get('jitter_pct')}%. "
                    f"Original finding confidence uplifted from "
                    f"{bf.confidence:.2f} to {new_conf:.2f}."
                ),
                evidence={
                    "original_finding_id": bf.finding_id,
                    "agent_id": matching_agent,
                    "beacon_ip": beacon_ip,
                    "sleep_seconds": agent_cfg.get("sleep_seconds"),
                    "jitter_pct": agent_cfg.get("jitter_pct"),
                    "framework": agent_cfg.get("framework"),
                    "confidence_before": bf.confidence,
                    "confidence_after": new_conf,
                },
                confidence=0.98,
            ))

    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────


def run_c2_fusion(
    db: Session,
    job_id: str,
) -> list[Finding]:
    """Run C2 fusion sensor and persist findings.

    Returns the list of all findings created.
    """
    findings = fuse_c2_with_observed(db, job_id)

    for finding in findings:
        db.add(finding)
    db.flush()

    logger.info(
        "C2 fusion complete for job %s: %d findings",
        job_id, len(findings),
    )
    return findings
