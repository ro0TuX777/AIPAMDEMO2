"""
Evidence Graph — builds a rich relationship graph from all evidence entities.

Nodes: hosts, alerts, findings, theories, slices, IOCs, annotations
Edges: derived from cross-references (supporting_evidence, host_ip links,
       community_id overlaps, slice membership, etc.)

The graph is computed on-demand (no new DB table required) and returned
as a JSON-serializable structure for D3 force-directed rendering.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.slice import IncidentSlice
from backend.app.models.theory import Theory

logger = logging.getLogger("aipam.evidence_graph")

# ── Node type constants ───────────────────────────────────────────────
NODE_HOST = "host"
NODE_ALERT = "alert"
NODE_FINDING = "finding"
NODE_THEORY = "theory"
NODE_SLICE = "slice"
NODE_IOC = "ioc"
NODE_ANNOTATION = "annotation"
NODE_TELEMETRY = "telemetry"

# ── Severity ordering for visual weight ───────────────────────────────
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev(val: str | None) -> str:
    return val if val and val in _SEV_RANK else "info"


def _parse_json_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return list(parsed) if isinstance(parsed, list) else []
    except Exception:
        return []


def _parse_data_json(raw: str | None) -> dict:
    """Parse a JSON blob into a dict, returning {} on failure."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


# ── Graph builder ─────────────────────────────────────────────────────

def build_evidence_graph(
    db: Session,
    job_id: str,
    *,
    include_types: set[str] | None = None,
) -> dict[str, Any]:
    """Build and return the evidence graph for a job.

    Args:
        db: SQLAlchemy session.
        job_id: The job to build the graph for.
        include_types: Optional set of node types to include.
                       Defaults to all types.

    Returns:
        dict with ``nodes`` and ``edges`` lists.

    Raises:
        ValueError: If job_id does not exist.
    """
    job = db.get(Job, job_id)
    if not job:
        raise ValueError(f"Job {job_id} not found")

    all_types = {NODE_HOST, NODE_ALERT, NODE_FINDING, NODE_THEORY,
                 NODE_SLICE, NODE_IOC, NODE_ANNOTATION, NODE_TELEMETRY}
    want = include_types if include_types else all_types

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def _add_node(nid: str, label: str, ntype: str, severity: str = "info",
                  meta: dict | None = None) -> None:
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": label,
                "type": ntype,
                "severity": severity,
                **({"meta": meta} if meta else {}),
            })

    def _add_edge(source: str, target: str, etype: str,
                  weight: int = 1) -> None:
        if source in node_ids and target in node_ids:
            edges.append({
                "source": source,
                "target": target,
                "type": etype,
                "weight": weight,
            })

    # ── 1. Hosts ──────────────────────────────────────────────────────
    hosts: list[Host] = []
    if NODE_HOST in want:
        hosts = list(db.execute(
            select(Host).where(Host.job_id == job_id)
        ).scalars().all())
        for h in hosts:
            sev = "high" if (h.alert_count or 0) > 0 else "info"
            _add_node(f"host:{h.ip}", h.ip, NODE_HOST, sev, {
                "conn_count": h.conn_count,
                "alert_count": h.alert_count,
            })

    # ── 2. Alerts ─────────────────────────────────────────────────────
    alerts: list[Alert] = []
    if NODE_ALERT in want:
        alerts = list(db.execute(
            select(Alert).where(Alert.job_id == job_id)
        ).scalars().all())
        for a in alerts:
            _add_node(f"alert:{a.alert_id}", a.signature[:60] if a.signature else a.alert_id,
                       NODE_ALERT, _sev(a.severity), {"ts": a.ts} if a.ts else None)
            # Edge: alert → host
            host_key = f"host:{a.host_ip}"
            if host_key in node_ids:
                _add_edge(f"alert:{a.alert_id}", host_key, "triggered_on")

    # ── 3. Findings ───────────────────────────────────────────────────
    findings: list[Finding] = []
    if NODE_FINDING in want:
        findings = list(db.execute(
            select(Finding).where(Finding.job_id == job_id)
        ).scalars().all())
        for f in findings:
            _add_node(f"finding:{f.finding_id}",
                       f.title[:60] if f.title else f.finding_id,
                       NODE_FINDING, _sev(f.severity), {
                           "confidence": f.confidence,
                           "category": f.category,
                       })
            # Edge: finding → host via community_id overlap with alerts
            if f.community_id and NODE_ALERT in want:
                for a in alerts:
                    if a.community_id == f.community_id:
                        _add_edge(f"finding:{f.finding_id}",
                                  f"alert:{a.alert_id}", "correlated")

    # ── 4. Theories ───────────────────────────────────────────────────
    theories: list[Theory] = []
    if NODE_THEORY in want:
        theories = list(db.execute(
            select(Theory).where(Theory.job_id == job_id)
        ).scalars().all())
        for t in theories:
            _add_node(f"theory:{t.theory_id}",
                       t.label[:60] if t.label else t.theory_id,
                       NODE_THEORY, _sev(t.confidence), {
                           "hypothesis_type": t.hypothesis_type,
                           "score": t.score,
                           **({"ts": t.created_at} if t.created_at else {}),
                       })
            # Edge: theory → host (host-scoped)
            if t.scope_type == "host" and t.scope_id:
                host_key = f"host:{t.scope_id}"
                if host_key in node_ids:
                    _add_edge(f"theory:{t.theory_id}", host_key, "about_host")
            # Edges: theory → supporting evidence
            for ref in _parse_json_list(t.supporting_evidence_json):
                for prefix in ("finding:", "alert:", "ioc:"):
                    target = f"{prefix}{ref}"
                    if target in node_ids:
                        _add_edge(f"theory:{t.theory_id}", target, "supported_by")

    # ── 5. IOCs ───────────────────────────────────────────────────────
    # (processed before slices so slice→IOC edges can resolve)
    iocs: list[Ioc] = []
    if NODE_IOC in want:
        iocs = list(db.execute(
            select(Ioc).where(Ioc.job_id == job_id)
        ).scalars().all())
        for i in iocs:
            _add_node(f"ioc:{i.ioc_id}",
                       f"{i.ioc_type}: {i.value[:40]}",
                       NODE_IOC, _sev(i.severity), {
                           "ioc_type": i.ioc_type,
                           "value": i.value,
                       })
            # Edge: IOC → host if value is an IP matching a host
            if i.ioc_type in ("ip", "ipv4", "ipv6", "ip-dst", "ip-src"):
                host_key = f"host:{i.value}"
                if host_key in node_ids:
                    _add_edge(f"ioc:{i.ioc_id}", host_key, "indicates")

    # ── 6. Slices ─────────────────────────────────────────────────────
    slices: list[IncidentSlice] = []
    if NODE_SLICE in want:
        slices = list(db.execute(
            select(IncidentSlice).where(IncidentSlice.job_id == job_id)
        ).scalars().all())
        for s in slices:
            _add_node(f"slice:{s.slice_id}",
                       s.label[:60] if s.label else s.slice_id,
                       NODE_SLICE, _sev(s.severity), {
                           "slice_type": s.slice_type,
                           "confidence": s.confidence,
                           **({"ts": s.time_start or s.created_at} if (s.time_start or s.created_at) else {}),
                       })
            # Edges: slice → member hosts
            for ip in _parse_json_list(s.host_ips_json):
                host_key = f"host:{ip}"
                if host_key in node_ids:
                    _add_edge(f"slice:{s.slice_id}", host_key, "involves_host")
            # Edges: slice → member alerts
            for aid in _parse_json_list(s.alert_ids_json):
                target = f"alert:{aid}"
                if target in node_ids:
                    _add_edge(f"slice:{s.slice_id}", target, "contains")
            # Edges: slice → member findings
            for fid in _parse_json_list(s.finding_ids_json):
                target = f"finding:{fid}"
                if target in node_ids:
                    _add_edge(f"slice:{s.slice_id}", target, "contains")
            # Edges: slice → member IOCs
            for iid in _parse_json_list(s.ioc_ids_json):
                target = f"ioc:{iid}"
                if target in node_ids:
                    _add_edge(f"slice:{s.slice_id}", target, "contains")

    # ── 7. Annotations ───────────────────────────────────────────────
    annotations: list[ContextAnnotation] = []
    if NODE_ANNOTATION in want:
        annotations = list(db.execute(
            select(ContextAnnotation).where(ContextAnnotation.job_id == job_id)
        ).scalars().all())
        for ann in annotations:
            _add_node(f"annotation:{ann.annotation_id}",
                       ann.title[:60] if ann.title else ann.annotation_id,
                       NODE_ANNOTATION, _sev(ann.severity), {
                           "metric_name": ann.metric_name,
                           "deviation_factor": ann.deviation_factor,
                       })
            # Edge: annotation → host
            host_key = f"host:{ann.host_ip}"
            if host_key in node_ids:
                _add_edge(f"annotation:{ann.annotation_id}", host_key, "annotates")
            # Edges: annotation → related alerts
            for aid in _parse_json_list(ann.related_alert_ids_json):
                target = f"alert:{aid}"
                if target in node_ids:
                    _add_edge(f"annotation:{ann.annotation_id}", target, "related_to")
            # Edges: annotation → related findings
            for fid in _parse_json_list(ann.related_finding_ids_json):
                target = f"finding:{fid}"
                if target in node_ids:
                    _add_edge(f"annotation:{ann.annotation_id}", target, "related_to")

    # ── 8. Telemetry (NormalizedEvents) ─────────────────────────────
    tel_events: list[NormalizedEvent] = []
    if NODE_TELEMETRY in want:
        tel_events = list(db.execute(
            select(NormalizedEvent).where(NormalizedEvent.job_id == job_id)
        ).scalars().all())

        # Build lookup indices for semantic edge generation
        _c2_callbacks: list[NormalizedEvent] = []
        _c2_tasks: list[NormalizedEvent] = []
        _by_session: dict[str, list[NormalizedEvent]] = {}
        _by_host_ts: list[NormalizedEvent] = []

        for te in tel_events:
            sev = "medium" if te.evidence_status in ("corroborated", "confirmed") else "info"
            label = f"{te.event_type}: {te.source_system or te.parser_name or 'unknown'}"
            if te.hostname:
                label += f" @ {te.hostname}"
            _add_node(f"telemetry:{te.event_id}", label[:60],
                       NODE_TELEMETRY, sev, {
                           "event_type": te.event_type,
                           "source_system": te.source_system,
                           "evidence_status": te.evidence_status,
                           "corroboration_score": te.corroboration_score,
                           "ts": te.timestamp,
                       })

            te_key = f"telemetry:{te.event_id}"

            # ── Basic host edges ──
            if te.src_ip:
                host_key = f"host:{te.src_ip}"
                if host_key in node_ids:
                    _add_edge(te_key, host_key, "observed_on")
            if te.dest_ip:
                host_key = f"host:{te.dest_ip}"
                if host_key in node_ids:
                    _add_edge(te_key, host_key, "targeted")

            # ── Semantic edges by event_type ──
            if te.event_type == "process" and te.src_ip:
                host_key = f"host:{te.src_ip}"
                if host_key in node_ids:
                    _add_edge(te_key, host_key, "executed_on")

            if te.event_type == "auth" and te.src_ip:
                host_key = f"host:{te.src_ip}"
                if host_key in node_ids:
                    _add_edge(te_key, host_key, "authenticated_as")

            if te.event_type in ("connection", "netflow") and te.dest_ip:
                data = _parse_data_json(te.data_json)
                if data.get("service") in ("http", "https", "ftp"):
                    host_key = f"host:{te.dest_ip}"
                    if host_key in node_ids:
                        _add_edge(te_key, host_key, "downloaded_from")

            if te.event_type in ("connection", "netflow") and te.dest_ip and te.src_ip:
                # Beaconing edge: confirmed or corroborated connection → C2 target
                if te.evidence_status in ("confirmed", "corroborated"):
                    dest_key = f"host:{te.dest_ip}"
                    if dest_key in node_ids:
                        _add_edge(te_key, dest_key, "beaconed_to")

            # Track C2 events for confirmed_by edges
            if te.event_type == "c2_callback":
                _c2_callbacks.append(te)
            elif te.event_type == "c2_task":
                _c2_tasks.append(te)

            # Track for session/temporal edges
            if te.session_id:
                _by_session.setdefault(te.session_id, []).append(te)
            _by_host_ts.append(te)

            # ── Alert correlation (community_id) ──
            if te.community_id and NODE_ALERT in want:
                for a in alerts:
                    if a.community_id == te.community_id:
                        _add_edge(te_key, f"alert:{a.alert_id}", "correlated")

        # ── confirmed_by edges: C2 callbacks/tasks → matching observed events ──
        for cb in _c2_callbacks:
            cb_key = f"telemetry:{cb.event_id}"
            for te in tel_events:
                if te.event_type in ("connection", "netflow") and te.event_id != cb.event_id:
                    if (te.src_ip == cb.src_ip and te.dest_ip == cb.dest_ip
                            and te.dest_port == cb.dest_port):
                        _add_edge(f"telemetry:{te.event_id}", cb_key, "confirmed_by")

        for task in _c2_tasks:
            task_key = f"telemetry:{task.event_id}"
            task_data = _parse_data_json(task.data_json)
            agent_id = task_data.get("agent_id")
            if not agent_id:
                continue
            # Find the callback that maps this agent to a host IP
            agent_ip = None
            for cb in _c2_callbacks:
                cb_data = _parse_data_json(cb.data_json)
                if cb_data.get("agent_id") == agent_id:
                    agent_ip = cb.src_ip
                    break
            if agent_ip:
                for te in tel_events:
                    if te.event_type == "process" and te.src_ip == agent_ip:
                        _add_edge(f"telemetry:{te.event_id}", task_key, "confirmed_by")

        # ── same_session edges ──
        for _sid, members in _by_session.items():
            if len(members) > 1:
                for i in range(len(members) - 1):
                    _add_edge(f"telemetry:{members[i].event_id}",
                              f"telemetry:{members[i + 1].event_id}", "same_session")

        # ── occurred_before edges (temporal, same host, within 5 min) ──
        _by_host_ts.sort(key=lambda e: (e.src_ip or "", e.timestamp or ""))
        for i in range(len(_by_host_ts) - 1):
            a_evt = _by_host_ts[i]
            b_evt = _by_host_ts[i + 1]
            if (a_evt.src_ip and a_evt.src_ip == b_evt.src_ip
                    and a_evt.timestamp and b_evt.timestamp
                    and a_evt.event_id != b_evt.event_id):
                try:
                    from datetime import datetime as _dt
                    ta = _dt.fromisoformat(a_evt.timestamp.replace("Z", "+00:00"))
                    tb = _dt.fromisoformat(b_evt.timestamp.replace("Z", "+00:00"))
                    if 0 <= (tb - ta).total_seconds() <= 300:
                        _add_edge(f"telemetry:{a_evt.event_id}",
                                  f"telemetry:{b_evt.event_id}", "occurred_before")
                except (ValueError, TypeError):
                    pass

        # ── caused_by edges: findings linked to telemetry via evidence_json ──
        if NODE_FINDING in want:
            for f in findings:
                ev_data = _parse_data_json(getattr(f, "evidence_json", None))
                linked_ids = ev_data.get("event_ids", []) if isinstance(ev_data, dict) else []
                for eid in linked_ids:
                    te_key = f"telemetry:{eid}"
                    if te_key in node_ids:
                        _add_edge(f"finding:{f.finding_id}", te_key, "caused_by")

    logger.info("Evidence graph for job %s: %d nodes, %d edges",
                job_id, len(nodes), len(edges))

    return {"nodes": nodes, "edges": edges}


# ── Stats summary (for chat context) ─────────────────────────────────

def graph_summary(db: Session, job_id: str) -> str:
    """Return a human-readable summary of the evidence graph."""
    graph = build_evidence_graph(db, job_id)
    nodes = graph["nodes"]
    edges = graph["edges"]

    type_counts: dict[str, int] = {}
    for n in nodes:
        t = n["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    edge_type_counts: dict[str, int] = {}
    for e in edges:
        t = e["type"]
        edge_type_counts[t] = edge_type_counts.get(t, 0) + 1

    lines = [f"Evidence Graph: {len(nodes)} nodes, {len(edges)} edges"]
    lines.append("Node types: " + ", ".join(
        f"{v} {k}s" for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
    ))
    if edge_type_counts:
        lines.append("Edge types: " + ", ".join(
            f"{v} {k}" for k, v in sorted(edge_type_counts.items(), key=lambda x: -x[1])
        ))

    # Identify hub nodes (high degree)
    degree: dict[str, int] = {}
    for e in edges:
        degree[e["source"]] = degree.get(e["source"], 0) + 1
        degree[e["target"]] = degree.get(e["target"], 0) + 1

    if degree:
        top = sorted(degree.items(), key=lambda x: -x[1])[:5]
        lines.append("Most connected: " + ", ".join(
            f"{nid} ({deg} edges)" for nid, deg in top
        ))

    return "\n".join(lines)

