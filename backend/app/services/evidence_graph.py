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
                 NODE_SLICE, NODE_IOC, NODE_ANNOTATION}
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
                       NODE_ALERT, _sev(a.severity))
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

