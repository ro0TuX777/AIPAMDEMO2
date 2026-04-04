"""
Storyline Reconstructor — synthesises the evidence graph into attack narratives.

Takes a built evidence graph (nodes + edges) and groups related evidence into
coherent attack stages aligned with a simplified kill-chain:
  Recon → Initial Access → Execution → C2 → Lateral Movement → Exfiltration

Each stage contains the nodes/edges that support it, a confidence score, and a
human-readable summary sentence.

Public API:
    reconstruct_storyline(db, job_id) → StorylineResult
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from backend.app.services.evidence_graph import build_evidence_graph

logger = logging.getLogger("aipam.storyline")

# ── Attack stage definitions (simplified kill-chain) ─────────────────

STAGE_ORDER = [
    "recon",
    "initial_access",
    "execution",
    "persistence",
    "c2",
    "lateral_movement",
    "credential_access",
    "exfiltration",
    "impact",
]

# Maps node metadata / edge types / keywords → stage
_STAGE_CLASSIFIERS: dict[str, dict[str, Any]] = {
    "recon": {
        "event_types": {"dns", "connection", "netflow"},
        "edge_types": {"targeted"},
        "keywords": ["scan", "recon", "enum", "discovery", "probe", "sweep", "fingerprint"],
        "finding_categories": ["recon", "scanning", "network_scan"],
        "hypothesis_types": ["recon"],
    },
    "initial_access": {
        "event_types": set(),
        "edge_types": {"downloaded_from"},
        "keywords": ["exploit", "phish", "initial.access", "delivery", "dropper"],
        "finding_categories": ["exploit", "malware_delivery"],
        "hypothesis_types": ["malware_delivery"],
    },
    "execution": {
        "event_types": {"process"},
        "edge_types": {"executed_on", "caused_by"},
        "keywords": ["exec", "process", "command", "powershell", "cmd", "script"],
        "finding_categories": ["execution", "process_anomaly"],
        "hypothesis_types": [],
    },
    "persistence": {
        "event_types": set(),
        "edge_types": set(),
        "keywords": ["persist", "scheduled.task", "registry", "service.install", "startup"],
        "finding_categories": ["persistence"],
        "hypothesis_types": [],
    },
    "c2": {
        "event_types": {"c2_callback", "c2_task"},
        "edge_types": {"beaconed_to", "confirmed_by"},
        "keywords": ["beacon", "c2", "callback", "heartbeat", "command.and.control", "cobalt"],
        "finding_categories": ["c2", "beaconing", "c2_fusion"],
        "hypothesis_types": ["c2"],
    },
    "lateral_movement": {
        "event_types": {"auth"},
        "edge_types": {"authenticated_as"},
        "keywords": ["lateral", "psexec", "wmi", "rdp", "smb", "pivot", "pass.the.hash"],
        "finding_categories": ["lateral_movement", "lateral_auth"],
        "hypothesis_types": ["lateral_movement"],
    },
    "credential_access": {
        "event_types": set(),
        "edge_types": set(),
        "keywords": ["brute", "credential", "spray", "password", "kerberoast", "mimikatz"],
        "finding_categories": ["credential_abuse", "brute_force", "credential_spraying"],
        "hypothesis_types": [],
    },
    "exfiltration": {
        "event_types": set(),
        "edge_types": set(),
        "keywords": ["exfil", "staging", "upload", "tunnel", "covert.channel", "data.leak"],
        "finding_categories": ["exfiltration", "data_staging"],
        "hypothesis_types": ["exfiltration"],
    },
    "impact": {
        "event_types": set(),
        "edge_types": set(),
        "keywords": ["ransom", "wipe", "destroy", "encrypt", "defac"],
        "finding_categories": ["impact", "ransomware"],
        "hypothesis_types": [],
    },
}


@dataclass
class AttackStage:
    """A single stage in the reconstructed attack storyline."""
    name: str
    display_name: str
    node_ids: list[str] = field(default_factory=list)
    edge_indices: list[int] = field(default_factory=list)
    confidence: float = 0.0
    summary: str = ""
    host_ips: list[str] = field(default_factory=list)
    time_range: tuple[str | None, str | None] = (None, None)


@dataclass
class StorylineResult:
    """Full storyline reconstruction output."""
    job_id: str
    stages: list[AttackStage] = field(default_factory=list)
    host_timelines: dict[str, list[str]] = field(default_factory=dict)
    narrative: str = ""
    total_nodes: int = 0
    total_edges: int = 0
    unclassified_node_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "stages": [
                {
                    "name": s.name,
                    "display_name": s.display_name,
                    "node_count": len(s.node_ids),
                    "edge_count": len(s.edge_indices),
                    "confidence": round(s.confidence, 3),
                    "summary": s.summary,
                    "host_ips": s.host_ips,
                    "time_start": s.time_range[0],
                    "time_end": s.time_range[1],
                    "node_ids": s.node_ids,
                }
                for s in self.stages
            ],
            "host_timelines": self.host_timelines,
            "narrative": self.narrative,
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "unclassified_count": len(self.unclassified_node_ids),
        }


# ── Display names ────────────────────────────────────────────────────

_DISPLAY_NAMES = {
    "recon": "Reconnaissance",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "c2": "Command & Control",
    "lateral_movement": "Lateral Movement",
    "credential_access": "Credential Access",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


# ── Stage classifier ─────────────────────────────────────────────────


def _classify_node(node: dict[str, Any], edges: list[dict[str, Any]]) -> str | None:
    """Return the best-fit stage name for a node, or None."""
    meta = node.get("meta", {}) or {}
    ntype = node.get("type", "")
    nid = node.get("id", "")
    label = node.get("label", "")

    # Gather edge types touching this node
    node_edge_types: set[str] = set()
    for e in edges:
        if e["source"] == nid or e["target"] == nid:
            node_edge_types.add(e["type"])

    # Build searchable text from label + meta
    search_text = f"{label} {meta.get('category', '')} {meta.get('event_type', '')} {meta.get('hypothesis_type', '')}"

    best_stage: str | None = None
    best_score = 0

    for stage_name, classifier in _STAGE_CLASSIFIERS.items():
        score = 0

        # Match by event_type (telemetry nodes)
        evt_type = meta.get("event_type", "")
        if evt_type and evt_type in classifier["event_types"]:
            score += 3

        # Match by edge types
        overlap = node_edge_types & classifier["edge_types"]
        score += len(overlap) * 2

        # Match by keywords in label/meta
        for kw in classifier["keywords"]:
            if re.search(kw, search_text, re.IGNORECASE):
                score += 1

        # Match by finding category
        cat = meta.get("category", "")
        if cat and cat in classifier["finding_categories"]:
            score += 3

        # Match by hypothesis type (theory nodes)
        hyp = meta.get("hypothesis_type", "")
        if hyp and hyp in classifier["hypothesis_types"]:
            score += 4

        if score > best_score:
            best_score = score
            best_stage = stage_name

    return best_stage if best_score >= 1 else None


def _extract_host_ips(node_ids: list[str], nodes_by_id: dict[str, dict]) -> list[str]:
    """Extract unique host IPs from a set of node IDs."""
    ips: set[str] = set()
    for nid in node_ids:
        if nid.startswith("host:"):
            ips.add(nid.split(":", 1)[1])
        else:
            node = nodes_by_id.get(nid, {})
            meta = node.get("meta", {}) or {}
            ts = meta.get("ts", "")
            # Extract from src_ip-like patterns in node id
            if "src_ip" in meta:
                ips.add(meta["src_ip"])
    return sorted(ips)


def _extract_time_range(
    node_ids: list[str], nodes_by_id: dict[str, dict]
) -> tuple[str | None, str | None]:
    """Extract earliest and latest timestamps from nodes."""
    timestamps: list[str] = []
    for nid in node_ids:
        node = nodes_by_id.get(nid, {})
        meta = node.get("meta", {}) or {}
        ts = meta.get("ts")
        if ts:
            timestamps.append(str(ts))
    if not timestamps:
        return (None, None)
    timestamps.sort()
    return (timestamps[0], timestamps[-1])


def _build_stage_summary(stage: AttackStage, nodes_by_id: dict[str, dict]) -> str:
    """Generate a one-line summary for a stage."""
    n = len(stage.node_ids)
    hosts = ", ".join(stage.host_ips[:3])
    suffix = f" and {len(stage.host_ips) - 3} more" if len(stage.host_ips) > 3 else ""
    time_part = ""
    if stage.time_range[0]:
        time_part = f" from {stage.time_range[0]}"
        if stage.time_range[1] and stage.time_range[1] != stage.time_range[0]:
            time_part += f" to {stage.time_range[1]}"
    return f"{stage.display_name}: {n} evidence items involving {hosts}{suffix}{time_part}"


def _build_narrative(stages: list[AttackStage]) -> str:
    """Build a multi-line human-readable narrative from ordered stages."""
    if not stages:
        return "No attack stages identified from available evidence."
    lines: list[str] = ["## Attack Storyline\n"]
    for i, stage in enumerate(stages, 1):
        lines.append(f"**Stage {i} — {stage.display_name}** (confidence: {stage.confidence:.0%})")
        lines.append(f"  {stage.summary}")
        lines.append("")
    return "\n".join(lines)


# ── Main entry point ─────────────────────────────────────────────────

def reconstruct_storyline(
    db: Session,
    job_id: str,
) -> StorylineResult:
    """Reconstruct the attack storyline for a job.

    1. Builds the evidence graph
    2. Classifies each node into an attack stage
    3. Computes per-stage confidence
    4. Generates per-host timelines
    5. Produces a human-readable narrative
    """
    graph = build_evidence_graph(db, job_id)
    nodes = graph["nodes"]
    edges = graph["edges"]

    nodes_by_id: dict[str, dict] = {n["id"]: n for n in nodes}

    # Classify each node into a stage
    stage_members: dict[str, list[str]] = {s: [] for s in STAGE_ORDER}
    unclassified: list[str] = []

    for node in nodes:
        # Skip pure host nodes — they are context, not evidence
        if node["type"] == "host":
            continue
        stage = _classify_node(node, edges)
        if stage:
            stage_members[stage].append(node["id"])
        else:
            unclassified.append(node["id"])

    # Build AttackStage objects (only for stages with evidence)
    stages: list[AttackStage] = []
    for stage_name in STAGE_ORDER:
        members = stage_members[stage_name]
        if not members:
            continue

        # Collect edges within this stage
        member_set = set(members)
        edge_indices = [
            i for i, e in enumerate(edges)
            if e["source"] in member_set or e["target"] in member_set
        ]

        # Confidence: proportion of high-sev / confirmed nodes
        confirmed = sum(
            1 for nid in members
            if (nodes_by_id.get(nid, {}).get("meta", {}) or {}).get("evidence_status") == "confirmed"
            or nodes_by_id.get(nid, {}).get("severity") in ("high", "critical")
        )
        confidence = min(0.5 + (confirmed / max(len(members), 1)) * 0.5, 1.0)

        host_ips = _extract_host_ips(members, nodes_by_id)
        time_range = _extract_time_range(members, nodes_by_id)

        stage_obj = AttackStage(
            name=stage_name,
            display_name=_DISPLAY_NAMES[stage_name],
            node_ids=members,
            edge_indices=edge_indices,
            confidence=round(confidence, 3),
            host_ips=host_ips,
            time_range=time_range,
        )
        stage_obj.summary = _build_stage_summary(stage_obj, nodes_by_id)
        stages.append(stage_obj)

    # Per-host timelines: list of stage names in order
    host_timelines: dict[str, list[str]] = {}
    for stage in stages:
        for ip in stage.host_ips:
            host_timelines.setdefault(ip, [])
            if stage.name not in host_timelines[ip]:
                host_timelines[ip].append(stage.name)

    narrative = _build_narrative(stages)

    result = StorylineResult(
        job_id=job_id,
        stages=stages,
        host_timelines=host_timelines,
        narrative=narrative,
        total_nodes=len(nodes),
        total_edges=len(edges),
        unclassified_node_ids=unclassified,
    )

    logger.info(
        "Storyline for job %s: %d stages, %d classified, %d unclassified",
        job_id, len(stages),
        sum(len(s.node_ids) for s in stages),
        len(unclassified),
    )
    return result
