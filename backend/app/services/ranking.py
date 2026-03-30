"""
Investigation Queue ranking algorithm.

Produces a unified rank_score for findings, alerts, and theories
so they can be sorted into a single triage queue.

Weights (Sprint 7 — feedback-adjusted):
  severity        0.25  (was 0.30)
  confidence      0.20  (was 0.25)
  corroboration   0.20
  blast_radius    0.15
  recency         0.10
  feedback_adj    0.10  (NEW — learned from analyst behavior)
"""

from __future__ import annotations

import json as _json
import math
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.theory import Theory
from backend.app.schemas.investigation import (
    AnalystStatus,
    InvestigationQueueItem,
    QueueItemSource,
    QueueSummary,
)

# ── MITRE ATT&CK mapping from hypothesis_type ────────────────────────
_HYPOTHESIS_TO_MITRE: dict[str, list[str]] = {
    "c2": ["T1071", "T1095"],
    "malware_delivery": ["T1566", "T1059"],
    "recon": ["T1046", "T1018"],
    "lateral_movement": ["T1021", "T1570"],
    "exfiltration": ["T1041", "T1048"],
    "admin_tools": ["T1219"],
}

# Regex to extract MITRE technique IDs from text
_MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


def _extract_mitre_ids(text: str | None, hypothesis_type: str | None = None) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from text and hypothesis type."""
    ids: set[str] = set()
    if hypothesis_type and hypothesis_type in _HYPOTHESIS_TO_MITRE:
        ids.update(_HYPOTHESIS_TO_MITRE[hypothesis_type])
    if text:
        ids.update(_MITRE_PATTERN.findall(text))
    return sorted(ids)

# ── Weight constants (Sprint 7: reduced sev/conf to make room for feedback) ──
W_SEVERITY = 0.25
W_CONFIDENCE = 0.20
W_CORROBORATION = 0.20
W_BLAST_RADIUS = 0.15
W_RECENCY = 0.10
W_FEEDBACK = 0.10

# Sub-weights within the feedback_adjustment component
_FB_SENSOR_TRUST = 0.50
_FB_SIGNATURE_NOISE = 0.30
_FB_CATEGORY_CONFIRM = 0.20

_SEVERITY_MAP: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}

# Recency: items from the last 24h get 1.0, decaying over 30 days
_RECENCY_HALF_LIFE_DAYS = 7.0


def _severity_score(severity: str) -> float:
    return _SEVERITY_MAP.get(severity.lower(), 0.1)


def _recency_score(timestamp_iso: str | None, now: datetime | None = None) -> float:
    """Exponential decay based on age. Returns 0.0–1.0."""
    if not timestamp_iso:
        return 0.5  # neutral if unknown
    now = now or datetime.now(timezone.utc)
    try:
        ts = datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_days = max(0, (now - ts).total_seconds() / 86400)
        return math.exp(-0.693 * age_days / _RECENCY_HALF_LIFE_DAYS)
    except (ValueError, TypeError):
        return 0.5


def _corroboration_score(
    job_id: str,
    source_type: str,
    source_id: str,
    db: Session,
) -> float:
    """Approximate corroboration: how many other items share the same job.

    For Sprint 1 this is a simple ratio; Sprint 7 will add cross-entity linking.
    """
    # Count total items in the job for this source type
    if source_type == "finding":
        total = db.query(Finding).filter(Finding.job_id == job_id).count()
    elif source_type == "alert":
        total = db.query(Alert).filter(Alert.job_id == job_id).count()
    else:
        total = db.query(Theory).filter(Theory.job_id == job_id).count()
    # Normalize: more items = more corroboration opportunity, cap at 1.0
    return min(1.0, total / 20.0) if total > 0 else 0.0


def _blast_radius_score(extra: dict[str, Any]) -> float:
    """Estimate blast radius from affected hosts count."""
    hosts = extra.get("affected_hosts", [])
    if isinstance(hosts, list):
        count = len(hosts)
    elif isinstance(hosts, int):
        count = hosts
    else:
        count = 0
    # Cap at 10 hosts = 1.0
    return min(1.0, count / 10.0)


def compute_feedback_adjustment(
    sensor: str | None,
    signature: str | None,
    category: str | None,
    sensor_adjustments: dict[str, float] | None = None,
    signature_adjustments: dict[str, float] | None = None,
    category_adjustments: dict[str, float] | None = None,
) -> float:
    """Compute the feedback adjustment factor (0.0–1.0 range, centered at 0.5).

    Components:
      - sensor_trust_factor (50%): high-trust sensors get boosted
      - signature_noise_penalty (30%): noisy signatures get penalized
      - category_confirmation_rate (20%): categories often confirmed rank higher
    """
    sensor_factor = 0.5  # neutral
    if sensor_adjustments and sensor and sensor in sensor_adjustments:
        # adjustments are in [-0.5, 0.5], shift to [0.0, 1.0]
        sensor_factor = 0.5 + sensor_adjustments[sensor]

    sig_factor = 0.5  # neutral
    if signature_adjustments and signature and signature in signature_adjustments:
        # penalties are in [-0.5, 0.0], shift to [0.0, 0.5] → center at 0.5
        sig_factor = 0.5 + signature_adjustments[signature]

    cat_factor = 0.5  # neutral
    if category_adjustments and category and category in category_adjustments:
        cat_factor = 0.5 + category_adjustments[category]

    return (
        _FB_SENSOR_TRUST * min(1.0, max(0.0, sensor_factor))
        + _FB_SIGNATURE_NOISE * min(1.0, max(0.0, sig_factor))
        + _FB_CATEGORY_CONFIRM * min(1.0, max(0.0, cat_factor))
    )


def compute_rank_score(
    severity: str,
    confidence: float,
    corroboration: float,
    blast_radius: float,
    recency: float,
    feedback_adj: float = 0.5,
) -> float:
    """Compute the weighted rank score (0.0–1.0).

    feedback_adj defaults to 0.5 (neutral) when no feedback data is available.
    """
    return (
        W_SEVERITY * _severity_score(severity)
        + W_CONFIDENCE * min(1.0, max(0.0, confidence))
        + W_CORROBORATION * corroboration
        + W_BLAST_RADIUS * blast_radius
        + W_RECENCY * recency
        + W_FEEDBACK * min(1.0, max(0.0, feedback_adj))
    )


def _find_corroborating_hosts(db: Session, job_id: str, host_ips: list[str]) -> int:
    """Count other queue-eligible items that share at least one host IP."""
    if not host_ips:
        return 0
    # Count alerts on shared hosts
    alert_count = db.query(Alert).filter(
        Alert.job_id == job_id,
        or_(Alert.src_ip.in_(host_ips), Alert.dest_ip.in_(host_ips)),
    ).count()
    # Count findings on shared hosts (via evidence_json containing the IP)
    finding_count = 0
    for ip in host_ips:
        finding_count += db.query(Finding).filter(
            Finding.job_id == job_id,
            Finding.evidence_json.contains(ip),
        ).count()
    return max(0, alert_count + finding_count - 1)  # -1 to exclude self


def _finding_to_queue_item(
    f: Finding, db: Session, now: datetime,
    sensor_adj: dict[str, float] | None = None,
    sig_adj: dict[str, float] | None = None,
    cat_adj: dict[str, float] | None = None,
) -> InvestigationQueueItem:
    """Convert a Finding ORM object to an InvestigationQueueItem."""
    evidence = {}
    if f.evidence_json:
        try:
            evidence = _json.loads(f.evidence_json)
        except (ValueError, TypeError):
            pass
    affected_hosts = evidence.get("affected_hosts", []) if isinstance(evidence, dict) else []
    if not isinstance(affected_hosts, list):
        affected_hosts = []

    mitre_ids = _extract_mitre_ids(f.title or "", None)
    mitre_ids.extend(_extract_mitre_ids(f.summary or "", None))
    mitre_ids = sorted(set(mitre_ids))

    extra = {"affected_hosts": affected_hosts}
    corroborating_count = _find_corroborating_hosts(db, f.job_id, affected_hosts)
    corroboration = _corroboration_score(f.job_id, "finding", f.finding_id, db)
    blast_radius = _blast_radius_score(extra)
    recency = _recency_score(f.reviewed_at or str(now), now)
    fb_adj = compute_feedback_adjustment(f.sensor, None, f.category, sensor_adj, sig_adj, cat_adj)

    rank = compute_rank_score(
        severity=f.severity or "info",
        confidence=f.confidence or 0.0,
        corroboration=corroboration,
        blast_radius=blast_radius,
        recency=recency,
        feedback_adj=fb_adj,
    )

    return InvestigationQueueItem(
        item_id=f"finding:{f.finding_id}",
        source_type=QueueItemSource.finding,
        source_id=f.finding_id,
        job_id=f.job_id,
        title=f.title or "Untitled Finding",
        severity=f.severity or "info",
        confidence=f.confidence or 0.0,
        category=f.category,
        sensor=f.sensor,
        description=f.summary,
        pcap_label=f.pcap_label,
        rank_score=round(rank, 4),
        corroborating_count=corroborating_count,
        affected_hosts=affected_hosts,
        affected_hosts_count=len(affected_hosts),
        mitre_ids=mitre_ids,
        analyst_status=f.analyst_status or "unreviewed",
        analyst_notes=f.analyst_notes,
        reviewed_at=f.reviewed_at,
        reviewer_id=getattr(f, "reviewer_id", None),
        extra=extra,
    )


def _alert_to_queue_item(
    a: Alert, db: Session, now: datetime,
    sensor_adj: dict[str, float] | None = None,
    sig_adj: dict[str, float] | None = None,
    cat_adj: dict[str, float] | None = None,
) -> InvestigationQueueItem:
    """Convert an Alert ORM object to an InvestigationQueueItem."""
    extra: dict[str, Any] = {}
    if a.src_ip:
        extra["src_ip"] = a.src_ip
    if a.dest_ip:
        extra["dest_ip"] = a.dest_ip
    hosts = [h for h in [a.src_ip, a.dest_ip, a.host_ip] if h]
    affected_hosts = sorted(set(hosts))
    extra["affected_hosts"] = affected_hosts

    mitre_ids = _extract_mitre_ids(a.signature or "", None)
    corroborating_count = _find_corroborating_hosts(db, a.job_id, affected_hosts)
    corroboration = _corroboration_score(a.job_id, "alert", a.alert_id, db)
    blast_radius = _blast_radius_score(extra)
    recency = _recency_score(a.ts, now)
    fb_adj = compute_feedback_adjustment(a.engine, a.signature, a.category, sensor_adj, sig_adj, cat_adj)

    # Alerts don't have a confidence score; use severity-based proxy
    confidence_proxy = _severity_score(a.severity or "info") * 0.7

    rank = compute_rank_score(
        severity=a.severity or "info",
        confidence=confidence_proxy,
        corroboration=corroboration,
        blast_radius=blast_radius,
        recency=recency,
        feedback_adj=fb_adj,
    )

    return InvestigationQueueItem(
        item_id=f"alert:{a.alert_id}",
        source_type=QueueItemSource.alert,
        source_id=a.alert_id,
        job_id=a.job_id,
        title=a.signature or "Untitled Alert",
        severity=a.severity or "info",
        confidence=round(confidence_proxy, 2),
        category=a.category,
        sensor=a.engine,
        description=None,
        pcap_label=a.pcap_label,
        rank_score=round(rank, 4),
        corroborating_count=corroborating_count,
        affected_hosts=affected_hosts,
        affected_hosts_count=len(affected_hosts),
        mitre_ids=mitre_ids,
        analyst_status=a.analyst_status or "unreviewed",
        analyst_notes=a.analyst_notes,
        reviewed_at=a.reviewed_at,
        reviewer_id=getattr(a, "reviewer_id", None),
        extra=extra,
    )


def _theory_to_queue_item(
    t: Theory, db: Session, now: datetime,
    sensor_adj: dict[str, float] | None = None,
    sig_adj: dict[str, float] | None = None,
    cat_adj: dict[str, float] | None = None,
) -> InvestigationQueueItem:
    """Convert a Theory ORM object to an InvestigationQueueItem."""
    extra: dict[str, Any] = {
        "hypothesis_type": t.hypothesis_type,
        "scope_type": t.scope_type,
        "scope_id": t.scope_id,
    }

    # Extract hosts from scope_id (host-scoped) and supporting evidence
    affected_hosts: list[str] = []
    if t.scope_type == "host" and t.scope_id:
        affected_hosts.append(t.scope_id)

    mitre_ids = _extract_mitre_ids(t.explanation, t.hypothesis_type)

    corroborating_count = 0
    if t.supporting_evidence_json:
        try:
            refs = _json.loads(t.supporting_evidence_json)
            corroborating_count = len(refs) if isinstance(refs, list) else 0
        except (ValueError, TypeError):
            pass

    corroboration = _corroboration_score(t.job_id, "theory", t.theory_id, db)
    recency = _recency_score(t.created_at, now)

    # Map theory confidence string to float
    _conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
    confidence = _conf_map.get(t.confidence, 0.3)

    blast_radius = _blast_radius_score({"affected_hosts": affected_hosts})

    fb_adj = compute_feedback_adjustment(None, None, t.hypothesis_type, sensor_adj, sig_adj, cat_adj)

    rank = compute_rank_score(
        severity="high" if t.score >= 0.7 else "medium" if t.score >= 0.4 else "low",
        confidence=confidence,
        corroboration=corroboration,
        blast_radius=blast_radius,
        recency=recency,
        feedback_adj=fb_adj,
    )

    return InvestigationQueueItem(
        item_id=f"theory:{t.theory_id}",
        source_type=QueueItemSource.theory,
        source_id=t.theory_id,
        job_id=t.job_id,
        title=t.label or "Untitled Theory",
        severity="high" if t.score >= 0.7 else "medium" if t.score >= 0.4 else "low",
        confidence=round(confidence, 2),
        category=t.hypothesis_type,
        sensor=None,
        description=t.explanation,
        pcap_label=t.pcap_label,
        rank_score=round(rank, 4),
        corroborating_count=corroborating_count,
        affected_hosts=affected_hosts,
        affected_hosts_count=len(affected_hosts),
        mitre_ids=mitre_ids,
        analyst_status=t.analyst_status or "unreviewed",
        analyst_notes=t.analyst_notes,
        reviewed_at=t.reviewed_at,
        reviewer_id=getattr(t, "reviewer_id", None),
        extra=extra,
    )


def build_investigation_queue(
    db: Session,
    job_id: str,
    *,
    status_filter: AnalystStatus | None = None,
    source_filter: QueueItemSource | None = None,
    severity_filter: str | None = None,
    search: str | None = None,
    host_filter: str | None = None,
    mitre_filter: str | None = None,
    has_corroboration: bool | None = None,
    reviewed: bool | None = None,
) -> tuple[list[InvestigationQueueItem], QueueSummary]:
    """Build the ranked investigation queue for a job.

    Returns (sorted_items, summary).
    """
    from backend.app.services.feedback_analytics import (
        compute_ranking_adjustments,
        compute_signature_adjustments,
    )

    now = datetime.now(timezone.utc)
    items: list[InvestigationQueueItem] = []

    # ── Load feedback adjustments once (Sprint 7) ──
    sensor_adj = compute_ranking_adjustments(db)
    sig_adj = compute_signature_adjustments(db)
    cat_adj: dict[str, float] | None = None  # reserved for future category-level feedback

    # ── Findings ──
    if source_filter is None or source_filter == QueueItemSource.finding:
        findings = db.query(Finding).filter(Finding.job_id == job_id).all()
        for f in findings:
            items.append(_finding_to_queue_item(f, db, now, sensor_adj, sig_adj, cat_adj))

    # ── Alerts (deduplicated by signature) ──
    if source_filter is None or source_filter == QueueItemSource.alert:
        alerts = db.query(Alert).filter(Alert.job_id == job_id).all()
        # Group alerts by signature to reduce noise
        seen_sigs: set[str] = set()
        for a in alerts:
            sig_key = f"{a.signature}:{a.severity}"
            if sig_key not in seen_sigs:
                seen_sigs.add(sig_key)
                items.append(_alert_to_queue_item(a, db, now, sensor_adj, sig_adj, cat_adj))

    # ── Theories (job-scoped only for queue) ──
    if source_filter is None or source_filter == QueueItemSource.theory:
        theories = db.query(Theory).filter(
            Theory.job_id == job_id,
            Theory.scope_type == "job",
        ).all()
        for t in theories:
            items.append(_theory_to_queue_item(t, db, now, sensor_adj, sig_adj, cat_adj))

    # ── Apply filters ──
    if status_filter:
        items = [i for i in items if i.analyst_status == status_filter]
    if severity_filter:
        items = [i for i in items if i.severity.value == severity_filter.lower()]
    if search and search.strip():
        q = search.strip().lower()
        items = [i for i in items if q in (i.title or "").lower() or q in (i.description or "").lower() or q in (i.category or "").lower()]
    # Sprint 2: enhanced filters
    if host_filter:
        items = [i for i in items if host_filter in i.affected_hosts]
    if mitre_filter:
        items = [i for i in items if mitre_filter in i.mitre_ids]
    if has_corroboration is not None:
        if has_corroboration:
            items = [i for i in items if i.corroborating_count > 0]
        else:
            items = [i for i in items if i.corroborating_count == 0]
    if reviewed is not None:
        if reviewed:
            items = [i for i in items if i.analyst_status != AnalystStatus.unreviewed]
        else:
            items = [i for i in items if i.analyst_status == AnalystStatus.unreviewed]

    # ── Sort by rank_score descending ──
    items.sort(key=lambda x: x.rank_score, reverse=True)

    # ── Assign rank positions ──
    for idx, item in enumerate(items, 1):
        item.rank_position = idx

    # ── Build summary ──
    total = len(items)
    unreviewed_count = sum(1 for i in items if i.analyst_status == AnalystStatus.unreviewed)
    summary = QueueSummary(
        total=total,
        unreviewed=unreviewed_count,
        confirmed=sum(1 for i in items if i.analyst_status == AnalystStatus.confirmed),
        false_positive=sum(1 for i in items if i.analyst_status == AnalystStatus.false_positive),
        needs_review=sum(1 for i in items if i.analyst_status == AnalystStatus.needs_review),
        deferred=sum(1 for i in items if i.analyst_status == AnalystStatus.deferred),
        review_rate=((total - unreviewed_count) / total) if total > 0 else 0.0,
    )

    return items, summary


def get_evidence_bundle(
    db: Session,
    job_id: str,
    item_id: str,
) -> dict[str, Any]:
    """Gather corroborating evidence for a single queue item.

    Returns a dict with related_findings, related_alerts, related_connections, timeline_events.
    """
    from backend.app.models.connection import Connection
    from backend.app.models.timeline import TimelineEvent

    source_type, source_id = item_id.split(":", 1)

    # Determine the host IPs to use for cross-referencing
    host_ips: list[str] = []
    evidence_ref_ids: list[str] = []

    if source_type == "finding":
        finding = db.execute(
            select(Finding).where(Finding.job_id == job_id, Finding.finding_id == source_id)
        ).scalar_one_or_none()
        if finding and finding.evidence_json:
            try:
                ev = _json.loads(finding.evidence_json)
                host_ips = ev.get("affected_hosts", []) if isinstance(ev, dict) else []
            except (ValueError, TypeError):
                pass
    elif source_type == "alert":
        alert = db.execute(
            select(Alert).where(Alert.job_id == job_id, Alert.alert_id == source_id)
        ).scalar_one_or_none()
        if alert:
            host_ips = [h for h in [alert.src_ip, alert.dest_ip, alert.host_ip] if h]
    elif source_type == "theory":
        theory = db.execute(
            select(Theory).where(Theory.job_id == job_id, Theory.theory_id == source_id)
        ).scalar_one_or_none()
        if theory:
            if theory.scope_type == "host" and theory.scope_id:
                host_ips = [theory.scope_id]
            # Parse supporting evidence refs (finding/alert IDs)
            evidence_ref_ids: list[str] = []
            if theory.supporting_evidence_json:
                try:
                    refs = _json.loads(theory.supporting_evidence_json)
                    if isinstance(refs, list):
                        evidence_ref_ids = [r for r in refs if isinstance(r, str)]
                except (ValueError, TypeError):
                    pass

    host_ips = list(set(host_ips))

    # Related findings — from supporting evidence refs (theories) or host IP matching
    related_findings: list[dict[str, Any]] = []
    related_alerts: list[dict[str, Any]] = []
    seen_finding_ids: set[str] = set()
    seen_alert_ids: set[str] = set()

    # First: direct evidence refs (for theories with supporting_evidence_json)
    evidence_ref_ids_resolved: list[str] = evidence_ref_ids if source_type == "theory" else []
    if evidence_ref_ids_resolved:
        ref_findings = db.query(Finding).filter(
            Finding.job_id == job_id,
            Finding.finding_id.in_(evidence_ref_ids_resolved),
        ).all()
        for f in ref_findings:
            seen_finding_ids.add(f.finding_id)
            related_findings.append({
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
            })
            # Also harvest host IPs from referenced findings for connection/timeline lookup
            if f.evidence_json:
                try:
                    ev = _json.loads(f.evidence_json)
                    if isinstance(ev, dict):
                        for h in ev.get("affected_hosts", []):
                            if h and h not in host_ips:
                                host_ips.append(h)
                except (ValueError, TypeError):
                    pass

        # Also check if any refs are alert IDs
        ref_alerts = db.query(Alert).filter(
            Alert.job_id == job_id,
            Alert.alert_id.in_(evidence_ref_ids_resolved),
        ).all()
        for a in ref_alerts:
            seen_alert_ids.add(a.alert_id)
            related_alerts.append({
                "alert_id": a.alert_id,
                "signature": a.signature,
                "severity": a.severity,
                "src_ip": a.src_ip,
                "dest_ip": a.dest_ip,
                "ts": a.ts,
            })
            for h in [a.src_ip, a.dest_ip, a.host_ip]:
                if h and h not in host_ips:
                    host_ips.append(h)

    # Second: host IP cross-reference (works for all source types)
    if host_ips:
        for ip in host_ips:
            for f in db.query(Finding).filter(
                Finding.job_id == job_id,
                Finding.evidence_json.contains(ip),
            ).all():
                if f.finding_id not in seen_finding_ids and f"finding:{f.finding_id}" != item_id:
                    seen_finding_ids.add(f.finding_id)
                    related_findings.append({
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "category": f.category,
                    })

    if host_ips:
        alerts = db.query(Alert).filter(
            Alert.job_id == job_id,
            or_(Alert.src_ip.in_(host_ips), Alert.dest_ip.in_(host_ips)),
        ).all()
        for a in alerts:
            if a.alert_id not in seen_alert_ids and f"alert:{a.alert_id}" != item_id:
                seen_alert_ids.add(a.alert_id)
                related_alerts.append({
                    "alert_id": a.alert_id,
                    "signature": a.signature,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "dest_ip": a.dest_ip,
                    "ts": a.ts,
                })

    # Related connections
    related_connections = []
    if host_ips:
        conns = db.query(Connection).filter(
            Connection.job_id == job_id,
            or_(Connection.src_ip.in_(host_ips), Connection.dest_ip.in_(host_ips)),
        ).limit(50).all()
        for c in conns:
            related_connections.append({
                "connection_id": c.connection_id,
                "src_ip": c.src_ip,
                "dest_ip": c.dest_ip,
                "proto": c.proto,
                "service": c.service,
                "ts": c.ts,
            })

    # Timeline events (matching host IPs in details_json)
    timeline_events = []
    if host_ips:
        for ip in host_ips:
            for te in db.query(TimelineEvent).filter(
                TimelineEvent.job_id == job_id,
                TimelineEvent.details_json.contains(ip),
            ).limit(20).all():
                details = {}
                if te.details_json:
                    try:
                        details = _json.loads(te.details_json)
                    except (ValueError, TypeError):
                        pass
                timeline_events.append({
                    "ts": te.ts,
                    "type": te.type,
                    "title": te.title,
                    "severity": te.severity,
                    "details": details,
                })

    return {
        "related_findings": related_findings,
        "related_alerts": related_alerts,
        "related_connections": related_connections,
        "timeline_events": timeline_events,
    }

