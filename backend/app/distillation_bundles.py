"""
Distillation v1 — Evidence Bundle Serializers.

Converts AIPAM DB models into structured JSON evidence bundles
matching the distillation teacher specification.  Each function
returns a plain dict ready for JSON serialization.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.file import File
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.slice import IncidentSlice
from backend.app.models.theory import Theory
from backend.app.models.timeline import TimelineEvent
from backend.app.models.tls import TlsSession

logger = logging.getLogger("aipam.distillation_bundles")


# ── Helper: safe JSON parse ────────────────────────────────────────────────

def _safe_json(raw: Optional[str], default=None):
    """Parse a JSON string, returning *default* on failure."""
    if not raw:
        return default if default is not None else []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


# ── Shared sub-serializers ─────────────────────────────────────────────────

def _serialize_alert(a: Alert) -> Dict[str, Any]:
    return {
        "alert_id": a.alert_id,
        "engine": a.engine or "unknown",
        "sid": a.sid,
        "signature": a.signature,
        "severity": a.severity,
        "src_ip": a.src_ip,
        "dest_ip": a.dest_ip,
        "ts": a.ts,
    }


def _serialize_ioc(i: Ioc) -> Dict[str, Any]:
    return {
        "ioc_id": i.ioc_id,
        "type": i.ioc_type,
        "value": i.value,
        "severity": i.severity,
        "confidence": i.confidence,
        "context": i.context,
    }


def _serialize_finding_brief(f: Finding) -> Dict[str, Any]:
    return {
        "id": f.finding_id,
        "title": f.title,
        "severity": f.severity,
        "summary": (f.summary or "")[:500],
        "confidence": {
            "score": f.confidence or 0.0,
            "level": _confidence_level(f.confidence or 0.0),
        },
        "sensor": f.sensor,
        "category": f.category,
    }


def _serialize_timeline(t: TimelineEvent) -> Dict[str, Any]:
    return {
        "ts": t.ts,
        "event_type": t.type,
        "severity": t.severity,
        "summary": t.title,
    }


def _serialize_tls(t: TlsSession) -> Dict[str, Any]:
    return {
        "tls_id": t.tls_id,
        "sni": t.sni,
        "ja3": t.ja3,
        "src_ip": t.src_ip,
        "dest_ip": t.dest_ip,
        "version": t.version,
        "ts": t.ts,
    }


def _serialize_dns(d: DnsQuery) -> Dict[str, Any]:
    return {
        "dns_id": d.dns_id,
        "query": d.query,
        "qtype": d.qtype,
        "answers": _safe_json(d.answers_json),
        "rcode": d.rcode,
        "src_ip": d.src_ip,
        "ts": d.ts,
    }


def _serialize_file(f: File) -> Dict[str, Any]:
    return {
        "file_id": f.file_id,
        "filename": f.filename,
        "sha256": f.sha256,
        "size_bytes": f.size_bytes,
        "mime": f.mime,
        "entropy": f.entropy,
        "yara_matches": f.yara_matches,
    }


def _serialize_theory(t: Theory) -> Dict[str, Any]:
    return {
        "id": t.theory_id,
        "label": t.label,
        "hypothesis_type": t.hypothesis_type,
        "score": t.score,
        "confidence": t.confidence,
        "supporting_evidence_refs": _safe_json(t.supporting_evidence_json),
        "contradicting_evidence_refs": _safe_json(t.contradicting_evidence_json),
        "explanation": t.explanation,
    }


def _confidence_level(score: float) -> str:
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"



# ── Job metadata helper ──────────────────────────────────────────────────

def _job_meta(job_id: str) -> Dict[str, Any]:
    """Minimal job metadata for the bundle envelope."""
    return {"job_id": job_id}



# ═══════════════════════════════════════════════════════════════════════════
# Bundle Builders — one per scope type
# ═══════════════════════════════════════════════════════════════════════════


def build_finding_bundle(db: Session, job_id: str, finding_id: str) -> Dict[str, Any]:
    """Build a Finding evidence bundle for explain_finding."""
    finding = db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id == finding_id)
    ).scalars().first()
    if not finding:
        return {}

    bundle: Dict[str, Any] = {
        "job": _job_meta(job_id),
        "scope": {"type": "finding", "id": finding_id},
        "finding": _serialize_finding_brief(finding),
    }

    # Parse evidence JSON for related IPs
    related_ips: set = set()
    evidence_raw = _safe_json(finding.evidence_json, default={})
    if isinstance(evidence_raw, dict):
        for key in ("src_ip", "dest_ip", "host_ip", "ip"):
            if key in evidence_raw:
                related_ips.add(evidence_raw[key])
    elif isinstance(evidence_raw, list):
        for item in evidence_raw[:10]:
            if isinstance(item, dict):
                for key in ("src_ip", "dest_ip", "host_ip", "ip"):
                    if key in item:
                        related_ips.add(item[key])

    # Host info
    if related_ips:
        ip = list(related_ips)[0]
        host = db.execute(
            select(Host).where(Host.job_id == job_id, Host.ip == ip)
        ).scalars().first()
        if host:
            bundle["host"] = {
                "ip": host.ip,
                "hostname": None,
                "role": host.role,
                "first_seen": host.first_seen,
                "last_seen": host.last_seen,
            }

    # Correlated alerts
    community_id = finding.community_id
    if community_id:
        alerts = db.execute(
            select(Alert).where(Alert.job_id == job_id, Alert.community_id == community_id).limit(10)
        ).scalars().all()
        if alerts:
            bundle["alerts"] = [_serialize_alert(a) for a in alerts]

    # IOCs related to this finding's IPs/domains
    iocs = db.execute(select(Ioc).where(Ioc.job_id == job_id).limit(20)).scalars().all()
    related_iocs = [i for i in iocs if any(ip in (i.value or "") for ip in related_ips)]
    if related_iocs:
        bundle["iocs"] = [_serialize_ioc(i) for i in related_iocs[:10]]

    # TLS sessions for related IPs
    if related_ips:
        ip = list(related_ips)[0]
        tls = db.execute(
            select(TlsSession).where(TlsSession.job_id == job_id, TlsSession.host_ip == ip).limit(10)
        ).scalars().all()
        if tls:
            bundle["tls"] = [_serialize_tls(t) for t in tls]

    # Timeline events
    timeline = db.execute(
        select(TimelineEvent).where(TimelineEvent.job_id == job_id).order_by(TimelineEvent.ts).limit(15)
    ).scalars().all()
    if timeline:
        bundle["timeline"] = [_serialize_timeline(t) for t in timeline]

    return bundle


def build_host_bundle(db: Session, job_id: str, host_ip: str) -> Dict[str, Any]:
    """Build a Host evidence bundle for host_summary."""
    host = db.execute(
        select(Host).where(Host.job_id == job_id, Host.ip == host_ip)
    ).scalars().first()
    if not host:
        return {}

    bundle: Dict[str, Any] = {
        "job": _job_meta(job_id),
        "scope": {"type": "host", "id": host_ip},
        "host": {
            "ip": host.ip,
            "hostname": None,
            "role": host.role or "unknown",
            "first_seen": host.first_seen,
            "last_seen": host.last_seen,
            "conn_count": host.conn_count,
            "alert_count": host.alert_count,
            "finding_count": host.finding_count,
        },
    }

    # Findings for this host
    findings = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            or_(
                Finding.title.contains(host_ip),
                Finding.summary.contains(host_ip),
                Finding.evidence_json.contains(host_ip),
            ),
        ).limit(10)
    ).scalars().all()
    if findings:
        bundle["findings"] = [_serialize_finding_brief(f) for f in findings]

    # Alerts
    alerts = db.execute(
        select(Alert).where(
            Alert.job_id == job_id,
            or_(Alert.src_ip == host_ip, Alert.dest_ip == host_ip, Alert.host_ip == host_ip),
        ).limit(10)
    ).scalars().all()
    if alerts:
        bundle["alerts"] = [_serialize_alert(a) for a in alerts]

    # IOCs
    iocs = db.execute(select(Ioc).where(Ioc.job_id == job_id).limit(20)).scalars().all()
    if iocs:
        bundle["iocs"] = [_serialize_ioc(i) for i in iocs[:10]]

    # DNS
    dns = db.execute(
        select(DnsQuery).where(DnsQuery.job_id == job_id, DnsQuery.src_ip == host_ip).limit(10)
    ).scalars().all()
    if dns:
        bundle["dns"] = [_serialize_dns(d) for d in dns]

    # TLS
    tls = db.execute(
        select(TlsSession).where(TlsSession.job_id == job_id, TlsSession.host_ip == host_ip).limit(10)
    ).scalars().all()
    if tls:
        bundle["tls"] = [_serialize_tls(t) for t in tls]

    # Files
    files = db.execute(
        select(File).where(File.job_id == job_id, File.host_ip == host_ip).limit(10)
    ).scalars().all()
    if files:
        bundle["files"] = [_serialize_file(f) for f in files]

    # Theories scoped to this host
    theories = db.execute(
        select(Theory).where(
            Theory.job_id == job_id, Theory.scope_type == "host", Theory.scope_id == host_ip,
        ).order_by(Theory.rank).limit(5)
    ).scalars().all()
    if theories:
        bundle["theories"] = [_serialize_theory(t) for t in theories]

    # Why unusual (derived from theories)
    why_unusual = []
    for t in (theories or []):
        if t.score >= 0.5:
            why_unusual.append(t.label)
    if why_unusual:
        bundle["why_unusual"] = why_unusual

    return bundle


def build_job_bundle(db: Session, job_id: str) -> Dict[str, Any]:
    """Build a Job evidence bundle for job_summary / analyst_report / executive_report."""
    bundle: Dict[str, Any] = {
        "job": _job_meta(job_id),
        "scope": {"type": "job", "id": job_id},
    }

    # Top hosts (by finding count)
    hosts = db.execute(
        select(Host).where(Host.job_id == job_id).order_by(Host.finding_count.desc()).limit(10)
    ).scalars().all()
    if hosts:
        bundle["top_hosts"] = [
            {"ip": h.ip, "role": h.role, "finding_count": h.finding_count,
             "alert_count": h.alert_count}
            for h in hosts
        ]

    # Top findings (by severity / confidence)
    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id).limit(15)
    ).scalars().all()
    if findings:
        bundle["top_findings"] = [_serialize_finding_brief(f) for f in findings]

    # Top IOCs
    iocs = db.execute(select(Ioc).where(Ioc.job_id == job_id).limit(15)).scalars().all()
    if iocs:
        bundle["top_iocs"] = [_serialize_ioc(i) for i in iocs]

    # Theories (job-scoped)
    theories = db.execute(
        select(Theory).where(Theory.job_id == job_id, Theory.scope_type == "job")
        .order_by(Theory.rank).limit(5)
    ).scalars().all()
    if theories:
        bundle["theories"] = [_serialize_theory(t) for t in theories]

    # Slices
    slices = db.execute(
        select(IncidentSlice).where(IncidentSlice.job_id == job_id)
        .order_by(IncidentSlice.rank).limit(10)
    ).scalars().all()
    if slices:
        bundle["slices"] = [
            {"slice_id": s.slice_id, "label": s.label, "severity": s.severity,
             "time_start": s.time_start, "time_end": s.time_end,
             "summary": s.summary}
            for s in slices
        ]

    # Overall confidence (avg of top findings)
    if findings:
        scores = [f.confidence for f in findings if f.confidence]
        avg = sum(scores) / len(scores) if scores else 0.0
        bundle["overall_confidence"] = {
            "score": round(avg, 2),
            "level": _confidence_level(avg),
        }

    return bundle


def build_slice_bundle(db: Session, job_id: str, slice_id: str) -> Dict[str, Any]:
    """Build a Slice evidence bundle for slice_summary."""
    sl = db.execute(
        select(IncidentSlice).where(
            IncidentSlice.job_id == job_id, IncidentSlice.slice_id == slice_id
        )
    ).scalars().first()
    if not sl:
        return {}

    bundle: Dict[str, Any] = {
        "job": _job_meta(job_id),
        "scope": {"type": "slice", "id": slice_id},
        "slice": {
            "slice_id": sl.slice_id,
            "label": sl.label,
            "start_ts": sl.time_start,
            "end_ts": sl.time_end,
            "summary": sl.summary,
            "severity": sl.severity,
        },
        "top_entities": _safe_json(sl.host_ips_json) or [],
    }

    # Member findings
    finding_ids = _safe_json(sl.finding_ids_json)
    if finding_ids:
        findings = db.execute(
            select(Finding).where(
                Finding.job_id == job_id, Finding.finding_id.in_(finding_ids)
            )
        ).scalars().all()
        if findings:
            bundle["findings"] = [_serialize_finding_brief(f) for f in findings]

    # Member alerts
    alert_ids = _safe_json(sl.alert_ids_json)
    if alert_ids:
        alerts = db.execute(
            select(Alert).where(
                Alert.job_id == job_id, Alert.alert_id.in_(alert_ids)
            )
        ).scalars().all()
        if alerts:
            bundle["alerts"] = [_serialize_alert(a) for a in alerts]

    # Member IOCs
    ioc_ids = _safe_json(sl.ioc_ids_json)
    if ioc_ids:
        iocs = db.execute(
            select(Ioc).where(Ioc.job_id == job_id, Ioc.ioc_id.in_(ioc_ids))
        ).scalars().all()
        if iocs:
            bundle["iocs"] = [_serialize_ioc(i) for i in iocs]

    # Timeline within the slice window
    if sl.time_start and sl.time_end:
        timeline = db.execute(
            select(TimelineEvent).where(
                TimelineEvent.job_id == job_id,
                TimelineEvent.ts >= sl.time_start,
                TimelineEvent.ts <= sl.time_end,
            ).order_by(TimelineEvent.ts).limit(20)
        ).scalars().all()
        if timeline:
            bundle["timeline"] = [_serialize_timeline(t) for t in timeline]

    return bundle


# ═══════════════════════════════════════════════════════════════════════════
# Collect all distillation targets for a job
# ═══════════════════════════════════════════════════════════════════════════


def collect_job_targets(db: Session, job_id: str) -> List[Dict[str, Any]]:
    """Return a list of {task_type, scope_id, bundle} dicts for all
    distillation tasks applicable to this job.

    This is the main entry point for the pipeline integration.
    """
    targets: List[Dict[str, Any]] = []

    # 1. explain_finding — one per finding
    findings = db.execute(
        select(Finding.finding_id).where(Finding.job_id == job_id)
    ).scalars().all()
    for fid in findings:
        bundle = build_finding_bundle(db, job_id, fid)
        if bundle:
            targets.append({"task_type": "explain_finding", "scope_id": fid, "bundle": bundle})

    # 2. host_summary — one per host
    hosts = db.execute(
        select(Host.ip).where(Host.job_id == job_id)
    ).scalars().all()
    for ip in hosts:
        bundle = build_host_bundle(db, job_id, ip)
        if bundle:
            targets.append({"task_type": "host_summary", "scope_id": ip, "bundle": bundle})

    # 3. job_summary — one per job
    job_bundle = build_job_bundle(db, job_id)
    if job_bundle:
        targets.append({"task_type": "job_summary", "scope_id": job_id, "bundle": job_bundle})

    # 4. slice_summary — one per slice
    slices = db.execute(
        select(IncidentSlice.slice_id).where(IncidentSlice.job_id == job_id)
    ).scalars().all()
    for sid in slices:
        bundle = build_slice_bundle(db, job_id, sid)
        if bundle:
            targets.append({"task_type": "slice_summary", "scope_id": sid, "bundle": bundle})

    # 5. analyst_report — one per job (uses job bundle)
    if job_bundle:
        targets.append({"task_type": "analyst_report", "scope_id": job_id, "bundle": job_bundle})

    # 6. executive_report — one per job (uses job bundle)
    if job_bundle:
        targets.append({"task_type": "executive_report", "scope_id": job_id, "bundle": job_bundle})

    logger.info("Collected %d distillation targets for job %s", len(targets), job_id)
    return targets

