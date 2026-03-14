"""
Scoped Evidence Bundles for the AI Chat context pipeline.

Bundles are typed, structured containers that assemble DB records into
high-density, consistent context blocks for the LLM. Each bundle type
knows how to query its scope (host, finding, IOC, job summary) and
serialize itself into a context string.

Usage:
    bundle = build_scoped_bundle(db, job_id, scope_type="host", scope_id="10.0.0.5")
    context_str = bundle.to_context()
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.dns import DnsQuery
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.theory import Theory
from backend.app.models.slice import IncidentSlice
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.report import Report

logger = logging.getLogger("aipam.evidence_bundles")


# ── Base bundle ──────────────────────────────────────────────────────────

@dataclass
class EvidenceBundle:
    """Base class for all evidence bundles."""

    scope_type: str
    scope_id: str
    job_id: str
    sections: list[str] = field(default_factory=list)

    def to_context(self, max_chars: int = 3000) -> str:
        """Serialize bundle into a context string within budget."""
        if not self.sections:
            return ""
        header = f"\n=== SCOPED EVIDENCE: {self.scope_type.upper()} {self.scope_id} ==="
        parts = [header]
        total = len(header)
        for section in self.sections:
            if total + len(section) + 5 > max_chars:
                break
            parts.append(section)
            total += len(section) + 1
        parts.append(f"=== END {self.scope_type.upper()} EVIDENCE ===")
        return "\n".join(parts)

    @property
    def has_evidence(self) -> bool:
        return bool(self.sections)


# ── Host Bundle ──────────────────────────────────────────────────────────

def _build_host_bundle(db: Session, job_id: str, ip: str) -> EvidenceBundle:
    """Assemble comprehensive evidence for a specific host IP."""
    bundle = EvidenceBundle(scope_type="host", scope_id=ip, job_id=job_id)

    # Host record
    host = db.execute(
        select(Host).where(Host.job_id == job_id, Host.ip == ip)
    ).scalars().first()
    if host:
        try:
            svcs = json.loads(host.top_services_json) if host.top_services_json else []
        except Exception:
            svcs = []
        try:
            doms = json.loads(host.top_domains_json) if host.top_domains_json else []
        except Exception:
            doms = []
        try:
            sev = json.loads(host.alerts_by_severity_json) if host.alerts_by_severity_json else {}
        except Exception:
            sev = {}
        lines = [
            f"Host: {host.ip} | Role: {host.role or 'unknown'}",
            f"Connections: {host.conn_count or 0} | Alerts: {host.alert_count or 0} | Findings: {host.finding_count or 0}",
            f"Bytes: sent={host.bytes_sent or 0} recv={host.bytes_recv or 0}",
            f"Active: {host.first_seen or '?'} – {host.last_seen or '?'}",
            f"DNS queries: {host.dns_query_count or 0} | TLS sessions: {host.tls_session_count or 0}",
        ]
        if svcs:
            lines.append(f"Services: {', '.join(svcs[:8])}")
        if doms:
            lines.append(f"Top domains: {', '.join(doms[:8])}")
        if sev:
            lines.append(f"Alerts by severity: {sev}")
        bundle.sections.append("\n".join(lines))

    # Alerts for this host
    alerts = db.execute(
        select(Alert).where(
            Alert.job_id == job_id,
            or_(Alert.src_ip == ip, Alert.dest_ip == ip, Alert.host_ip == ip),
        ).order_by(Alert.severity.asc()).limit(10)
    ).scalars().all()
    if alerts:
        alert_lines = ["Alerts involving this host:"]
        for a in alerts:
            alert_lines.append(
                f"  [{a.severity}] {a.signature} | "
                f"{a.src_ip}:{a.src_port or '?'} → {a.dest_ip}:{a.dest_port or '?'} | "
                f"SID={a.sid or '?'} ts={a.ts}"
            )
        bundle.sections.append("\n".join(alert_lines))

    # Findings mentioning this host
    findings = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            or_(
                Finding.title.contains(ip),
                Finding.summary.contains(ip),
                Finding.evidence_json.contains(ip),
            ),
        ).limit(6)
    ).scalars().all()
    if findings:
        finding_lines = ["Findings related to this host:"]
        for f in findings:
            conf = getattr(f, "confidence", 0.0) or 0.0
            finding_lines.append(
                f"  [{f.severity}|{round(conf*100)}%] {f.finding_id}: {f.title}"
            )
            if f.summary:
                finding_lines.append(f"    {f.summary[:200]}")
        bundle.sections.append("\n".join(finding_lines))

    # DNS queries from this host
    dns = db.execute(
        select(DnsQuery).where(DnsQuery.job_id == job_id, DnsQuery.src_ip == ip)
        .order_by(DnsQuery.ts.desc()).limit(8)
    ).scalars().all()
    if dns:
        dns_lines = ["DNS queries from this host:"]
        for d in dns:
            answers = ""
            if d.answers_json:
                try:
                    answers = ", ".join(json.loads(d.answers_json)[:3])
                except Exception:
                    pass
            dns_lines.append(f"  {d.query} ({d.qtype or '?'}) → {answers or 'no answer'} | ts={d.ts}")
        bundle.sections.append("\n".join(dns_lines))

    return bundle


# ── Finding Bundle ───────────────────────────────────────────────────────

def _build_finding_bundle(db: Session, job_id: str, finding_id: str) -> EvidenceBundle:
    """Assemble comprehensive evidence for a specific finding."""
    bundle = EvidenceBundle(scope_type="finding", scope_id=finding_id, job_id=job_id)

    finding = db.execute(
        select(Finding).where(Finding.job_id == job_id, Finding.finding_id == finding_id)
    ).scalars().first()
    if not finding:
        return bundle

    conf = getattr(finding, "confidence", 0.0) or 0.0
    lines = [
        f"Finding: {finding.finding_id}",
        f"Title: {finding.title}",
        f"Severity: {finding.severity} | Confidence: {round(conf * 100)}% | Sensor: {finding.sensor}",
    ]
    if finding.category:
        lines.append(f"Category: {finding.category}")
    if finding.summary:
        lines.append(f"Summary: {finding.summary[:500]}")
    bundle.sections.append("\n".join(lines))

    # Parse evidence JSON for related IPs/community IDs
    related_ips: set[str] = set()
    community_id = finding.community_id
    if finding.evidence_json:
        try:
            evidence = json.loads(finding.evidence_json)
            if isinstance(evidence, dict):
                for key in ("src_ip", "dest_ip", "host_ip", "ip"):
                    if key in evidence:
                        related_ips.add(evidence[key])
                if "community_id" in evidence and not community_id:
                    community_id = evidence["community_id"]
            elif isinstance(evidence, list):
                for item in evidence[:5]:
                    if isinstance(item, dict):
                        for key in ("src_ip", "dest_ip", "host_ip", "ip"):
                            if key in item:
                                related_ips.add(item[key])
        except Exception:
            pass

    # Correlated alerts (by community_id or IPs)
    if community_id:
        correlated_alerts = db.execute(
            select(Alert).where(
                Alert.job_id == job_id, Alert.community_id == community_id,
            ).limit(6)
        ).scalars().all()
        if correlated_alerts:
            alert_lines = ["Correlated alerts (same flow):"]
            for a in correlated_alerts:
                alert_lines.append(
                    f"  [{a.severity}] {a.signature} | "
                    f"{a.src_ip}:{a.src_port or '?'} → {a.dest_ip}:{a.dest_port or '?'}"
                )
            bundle.sections.append("\n".join(alert_lines))

    # Related host info
    for ip in list(related_ips)[:3]:
        host = db.execute(
            select(Host).where(Host.job_id == job_id, Host.ip == ip)
        ).scalars().first()
        if host:
            bundle.sections.append(
                f"Related host: {host.ip} (role={host.role or '?'}, "
                f"conns={host.conn_count or 0}, alerts={host.alert_count or 0})"
            )

    return bundle


# ── IOC Bundle ───────────────────────────────────────────────────────────

def _build_ioc_bundle(db: Session, job_id: str, ioc_value: str) -> EvidenceBundle:
    """Assemble evidence for a specific IOC value (IP, domain, hash)."""
    bundle = EvidenceBundle(scope_type="ioc", scope_id=ioc_value, job_id=job_id)

    # IOC record
    ioc = db.execute(
        select(Ioc).where(Ioc.job_id == job_id, Ioc.value == ioc_value)
    ).scalars().first()
    if ioc:
        conf = ioc.confidence or 0.0
        lines = [
            f"IOC: {ioc.ioc_type}={ioc.value}",
            f"Severity: {ioc.severity or '?'} | Confidence: {round(conf * 100)}%",
            f"Sensor: {ioc.source_sensor or '?'}",
        ]
        if ioc.context:
            lines.append(f"Context: {ioc.context[:300]}")
        bundle.sections.append("\n".join(lines))

    # Findings mentioning this IOC value
    findings = db.execute(
        select(Finding).where(
            Finding.job_id == job_id,
            or_(
                Finding.title.contains(ioc_value),
                Finding.summary.contains(ioc_value),
                Finding.evidence_json.contains(ioc_value),
            ),
        ).limit(5)
    ).scalars().all()
    if findings:
        finding_lines = ["Findings mentioning this IOC:"]
        for f in findings:
            conf = getattr(f, "confidence", 0.0) or 0.0
            finding_lines.append(f"  [{f.severity}|{round(conf*100)}%] {f.title}")
        bundle.sections.append("\n".join(finding_lines))

    # Alerts mentioning this IOC (if it's an IP)
    alerts = db.execute(
        select(Alert).where(
            Alert.job_id == job_id,
            or_(Alert.src_ip == ioc_value, Alert.dest_ip == ioc_value),
        ).limit(6)
    ).scalars().all()
    if alerts:
        alert_lines = ["Alerts involving this IOC:"]
        for a in alerts:
            alert_lines.append(f"  [{a.severity}] {a.signature}")
        bundle.sections.append("\n".join(alert_lines))

    return bundle


# ── Job Summary Bundle ───────────────────────────────────────────────────

def _build_job_summary_bundle(db: Session, job_id: str) -> EvidenceBundle:
    """Assemble a high-level job summary bundle."""
    bundle = EvidenceBundle(scope_type="job_summary", scope_id=job_id, job_id=job_id)

    # Count totals
    host_count = db.execute(
        select(Host).where(Host.job_id == job_id)
    ).scalars().all()
    alert_count = db.execute(
        select(Alert).where(Alert.job_id == job_id)
    ).scalars().all()
    finding_count = db.execute(
        select(Finding).where(Finding.job_id == job_id)
    ).scalars().all()
    ioc_count = db.execute(
        select(Ioc).where(Ioc.job_id == job_id)
    ).scalars().all()

    lines = [
        f"Job Summary: {job_id}",
        f"Hosts: {len(host_count)} | Alerts: {len(alert_count)} | "
        f"Findings: {len(finding_count)} | IOCs: {len(ioc_count)}",
    ]

    # Top findings by severity
    top_findings = db.execute(
        select(Finding).where(Finding.job_id == job_id)
        .order_by(Finding.confidence.desc())
        .limit(5)
    ).scalars().all()
    if top_findings:
        lines.append("Top findings:")
        for f in top_findings:
            conf = getattr(f, "confidence", 0.0) or 0.0
            lines.append(f"  [{f.severity}|{round(conf*100)}%] {f.title}")

    bundle.sections.append("\n".join(lines))
    return bundle


# ── Bundle Router ────────────────────────────────────────────────────────

# ── Theory Bundle ───────────────────────────────────────────────────────

def _build_theory_bundle(db: Session, job_id: str, theory_id: str) -> EvidenceBundle:
    """Assemble context for a specific theory hypothesis."""
    bundle = EvidenceBundle(scope_type="theory", scope_id=theory_id, job_id=job_id)

    theory = db.execute(
        select(Theory).where(Theory.job_id == job_id, Theory.theory_id == theory_id)
    ).scalars().first()
    if not theory:
        # If theory_id not found, try loading all job-level theories
        theories = db.execute(
            select(Theory).where(Theory.job_id == job_id, Theory.scope_type == "job")
            .order_by(Theory.rank.asc())
        ).scalars().all()
        if theories:
            lines = ["Job-level theories (ranked hypotheses):"]
            for t in theories:
                lines.append(f"  #{t.rank} [{t.confidence}] {t.label} (score={t.score:.0%})")
                if t.explanation:
                    lines.append(f"    {t.explanation[:200]}")
            bundle.sections.append("\n".join(lines))
        return bundle

    supporting = []
    if theory.supporting_evidence_json:
        try:
            supporting = json.loads(theory.supporting_evidence_json)
        except Exception:
            pass
    contradicting = []
    if theory.contradicting_evidence_json:
        try:
            contradicting = json.loads(theory.contradicting_evidence_json)
        except Exception:
            pass

    lines = [
        f"Theory: {theory.label}",
        f"Type: {theory.hypothesis_type} | Score: {theory.score:.0%} | Confidence: {theory.confidence}",
        f"Rank: #{theory.rank} | Scope: {theory.scope_type}:{theory.scope_id}",
    ]
    if theory.explanation:
        lines.append(f"Explanation: {theory.explanation}")
    if supporting:
        lines.append(f"Supporting evidence: {', '.join(supporting)}")
    if contradicting:
        lines.append(f"Contradicting evidence: {', '.join(contradicting)}")
    bundle.sections.append("\n".join(lines))

    # Include related findings for context
    if supporting:
        findings = db.execute(
            select(Finding).where(
                Finding.job_id == job_id,
                Finding.finding_id.in_(supporting),
            ).limit(5)
        ).scalars().all()
        if findings:
            f_lines = ["Related findings:"]
            for f in findings:
                f_lines.append(f"  [{f.severity}] {f.finding_id}: {f.title}")
                if f.summary:
                    f_lines.append(f"    {f.summary[:200]}")
            bundle.sections.append("\n".join(f_lines))

    return bundle


def _build_slice_bundle(db: Session, job_id: str, slice_id: str) -> EvidenceBundle:
    """Assemble context for a specific incident slice."""
    bundle = EvidenceBundle(scope_type="slice", scope_id=slice_id, job_id=job_id)

    s = db.execute(
        select(IncidentSlice).where(IncidentSlice.job_id == job_id, IncidentSlice.slice_id == slice_id)
    ).scalars().first()

    if not s:
        # Provide summary of all slices if specific one not found
        slices = db.execute(
            select(IncidentSlice).where(IncidentSlice.job_id == job_id)
            .order_by(IncidentSlice.rank.asc())
        ).scalars().all()
        if slices:
            lines = ["Job incident slices (attack threads):"]
            for sl in slices:
                lines.append(f"  #{sl.rank} [{sl.severity}] {sl.label} ({sl.slice_type})")
                if sl.summary:
                    lines.append(f"    {sl.summary[:200]}")
            bundle.sections.append("\n".join(lines))
        return bundle

    # Build detailed slice context
    host_ips = json.loads(s.host_ips_json) if s.host_ips_json else []
    alert_ids = json.loads(s.alert_ids_json) if s.alert_ids_json else []
    finding_ids = json.loads(s.finding_ids_json) if s.finding_ids_json else []
    ioc_ids = json.loads(s.ioc_ids_json) if s.ioc_ids_json else []
    community_ids = json.loads(s.community_ids_json) if s.community_ids_json else []

    lines = [
        f"Incident Slice: {s.label}",
        f"Type: {s.slice_type} | Severity: {s.severity} | Confidence: {s.confidence:.0%}",
        f"Rank: #{s.rank} | Hosts: {', '.join(host_ips)}",
        f"Time range: {s.time_start or '?'} → {s.time_end or '?'}",
        f"Community IDs: {', '.join(community_ids) if community_ids else 'none'}",
    ]
    if s.summary:
        lines.append(f"Summary: {s.summary}")
    lines.append(f"Member alerts: {', '.join(alert_ids) if alert_ids else 'none'}")
    lines.append(f"Member findings: {', '.join(finding_ids) if finding_ids else 'none'}")
    lines.append(f"Member IOCs: {', '.join(ioc_ids) if ioc_ids else 'none'}")
    bundle.sections.append("\n".join(lines))

    # Add detail for member alerts
    if alert_ids:
        alerts = db.execute(
            select(Alert).where(Alert.job_id == job_id, Alert.alert_id.in_(alert_ids))
        ).scalars().all()
        if alerts:
            a_lines = [f"Member Alerts ({len(alerts)}):"]
            for a in alerts:
                a_lines.append(f"  [{a.severity}] {a.signature} ({a.src_ip}→{a.dest_ip})")
            bundle.sections.append("\n".join(a_lines))

    # Add detail for member findings
    if finding_ids:
        findings = db.execute(
            select(Finding).where(Finding.job_id == job_id, Finding.finding_id.in_(finding_ids))
        ).scalars().all()
        if findings:
            f_lines = [f"Member Findings ({len(findings)}):"]
            for f in findings:
                f_lines.append(f"  [{f.severity}] {f.title}")
                if f.summary:
                    f_lines.append(f"    {f.summary[:200]}")
            bundle.sections.append("\n".join(f_lines))

    return bundle


def _build_annotation_bundle(db: Session, job_id: str, scope_id: str) -> EvidenceBundle:
    """Assemble context for annotations — scope_id can be host IP or annotation_id."""
    bundle = EvidenceBundle(scope_type="annotation", scope_id=scope_id, job_id=job_id)

    # Try as annotation_id first, then as host_ip filter
    ann = db.execute(
        select(ContextAnnotation).where(
            ContextAnnotation.job_id == job_id,
            ContextAnnotation.annotation_id == scope_id,
        )
    ).scalars().first()

    if ann:
        annotations = [ann]
    else:
        # Treat scope_id as host IP
        annotations = db.execute(
            select(ContextAnnotation).where(
                ContextAnnotation.job_id == job_id,
                ContextAnnotation.host_ip == scope_id,
            )
        ).scalars().all()

    if not annotations:
        bundle.sections.append(f"No context annotations found for '{scope_id}'.")
        return bundle

    lines = [f"Context Annotations ({len(annotations)} items):"]
    for a in annotations:
        lines.append(f"\n--- {a.title} [{a.severity}] ---")
        lines.append(f"Host: {a.host_ip} | Metric: {a.metric_name}")
        lines.append(f"Observed: {a.observed_value} | Baseline: {a.baseline_value}")
        lines.append(f"Deviation: {a.deviation_factor}σ | Confidence: {a.confidence:.0%}")
        lines.append(f"Why unusual: {a.why_unusual}")
    bundle.sections.append("\n".join(lines))

    return bundle


def _build_report_bundle(db: Session, job_id: str, scope_id: str) -> EvidenceBundle:
    """Assemble context from a generated report — scope_id is 'executive' or 'analyst'."""
    mode = scope_id if scope_id in ("executive", "analyst") else "analyst"
    bundle = EvidenceBundle(scope_type="report", scope_id=mode, job_id=job_id)

    report = db.execute(
        select(Report).where(Report.job_id == job_id, Report.mode == mode)
        .order_by(Report.created_at.desc())
    ).scalars().first()

    if not report:
        bundle.sections.append(f"No {mode} report has been generated yet for this job.")
        return bundle

    # Include the markdown content (truncated to budget)
    lines = [
        f"Generated {mode.title()} Report: {report.report_id}",
        f"Threat Level: {report.threat_level} | Confidence: {report.confidence:.0%}",
        f"Evidence: {report.theory_count} theories, {report.slice_count} slices, "
        f"{report.finding_count} findings, {report.alert_count} alerts, {report.ioc_count} IOCs",
        "",
        report.content_markdown[:2000],
    ]
    bundle.sections.append("\n".join(lines))
    return bundle


def build_scoped_bundle(
    db: Session,
    job_id: str,
    scope_type: str,
    scope_id: str = "",
) -> EvidenceBundle:
    """Route to the correct bundle builder based on scope_type.

    scope_type values:
        "host"         — scope_id is an IP address
        "finding"      — scope_id is a finding_id (e.g., F-101)
        "ioc"          — scope_id is an IOC value
        "job_summary"  — scope_id is ignored
        "annotation"   — scope_id is annotation_id or host IP
        "report"       — scope_id is 'executive' or 'analyst'
    """
    scope_type = scope_type.lower().strip()

    if scope_type == "host":
        return _build_host_bundle(db, job_id, scope_id)
    elif scope_type == "finding":
        return _build_finding_bundle(db, job_id, scope_id)
    elif scope_type == "ioc":
        return _build_ioc_bundle(db, job_id, scope_id)
    elif scope_type == "job_summary":
        return _build_job_summary_bundle(db, job_id)
    elif scope_type == "theory":
        return _build_theory_bundle(db, job_id, scope_id)
    elif scope_type == "slice":
        return _build_slice_bundle(db, job_id, scope_id)
    elif scope_type == "annotation":
        return _build_annotation_bundle(db, job_id, scope_id)
    elif scope_type == "report":
        return _build_report_bundle(db, job_id, scope_id)
    elif scope_type == "evidence_graph":
        return _build_evidence_graph_bundle(db, job_id)
    elif scope_type == "proof":
        return _build_proof_bundle(db, job_id, scope_id)
    else:
        logger.warning("Unknown scope_type=%s, returning empty bundle", scope_type)
        return EvidenceBundle(scope_type=scope_type, scope_id=scope_id, job_id=job_id)


def _build_evidence_graph_bundle(db: Session, job_id: str) -> EvidenceBundle:
    """Build an evidence bundle containing the graph summary for a job."""
    from backend.app.services.evidence_graph import graph_summary

    bundle = EvidenceBundle(scope_type="evidence_graph", scope_id="", job_id=job_id)
    try:
        summary = graph_summary(db, job_id)
        bundle.sections.append(summary)
    except ValueError:
        bundle.sections.append("Evidence graph not available (no job data).")
    return bundle


def _build_proof_bundle(db: Session, job_id: str, scope_id: str) -> EvidenceBundle:
    """Build an evidence bundle from proof data for chat context."""
    from backend.app.services.proof_builder import proof_summary

    bundle = EvidenceBundle(scope_type="proof", scope_id=scope_id, job_id=job_id)
    try:
        summary = proof_summary(db, job_id)
        bundle.sections.append(summary)
    except Exception:
        bundle.sections.append("Proof data not available.")
    return bundle


def parse_context_hint(context_hint: str | None) -> tuple[str, str]:
    """Parse a context_hint string into (scope_type, scope_id).

    Expected formats:
        "host:10.0.0.5"
        "finding:F-101"
        "ioc:evil.example.com"
        "theory:TH-abc12345"
        "evidence_graph"
        "job_summary"
        None → ("", "")
    """
    if not context_hint:
        return ("", "")
    parts = context_hint.strip().split(":", 1)
    scope_type = parts[0].strip().lower()
    scope_id = parts[1].strip() if len(parts) > 1 else ""
    return (scope_type, scope_id)
