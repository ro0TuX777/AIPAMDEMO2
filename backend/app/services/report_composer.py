"""
Report Composer — assembles executive and analyst reports from job data.

Pulls from theories, slices, annotations, findings, alerts, IOCs, and hosts
to produce structured, evidence-backed reports in Markdown and JSON.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.context_annotation import ContextAnnotation
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.report import Report
from backend.app.models.slice import IncidentSlice
from backend.app.models.theory import Theory

logger = logging.getLogger("aipam.report_composer")

# ── Severity ordering ────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _threat_level(alerts: list[Alert], findings: list[Finding]) -> str:
    """Determine overall threat level from alerts and findings."""
    worst = "info"
    for a in alerts:
        sev = getattr(a, "severity", "info") or "info"
        if _SEV_ORDER.get(sev, 4) < _SEV_ORDER.get(worst, 4):
            worst = sev
    for f in findings:
        sev = getattr(f, "severity", "info") or "info"
        if _SEV_ORDER.get(sev, 4) < _SEV_ORDER.get(worst, 4):
            worst = sev
    return worst


def _report_confidence(theories: list[Theory], findings: list[Finding]) -> float:
    """Compute overall report confidence from theory and finding confidences."""
    scores: list[float] = []
    for t in theories:
        scores.append(t.score or 0.0)
    for f in findings:
        c = getattr(f, "confidence", 0.0) or 0.0
        scores.append(c)
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 3)


def _make_id(job_id: str, mode: str) -> str:
    """Generate a deterministic-ish report ID."""
    ts = datetime.now(timezone.utc).isoformat()
    h = hashlib.md5(f"{job_id}:{mode}:{ts}".encode()).hexdigest()[:12]
    return f"RPT-{h}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ── Section builders ─────────────────────────────────────────────────────

def _fmt_bytes(b: int | float | None) -> str:
    if not b:
        return "0 B"
    b = float(b)
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.2f} GB"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{int(b)} B"


def _build_executive_sections(
    job: Job,
    theories: list[Theory],
    slices: list[IncidentSlice],
    annotations: list[ContextAnnotation],
    findings: list[Finding],
    alerts: list[Alert],
    iocs: list[Ioc],
    hosts: list[Host],
) -> tuple[str, dict[str, Any]]:
    """Build executive report — concise, impact-focused, low jargon."""
    threat = _threat_level(alerts, findings)
    sections: dict[str, Any] = {}
    md_parts: list[str] = []

    # Title
    md_parts.append("# Executive Summary — PCAP Analysis Report")
    md_parts.append("")
    md_parts.append(f"**Job:** {job.job_id}")
    md_parts.append(f"**PCAP:** {job.pcap_filename or 'N/A'}")
    md_parts.append(f"**Date:** {_now()}")
    md_parts.append(f"**Overall Threat Level:** {threat.upper()}")
    md_parts.append("")

    # Top concern
    sections["summary"] = {
        "threat_level": threat,
        "host_count": len(hosts),
        "alert_count": len(alerts),
        "finding_count": len(findings),
        "ioc_count": len(iocs),
    }

    md_parts.append("## Key Metrics")
    md_parts.append("")
    md_parts.append("| Metric | Count |")
    md_parts.append("|--------|-------|")
    md_parts.append(f"| Hosts Analyzed | {len(hosts)} |")
    md_parts.append(f"| Alerts Triggered | {len(alerts)} |")
    md_parts.append(f"| Findings | {len(findings)} |")
    md_parts.append(f"| IOCs Identified | {len(iocs)} |")
    md_parts.append(f"| Attack Threads | {len(slices)} |")
    md_parts.append(f"| Anomalies Detected | {len(annotations)} |")
    md_parts.append("")

    # Top theories (executive: short)
    if theories:
        md_parts.append("## Top Assessments")
        md_parts.append("")
        sections["top_theories"] = []
        for t in theories[:3]:
            md_parts.append(f"- **{t.label}** (confidence: {t.confidence}, score: {t.score:.0%})")
            sections["top_theories"].append({
                "label": t.label,
                "confidence": t.confidence,
                "score": t.score,
                "theory_id": t.theory_id,
            })
        md_parts.append("")

    # Affected hosts
    suspicious_hosts = sorted(hosts, key=lambda h: (h.alert_count or 0), reverse=True)[:5]
    if suspicious_hosts:
        md_parts.append("## Most Affected Hosts")
        md_parts.append("")
        sections["affected_hosts"] = []
        for h in suspicious_hosts:
            if (h.alert_count or 0) > 0 or (h.finding_count or 0) > 0:
                md_parts.append(f"- **{h.ip}** — {h.alert_count or 0} alerts, {h.finding_count or 0} findings")
                sections["affected_hosts"].append({"ip": h.ip, "alerts": h.alert_count or 0, "findings": h.finding_count or 0})
        md_parts.append("")

    # Recommendations
    md_parts.append("## Recommended Actions")
    md_parts.append("")
    recs = _generate_recommendations(threat, theories, findings, iocs)
    sections["recommendations"] = recs
    for i, r in enumerate(recs, 1):
        md_parts.append(f"{i}. {r}")
    md_parts.append("")

    return "\n".join(md_parts), sections

def _build_analyst_sections(
    job: Job,
    theories: list[Theory],
    slices: list[IncidentSlice],
    annotations: list[ContextAnnotation],
    findings: list[Finding],
    alerts: list[Alert],
    iocs: list[Ioc],
    hosts: list[Host],
) -> tuple[str, dict[str, Any]]:
    """Build analyst report — technical, evidence-heavy, detailed."""
    threat = _threat_level(alerts, findings)
    sections: dict[str, Any] = {}
    md_parts: list[str] = []

    md_parts.append("# Analyst Report — PCAP Investigation")
    md_parts.append("")
    md_parts.append(f"**Job:** `{job.job_id}`")
    md_parts.append(f"**PCAP:** `{job.pcap_filename or 'N/A'}`")
    md_parts.append(f"**Date:** {_now()}")
    md_parts.append(f"**Overall Threat Level:** {threat.upper()}")
    md_parts.append("")

    # ── Theories of the Case ──
    if theories:
        md_parts.append("## Theories of the Case")
        md_parts.append("")
        sections["theories"] = []
        for t in sorted(theories, key=lambda x: x.rank or 999):
            scope_str = f" (host: {t.scope_id})" if t.scope_type == "host" and t.scope_id else ""
            md_parts.append(f"### {t.rank}. {t.label}{scope_str}")
            md_parts.append("")
            md_parts.append(f"- **Type:** {t.hypothesis_type}")
            md_parts.append(f"- **Score:** {t.score:.0%}  |  **Confidence:** {t.confidence}")
            if t.explanation:
                md_parts.append(f"- **Explanation:** {t.explanation}")

            # Supporting evidence
            sup = _parse_json_list(t.supporting_evidence_json)
            if sup:
                md_parts.append(f"- **Supporting Evidence:** {', '.join(f'`{s}`' for s in sup)}")
            con = _parse_json_list(t.contradicting_evidence_json)
            if con:
                md_parts.append(f"- **Contradicting Evidence:** {', '.join(f'`{c}`' for c in con)}")

            steps = _parse_json_list(t.next_steps_json)
            if steps:
                md_parts.append("- **Next Steps:**")
                for s in steps:
                    md_parts.append(f"  - {s}")
            md_parts.append("")

            sections["theories"].append({
                "theory_id": t.theory_id,
                "label": t.label,
                "type": t.hypothesis_type,
                "score": t.score,
                "confidence": t.confidence,
                "rank": t.rank,
                "supporting": sup,
                "contradicting": con,
            })

    # ── Incident Slices (Attack Threads) ──
    if slices:
        md_parts.append("## Incident Slices (Attack Threads)")
        md_parts.append("")
        sections["slices"] = []
        for s in sorted(slices, key=lambda x: x.rank or 999):
            md_parts.append(f"### Slice {s.rank}: {s.label}")
            md_parts.append("")
            md_parts.append(f"- **Type:** {s.slice_type}  |  **Severity:** {s.severity}  |  **Confidence:** {s.confidence:.0%}")
            host_ips = _parse_json_list(s.host_ips_json)
            if host_ips:
                md_parts.append(f"- **Hosts:** {', '.join(f'`{ip}`' for ip in host_ips)}")
            if s.time_start or s.time_end:
                md_parts.append(f"- **Time Window:** {s.time_start or '?'} → {s.time_end or '?'}")
            if s.summary:
                md_parts.append(f"- **Summary:** {s.summary}")

            a_ids = _parse_json_list(s.alert_ids_json)
            f_ids = _parse_json_list(s.finding_ids_json)
            if a_ids:
                md_parts.append(f"- **Alerts ({len(a_ids)}):** {', '.join(f'`{a}`' for a in a_ids[:10])}")
            if f_ids:
                md_parts.append(f"- **Findings ({len(f_ids)}):** {', '.join(f'`{f}`' for f in f_ids[:10])}")
            md_parts.append("")

            sections["slices"].append({
                "slice_id": s.slice_id,
                "label": s.label,
                "type": s.slice_type,
                "severity": s.severity,
                "rank": s.rank,
                "host_ips": host_ips,
                "alert_count": len(a_ids),
                "finding_count": len(f_ids),
            })

    # ── Statistical Anomalies ──
    if annotations:
        md_parts.append("## Statistical Anomalies (Why Unusual?)")
        md_parts.append("")
        sections["anomalies"] = []
        for ann in sorted(annotations, key=lambda a: _SEV_ORDER.get(a.severity, 4)):
            md_parts.append(f"- **{ann.title}** [{ann.severity.upper()}]")
            md_parts.append(f"  - {ann.why_unusual}")
            md_parts.append(f"  - Baseline: {ann.baseline_value:.1f} → Observed: {ann.observed_value:.1f} ({ann.deviation_factor:.1f}x)")
            sections["anomalies"].append({
                "host_ip": ann.host_ip,
                "metric": ann.metric_name,
                "severity": ann.severity,
                "deviation_factor": ann.deviation_factor,
            })
        md_parts.append("")

    # ── Detailed Findings ──
    if findings:
        md_parts.append("## Detailed Findings")
        md_parts.append("")
        sections["findings"] = []
        for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 4)):
            md_parts.append(f"### {f.finding_id}: {f.title}")
            md_parts.append("")
            md_parts.append(f"- **Severity:** {f.severity}  |  **Sensor:** {f.sensor}  |  **Confidence:** {(f.confidence or 0):.0%}")
            if f.summary:
                md_parts.append(f"- {f.summary}")
            md_parts.append("")
            sections["findings"].append({
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "sensor": f.sensor,
            })

    # ── IOCs ──
    if iocs:
        md_parts.append("## Indicators of Compromise")
        md_parts.append("")
        md_parts.append("| Type | Value | Severity | Confidence |")
        md_parts.append("|------|-------|----------|------------|")
        sections["iocs"] = []
        for ioc in iocs:
            sev = ioc.severity or "info"
            conf = f"{(ioc.confidence or 0) * 100:.0f}%" if ioc.confidence else "—"
            md_parts.append(f"| {ioc.ioc_type} | `{ioc.value}` | {sev} | {conf} |")
            sections["iocs"].append({
                "ioc_id": ioc.ioc_id,
                "type": ioc.ioc_type,
                "value": ioc.value,
                "severity": sev,
            })
        md_parts.append("")

    # ── Alert Summary ──
    if alerts:
        md_parts.append("## Alert Summary")
        md_parts.append("")
        sev_counts: dict[str, int] = {}
        for a in alerts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        md_parts.append("| Severity | Count |")
        md_parts.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_counts:
                md_parts.append(f"| {sev.upper()} | {sev_counts[sev]} |")
        md_parts.append("")
        sections["alert_summary"] = sev_counts

    # ── Host Overview ──
    if hosts:
        md_parts.append("## Host Overview")
        md_parts.append("")
        md_parts.append("| IP | Role | Connections | Alerts | Bytes Sent | Bytes Recv |")
        md_parts.append("|-----|------|-------------|--------|------------|------------|")
        sections["hosts"] = []
        for h in sorted(hosts, key=lambda x: (x.alert_count or 0), reverse=True)[:20]:
            md_parts.append(
                f"| `{h.ip}` | {h.role or '?'} | {h.conn_count} | {h.alert_count or 0} "
                f"| {_fmt_bytes(h.bytes_sent)} | {_fmt_bytes(h.bytes_recv)} |"
            )
            sections["hosts"].append({
                "ip": h.ip,
                "role": h.role,
                "conn_count": h.conn_count,
                "alert_count": h.alert_count or 0,
            })
        md_parts.append("")

    # ── Recommendations ──
    md_parts.append("## Recommended Actions")
    md_parts.append("")
    recs = _generate_recommendations(threat, theories, findings, iocs)
    sections["recommendations"] = recs
    for i, r in enumerate(recs, 1):
        md_parts.append(f"{i}. {r}")
    md_parts.append("")

    return "\n".join(md_parts), sections


# ── Helpers ──────────────────────────────────────────────────────────────

def _parse_json_list(raw: str | None) -> list[str]:
    """Safely parse a JSON-encoded list of strings."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return list(parsed) if isinstance(parsed, list) else []
    except Exception:
        return []


def _generate_recommendations(
    threat: str,
    theories: list[Theory],
    findings: list[Finding],
    iocs: list[Ioc],
) -> list[str]:
    """Generate deterministic recommendations based on evidence."""
    recs: list[str] = []

    if threat in ("critical", "high"):
        recs.append("Immediately isolate affected hosts and initiate incident response procedures.")
    if any(t.hypothesis_type == "c2" for t in theories):
        recs.append("Investigate potential C2 channels — check for beaconing patterns and unusual DNS queries.")
    if any(t.hypothesis_type == "exfiltration" for t in theories):
        recs.append("Examine outbound data transfers for potential data exfiltration.")
    if any(t.hypothesis_type == "lateral_movement" for t in theories):
        recs.append("Review internal east-west traffic for lateral movement indicators.")
    if iocs:
        recs.append(f"Block {len(iocs)} identified IOCs at the perimeter (firewall/proxy rules).")
    if any(f.severity in ("critical", "high") for f in findings):
        recs.append("Prioritize investigation of critical and high-severity findings.")
    if not recs:
        recs.append("Continue monitoring — no immediate high-priority actions required.")
    recs.append("Preserve PCAP evidence and analysis artifacts for potential escalation.")
    return recs


# ── Main entry point ─────────────────────────────────────────────────────

def generate_report(db: Session, job_id: str, mode: str = "analyst", pcap_label: str | None = None) -> Report:
    """
    Generate a report for the given job.

    Deletes any existing report of the same mode (and pcap_label), then creates a fresh one.
    Returns the persisted Report ORM object.
    """
    job = db.get(Job, job_id)
    if not job:
        raise ValueError(f"Job {job_id} not found")

    # Fetch evidence, filtered by pcap_label if provided
    tq = select(Theory).where(Theory.job_id == job_id).order_by(Theory.rank)
    sq = select(IncidentSlice).where(IncidentSlice.job_id == job_id).order_by(IncidentSlice.rank)
    aq = select(ContextAnnotation).where(ContextAnnotation.job_id == job_id)
    fq = select(Finding).where(Finding.job_id == job_id)
    alq = select(Alert).where(Alert.job_id == job_id)
    ioq = select(Ioc).where(Ioc.job_id == job_id)
    hq = select(Host).where(Host.job_id == job_id)
    if pcap_label:
        tq = tq.where(Theory.pcap_label == pcap_label)
        sq = sq.where(IncidentSlice.pcap_label == pcap_label)
        aq = aq.where(ContextAnnotation.pcap_label == pcap_label)
        fq = fq.where(Finding.pcap_label == pcap_label)
        alq = alq.where(Alert.pcap_label == pcap_label)
        hq = hq.where(Host.pcap_label == pcap_label)
    theories = list(db.execute(tq).scalars())
    slices = list(db.execute(sq).scalars())
    annotations = list(db.execute(aq).scalars())
    findings = list(db.execute(fq).scalars())
    alerts = list(db.execute(alq).scalars())
    iocs = list(db.execute(ioq).scalars())
    hosts = list(db.execute(hq).scalars())

    # Build sections
    if mode == "executive":
        md, sections_json = _build_executive_sections(job, theories, slices, annotations, findings, alerts, iocs, hosts)
        title = "Executive Summary — PCAP Analysis Report"
    else:
        md, sections_json = _build_analyst_sections(job, theories, slices, annotations, findings, alerts, iocs, hosts)
        title = "Analyst Report — PCAP Investigation"

    threat = _threat_level(alerts, findings)
    confidence = _report_confidence(theories, findings)

    # Collect all evidence refs
    evidence_refs: list[str] = []
    evidence_refs.extend(t.theory_id for t in theories)
    evidence_refs.extend(s.slice_id for s in slices)
    evidence_refs.extend(a.annotation_id for a in annotations)
    evidence_refs.extend(f.finding_id for f in findings)
    evidence_refs.extend(ioc.ioc_id for ioc in iocs)

    # Delete existing report of same mode + pcap_label
    del_stmt = delete(Report).where(Report.job_id == job_id, Report.mode == mode)
    if pcap_label:
        del_stmt = del_stmt.where(Report.pcap_label == pcap_label)
    else:
        del_stmt = del_stmt.where(Report.pcap_label.is_(None))
    db.execute(del_stmt)
    db.flush()

    report = Report(
        job_id=job_id,
        report_id=_make_id(job_id, mode),
        mode=mode,
        title=title,
        threat_level=threat,
        confidence=confidence,
        content_markdown=md,
        content_json=json.dumps(sections_json),
        theory_count=len(theories),
        slice_count=len(slices),
        finding_count=len(findings),
        alert_count=len(alerts),
        ioc_count=len(iocs),
        host_count=len(hosts),
        annotation_count=len(annotations),
        evidence_refs_json=json.dumps(evidence_refs),
        pcap_label=pcap_label,
        created_at=_now(),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    logger.info(
        "Generated %s report %s for job %s: %d theories, %d slices, %d annotations, %d findings, %d alerts, %d IOCs",
        mode, report.report_id, job_id,
        len(theories), len(slices), len(annotations), len(findings), len(alerts), len(iocs),
    )
    return report
