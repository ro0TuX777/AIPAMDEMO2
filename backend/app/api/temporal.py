"""
Temporal Analysis API endpoints — before/after PCAP comparison.

GET  /jobs/{jobId}/temporal-delta      – compute delta between before/after phases
GET  /jobs/{jobId}/temporal-flows      – list new connection flows in the after phase
GET  /jobs/{jobId}/temporal-export     – generate a markdown/html comparison report
POST /jobs/{jobId}/temporal-narrative  – generate LLM narrative of temporal changes
"""

import logging
from collections import Counter
from html import escape
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.job_pcap import JobPcap
from backend.app.models.theory import Theory
from backend.app.models.tls import TlsSession
from backend.app.schemas.temporal import (
    AlertCountDelta,
    AlertDiffItem,
    ContainmentIndicators,
    CountDelta,
    DnsDiffs,
    FindingDiffItem,
    HostChangedItem,
    HostDiffItem,
    HostDiffs,
    IocDiffs,
    PhaseSnapshot,
    PhaseSummary,
    SeverityCounts,
    SeverityShift,
    SeverityShiftItem,
    TemporalDeltaResponse,
    TemporalExportResponse,
    TemporalFlowItem,
    TemporalFlowsResponse,
    TemporalNarrativeResponse,
    TemporalSummary,
    TrafficDelta,
    TrafficSnapshot,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Temporal"], dependencies=[Depends(verify_token)])

TEMPORAL_EXPORT_FORMAT = Literal["markdown", "html"]

# Canonical ordering for label auto-detection.  The first label found in
# this list becomes the "baseline" (phase A) and the second becomes the
# "comparison" (phase B).  Any custom labels not listed here are sorted
# alphabetically after the known ones.
_LABEL_ORDER = ["before", "during", "after"]

_SEVERITY_SHIFT_LEVELS = ("critical", "high", "medium", "low")
_C2_KEYWORDS = (
    "command_and_control",
    "command and control",
    "cnc",
    "beacon",
)
_DEFENSIVE_KEYWORDS = (
    "block",
    "blocked",
    "deny",
    "denied",
    "drop",
    "dropped",
    "quarantine",
    "contained",
    "containment",
    "remediation",
    "remediated",
    "sinkhole",
    "firewall",
    "egress filter",
)


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _resolve_labels(db: Session, job_id: str) -> tuple[str, str]:
    """Return the (phase_a, phase_b) label pair for a temporal comparison.

    Auto-detects labels from the job's PCAPs using canonical ordering
    (before → during → after).  Raises 400 if fewer than two distinct
    labels exist.
    """
    labels = sorted(
        set(
            db.execute(
                select(JobPcap.label).where(JobPcap.job_id == job_id)
            ).scalars().all()
        ),
        key=lambda lbl: (
            _LABEL_ORDER.index(lbl) if lbl in _LABEL_ORDER else len(_LABEL_ORDER),
            lbl,
        ),
    )
    if len(labels) < 2:
        raise HTTPException(
            status_code=400,
            detail="Job needs at least two distinct PCAP phase labels for temporal comparison "
                   f"(found: {labels!r})",
        )
    return labels[0], labels[1]


def _require_temporal(db: Session, job_id: str) -> tuple[str, str]:
    """Verify that the job has ≥2 PCAP labels and return (phase_a, phase_b)."""
    return _resolve_labels(db, job_id)


def _sev_counts(alerts: list) -> SeverityCounts:
    c: Counter = Counter()
    for a in alerts:
        c[a.severity] += 1
    return SeverityCounts(
        critical=c.get("critical", 0),
        high=c.get("high", 0),
        medium=c.get("medium", 0),
        low=c.get("low", 0),
        info=c.get("info", 0),
    )


def _connection_key(connection: Connection) -> tuple[str | None, str | None, int | None, str | None]:
    return (
        connection.src_ip,
        connection.dest_ip,
        connection.dest_port,
        connection.proto,
    )


def _phase_snapshot(
    hosts: list[Host],
    alerts: list[Alert],
    findings: list[Finding],
    connections: list[Connection],
    iocs: list[Ioc],
) -> PhaseSnapshot:
    return PhaseSnapshot(
        host_count=len(hosts),
        alert_count=len(alerts),
        finding_count=len(findings),
        connection_count=len(connections),
        ioc_count=len(iocs),
    )


def _build_severity_shift(before_counts: SeverityCounts, after_counts: SeverityCounts) -> SeverityShift:
    return SeverityShift(
        **{
            level: SeverityShiftItem(
                before=getattr(before_counts, level),
                after=getattr(after_counts, level),
                delta=getattr(after_counts, level) - getattr(before_counts, level),
            )
            for level in _SEVERITY_SHIFT_LEVELS
        }
    )


def _contains_keyword(values: list[str | None], keywords: tuple[str, ...]) -> bool:
    haystack = " ".join(v for v in values if v).lower()
    return any(keyword in haystack for keyword in keywords)


def _is_c2_alert(alert: Alert) -> bool:
    return _contains_keyword([alert.category, alert.signature], _C2_KEYWORDS)


def _is_defensive_alert(alert: Alert) -> bool:
    return _contains_keyword([alert.category, alert.signature], _DEFENSIVE_KEYWORDS)


def _is_defensive_finding(finding: Finding) -> bool:
    return _contains_keyword([finding.category, finding.title, finding.summary], _DEFENSIVE_KEYWORDS)


def _matches_alert_connection(alert: Alert, connection: Connection) -> bool:
    if alert.community_id and connection.community_id:
        return alert.community_id == connection.community_id
    return (
        alert.src_ip == connection.src_ip
        and alert.dest_ip == connection.dest_ip
        and alert.dest_port == connection.dest_port
        and alert.proto == connection.proto
    )


def _build_containment_indicators(
    before_alerts: list[Alert],
    after_alerts: list[Alert],
    before_connections: list[Connection],
    after_connections: list[Connection],
    before_findings: list[Finding],
    after_findings: list[Finding],
) -> ContainmentIndicators:
    removed_connection_keys = {_connection_key(c) for c in before_connections} - {
        _connection_key(c) for c in after_connections
    }
    removed_c2_connection_keys: set[tuple[str | None, str | None, int | None, str | None]] = set()
    for alert in before_alerts:
        if not _is_c2_alert(alert):
            continue
        for connection in before_connections:
            if _matches_alert_connection(alert, connection):
                key = _connection_key(connection)
                if key in removed_connection_keys:
                    removed_c2_connection_keys.add(key)

    before_category_counts = Counter(
        alert.category for alert in before_alerts if alert.category and alert.category.strip()
    )
    after_category_counts = Counter(
        alert.category for alert in after_alerts if alert.category and alert.category.strip()
    )
    reduced_alert_categories = sorted(
        category
        for category, before_count in before_category_counts.items()
        if after_category_counts.get(category, 0) < before_count
    )

    before_defensive_activity = {
        alert.signature or alert.category
        for alert in before_alerts
        if _is_defensive_alert(alert)
    }
    before_defensive_activity.update(
        (finding.title or finding.summary or finding.category)
        for finding in before_findings
        if _is_defensive_finding(finding)
    )
    after_defensive_activity = {
        alert.signature or alert.category
        for alert in after_alerts
        if _is_defensive_alert(alert)
    }
    after_defensive_activity.update(
        (finding.title or finding.summary or finding.category)
        for finding in after_findings
        if _is_defensive_finding(finding)
    )

    return ContainmentIndicators(
        removed_c2_connections=len(removed_c2_connection_keys),
        reduced_alert_categories=reduced_alert_categories,
        new_defensive_activity=sorted(activity for activity in after_defensive_activity - before_defensive_activity if activity),
    )


def _build_temporal_delta_payload(db: Session, job_id: str, label_a: str = "before", label_b: str = "after") -> TemporalDeltaResponse:
    def _hosts(label: str):
        return db.execute(select(Host).where(Host.job_id == job_id, Host.pcap_label == label)).scalars().all()

    def _alerts(label: str):
        return db.execute(select(Alert).where(Alert.job_id == job_id, Alert.pcap_label == label)).scalars().all()

    def _findings(label: str):
        return db.execute(select(Finding).where(Finding.job_id == job_id, Finding.pcap_label == label)).scalars().all()

    def _iocs(label: str):
        return db.execute(select(Ioc).where(Ioc.job_id == job_id, Ioc.pcap_label == label)).scalars().all()

    def _dns(label: str):
        return db.execute(select(DnsQuery).where(DnsQuery.job_id == job_id, DnsQuery.pcap_label == label)).scalars().all()

    def _conns(label: str):
        return db.execute(select(Connection).where(Connection.job_id == job_id, Connection.pcap_label == label)).scalars().all()

    def _theories(label: str):
        return db.execute(select(Theory).where(Theory.job_id == job_id, Theory.pcap_label == label)).scalars().all()

    def _tls(label: str):
        return db.execute(select(TlsSession).where(TlsSession.job_id == job_id, TlsSession.pcap_label == label)).scalars().all()

    bh, ah = _hosts(label_a), _hosts(label_b)
    ba, aa = _alerts(label_a), _alerts(label_b)
    bf, af = _findings(label_a), _findings(label_b)
    bi, ai = _iocs(label_a), _iocs(label_b)
    bd, ad = _dns(label_a), _dns(label_b)
    bc_, ac = _conns(label_a), _conns(label_b)
    bt, at_ = _theories(label_a), _theories(label_b)
    btls, atls = _tls(label_a), _tls(label_b)

    bh_ips = {h.ip: h for h in bh}
    ah_ips = {h.ip: h for h in ah}
    added_hosts = [
        HostDiffItem(ip=h.ip, role=h.role or "unknown", conn_count=h.conn_count or 0, alert_count=h.alert_count or 0)
        for h in ah if h.ip not in bh_ips
    ]
    removed_hosts = [
        HostDiffItem(ip=h.ip, role=h.role or "unknown", conn_count=h.conn_count or 0, alert_count=h.alert_count or 0)
        for h in bh if h.ip not in ah_ips
    ]
    changed_hosts = []
    for ip, hb in bh_ips.items():
        ha = ah_ips.get(ip)
        if ha and ((ha.conn_count or 0) != (hb.conn_count or 0) or (ha.alert_count or 0) != (hb.alert_count or 0)):
            changed_hosts.append(HostChangedItem(
                ip=ip,
                role=ha.role or "unknown",
                conn_before=hb.conn_count or 0,
                conn_after=ha.conn_count or 0,
                alert_before=hb.alert_count or 0,
                alert_after=ha.alert_count or 0,
            ))

    bsigs: Counter = Counter()
    asigs: Counter = Counter()
    bsev: dict[str, str] = {}
    asev: dict[str, str] = {}
    for a in ba:
        bsigs[a.signature] += 1
        bsev[a.signature] = a.severity or "info"
    for a in aa:
        asigs[a.signature] += 1
        asev[a.signature] = a.severity or "info"
    all_sigs = set(bsigs) | set(asigs)
    alert_diffs = []
    for sig in sorted(all_sigs):
        bc_count, ac_count = bsigs.get(sig, 0), asigs.get(sig, 0)
        if bc_count == 0:
            status = "new"
        elif ac_count == 0:
            status = "removed"
        elif bc_count != ac_count:
            status = "changed"
        else:
            continue
        alert_diffs.append(AlertDiffItem(
            signature=sig,
            severity=asev.get(sig, bsev.get(sig, "info")),
            status=status,
            before_count=bc_count,
            after_count=ac_count,
        ))

    bf_titles = {f.title for f in bf}
    af_titles = {f.title for f in af}
    finding_diffs = []
    for f in af:
        if f.title not in bf_titles:
            finding_diffs.append(FindingDiffItem(title=f.title, severity=f.severity, sensor=f.sensor, status="new"))
    for f in bf:
        if f.title not in af_titles:
            finding_diffs.append(FindingDiffItem(title=f.title, severity=f.severity, sensor=f.sensor, status="removed"))

    bi_vals = {i.value for i in bi}
    ai_vals = {i.value for i in ai}
    bd_qnames = {d.query for d in bd}
    ad_qnames = {d.query for d in ad}

    def _traffic(conns: list[Connection]) -> TrafficSnapshot:
        return TrafficSnapshot(
            connections=len(conns),
            bytes_sent=sum(c.bytes_sent or 0 for c in conns),
            bytes_recv=sum(c.bytes_recv or 0 for c in conns),
        )

    severity_before = _sev_counts(ba)
    severity_after = _sev_counts(aa)
    summary = TemporalSummary(
        hosts=CountDelta(before=len(bh), after=len(ah), new=len(added_hosts), removed=len(removed_hosts)),
        alerts=AlertCountDelta(
            before=len(ba), after=len(aa),
            new_signatures=sum(1 for d in alert_diffs if d.status == "new"),
            removed_signatures=sum(1 for d in alert_diffs if d.status == "removed"),
        ),
        findings=CountDelta(
            before=len(bf),
            after=len(af),
            new=sum(1 for d in finding_diffs if d.status == "new"),
            removed=sum(1 for d in finding_diffs if d.status == "removed"),
        ),
        iocs=CountDelta(before=len(bi), after=len(ai), new=len(ai_vals - bi_vals), removed=len(bi_vals - ai_vals)),
        dns_domains=CountDelta(before=len(bd_qnames), after=len(ad_qnames), new=len(ad_qnames - bd_qnames), removed=len(bd_qnames - ad_qnames)),
        traffic=TrafficDelta(before=_traffic(bc_), after=_traffic(ac)),
        theories=CountDelta(before=len(bt), after=len(at_)),
        tls_sessions=CountDelta(before=len(btls), after=len(atls)),
        severity_before=severity_before,
        severity_after=severity_after,
    )

    return TemporalDeltaResponse(
        phase_labels=[label_a, label_b],
        summary=summary,
        phase_summary=PhaseSummary(
            before=_phase_snapshot(bh, ba, bf, bc_, bi),
            after=_phase_snapshot(ah, aa, af, ac, ai),
        ),
        severity_shift=_build_severity_shift(severity_before, severity_after),
        containment_indicators=_build_containment_indicators(ba, aa, bc_, ac, bf, af),
        hosts=HostDiffs(added=added_hosts, removed=removed_hosts, changed=changed_hosts),
        alerts=alert_diffs,
        findings=finding_diffs,
        iocs=IocDiffs(added=sorted(ai_vals - bi_vals), removed=sorted(bi_vals - ai_vals)),
        dns=DnsDiffs(added=sorted(ad_qnames - bd_qnames), removed=sorted(bd_qnames - ad_qnames)),
    )


def _build_temporal_narrative_markdown(delta: TemporalDeltaResponse) -> str:
    s = delta.summary
    lbl_a, lbl_b = delta.phase_labels[0], delta.phase_labels[1]
    lines: list[str] = ["# Temporal Analysis Narrative\n"]
    lines.append("## Overview\n")
    lines.append(
        f"Comparing **{lbl_a}** ({s.hosts.before} hosts, {s.alerts.before} alerts) "
        f"with **{lbl_b}** ({s.hosts.after} hosts, {s.alerts.after} alerts).\n"
    )

    if s.hosts.new or s.hosts.removed:
        lines.append("### Host Changes\n")
        if s.hosts.new:
            lines.append(f"- **{s.hosts.new}** new host(s) appeared\n")
        if s.hosts.removed:
            lines.append(f"- **{s.hosts.removed}** host(s) disappeared\n")

    if s.alerts.new_signatures or s.alerts.removed_signatures:
        lines.append("### Alert Signature Changes\n")
        if s.alerts.new_signatures:
            lines.append(f"- **{s.alerts.new_signatures}** new alert signature(s)\n")
        if s.alerts.removed_signatures:
            lines.append(f"- **{s.alerts.removed_signatures}** alert signature(s) no longer seen\n")

    if s.findings.new or s.findings.removed:
        lines.append("### Finding Changes\n")
        lines.append(f"- {s.findings.new} new, {s.findings.removed} removed\n")

    if s.iocs.new or s.iocs.removed:
        lines.append("### IOC Changes\n")
        lines.append(f"- {s.iocs.new} new IOC(s), {s.iocs.removed} removed\n")

    if s.dns_domains.new or s.dns_domains.removed:
        lines.append("### DNS Changes\n")
        lines.append(f"- {s.dns_domains.new} new domain(s) queried, {s.dns_domains.removed} removed\n")

    tb, ta = s.traffic.before, s.traffic.after
    if tb.connections or ta.connections:
        lines.append("### Traffic\n")
        lines.append(f"- Before: {tb.connections} connections ({tb.bytes_sent + tb.bytes_recv} bytes total)\n")
        lines.append(f"- After: {ta.connections} connections ({ta.bytes_sent + ta.bytes_recv} bytes total)\n")

    if delta.containment_indicators.removed_c2_connections:
        lines.append("### Containment Signals\n")
        lines.append(
            f"- {delta.containment_indicators.removed_c2_connections} suspected C2 connection(s) were removed\n"
        )

    return "\n".join(lines)


def _render_markdown_bullet_list(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items] if items else ["- None"]


def _render_temporal_export_markdown(job_id: str, delta: TemporalDeltaResponse, narrative_markdown: str) -> str:
    lbl_a, lbl_b = delta.phase_labels[0], delta.phase_labels[1]
    phase_before = delta.phase_summary.before
    phase_after = delta.phase_summary.after
    containment = delta.containment_indicators
    severity = delta.severity_shift
    lines = [
        f"# Temporal Comparison Report for Job {job_id}",
        "",
        "## Phase Summary",
        "",
        f"- {lbl_a.capitalize()}: hosts={phase_before.host_count}, alerts={phase_before.alert_count}, findings={phase_before.finding_count}, connections={phase_before.connection_count}, iocs={phase_before.ioc_count}",
        f"- {lbl_b.capitalize()}: hosts={phase_after.host_count}, alerts={phase_after.alert_count}, findings={phase_after.finding_count}, connections={phase_after.connection_count}, iocs={phase_after.ioc_count}",
        "",
        "## Severity Shift",
        "",
        f"- Critical: {severity.critical.before} → {severity.critical.after} (delta {severity.critical.delta})",
        f"- High: {severity.high.before} → {severity.high.after} (delta {severity.high.delta})",
        f"- Medium: {severity.medium.before} → {severity.medium.after} (delta {severity.medium.delta})",
        f"- Low: {severity.low.before} → {severity.low.after} (delta {severity.low.delta})",
        "",
        "## Containment Indicators",
        "",
        f"- Removed C2 connections: {containment.removed_c2_connections}",
        "- Reduced alert categories:",
        *_render_markdown_bullet_list(containment.reduced_alert_categories),
        "- New defensive activity:",
        *_render_markdown_bullet_list(containment.new_defensive_activity),
        "",
        "## Delta Details",
        "",
        f"- Host changes: +{delta.summary.hosts.new} / -{delta.summary.hosts.removed}",
        f"- Alert signature changes: +{delta.summary.alerts.new_signatures} / -{delta.summary.alerts.removed_signatures}",
        f"- Finding changes: +{delta.summary.findings.new} / -{delta.summary.findings.removed}",
        f"- IOC changes: +{delta.summary.iocs.new} / -{delta.summary.iocs.removed}",
        f"- DNS changes: +{delta.summary.dns_domains.new} / -{delta.summary.dns_domains.removed}",
        "",
        "## Narrative",
        "",
        narrative_markdown.strip(),
    ]
    return "\n".join(lines)


def _render_temporal_export_html(job_id: str, delta: TemporalDeltaResponse, narrative_markdown: str) -> str:
    lbl_a, lbl_b = delta.phase_labels[0], delta.phase_labels[1]
    containment = delta.containment_indicators
    severity = delta.severity_shift
    reduced_categories = "".join(f"<li>{escape(item)}</li>" for item in containment.reduced_alert_categories) or "<li>None</li>"
    defensive_activity = "".join(f"<li>{escape(item)}</li>" for item in containment.new_defensive_activity) or "<li>None</li>"
    return "".join([
        "<!DOCTYPE html>",
        "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>",
        escape(f"Temporal Comparison Report for Job {job_id}"),
        "</title></head><body>",
        f"<h1>{escape(f'Temporal Comparison Report for Job {job_id}')}</h1>",
        "<h2>Phase Summary</h2>",
        "<ul>",
        f"<li>{escape(lbl_a.capitalize())}: hosts={delta.phase_summary.before.host_count}, alerts={delta.phase_summary.before.alert_count}, findings={delta.phase_summary.before.finding_count}, connections={delta.phase_summary.before.connection_count}, iocs={delta.phase_summary.before.ioc_count}</li>",
        f"<li>{escape(lbl_b.capitalize())}: hosts={delta.phase_summary.after.host_count}, alerts={delta.phase_summary.after.alert_count}, findings={delta.phase_summary.after.finding_count}, connections={delta.phase_summary.after.connection_count}, iocs={delta.phase_summary.after.ioc_count}</li>",
        "</ul>",
        "<h2>Severity Shift</h2>",
        "<ul>",
        f"<li>Critical: {severity.critical.before} &rarr; {severity.critical.after} (delta {severity.critical.delta})</li>",
        f"<li>High: {severity.high.before} &rarr; {severity.high.after} (delta {severity.high.delta})</li>",
        f"<li>Medium: {severity.medium.before} &rarr; {severity.medium.after} (delta {severity.medium.delta})</li>",
        f"<li>Low: {severity.low.before} &rarr; {severity.low.after} (delta {severity.low.delta})</li>",
        "</ul>",
        "<h2>Containment Indicators</h2>",
        f"<p>Removed C2 connections: {containment.removed_c2_connections}</p>",
        "<h3>Reduced Alert Categories</h3><ul>",
        reduced_categories,
        "</ul><h3>New Defensive Activity</h3><ul>",
        defensive_activity,
        "</ul>",
        "<h2>Narrative</h2>",
        f"<pre>{escape(narrative_markdown.strip())}</pre>",
        "</body></html>",
    ])




# ─── GET /jobs/{jobId}/temporal-delta ─────────────────────────────────────

@router.get("/jobs/{job_id}/temporal-delta", response_model=TemporalDeltaResponse)
async def get_temporal_delta(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Compute the delta between two PCAP analysis phases (auto-detected)."""
    _require_job(db, job_id)
    label_a, label_b = _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

    return _build_temporal_delta_payload(db, job_id, label_a, label_b)



# ─── GET /jobs/{jobId}/temporal-flows ─────────────────────────────────────

@router.get("/jobs/{job_id}/temporal-flows", response_model=TemporalFlowsResponse)
async def get_temporal_flows(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List new connection flows that only appear in the second phase."""
    _require_job(db, job_id)
    label_a, label_b = _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

    before_conns = db.execute(
        select(Connection).where(Connection.job_id == job_id, Connection.pcap_label == label_a)
    ).scalars().all()
    after_conns = db.execute(
        select(Connection).where(Connection.job_id == job_id, Connection.pcap_label == label_b)
    ).scalars().all()

    # Build set of (src_ip, dest_ip, dest_port, proto) tuples from phase A
    before_keys = {(c.src_ip, c.dest_ip, c.dest_port, c.proto) for c in before_conns}

    # Aggregate new flows
    flow_agg: dict[tuple, dict] = {}
    for c in after_conns:
        key = (c.src_ip, c.dest_ip, c.dest_port, c.proto)
        if key in before_keys:
            continue
        if key not in flow_agg:
            flow_agg[key] = {
                "src_ip": c.src_ip, "dest_ip": c.dest_ip,
                "dest_port": c.dest_port, "proto": c.proto,
                "service": c.service, "count": 0,
                "total_bytes_sent": 0, "total_bytes_recv": 0,
            }
        flow_agg[key]["count"] += 1
        flow_agg[key]["total_bytes_sent"] += c.bytes_sent or 0
        flow_agg[key]["total_bytes_recv"] += c.bytes_recv or 0

    flows = [TemporalFlowItem(**v) for v in flow_agg.values()]
    flows.sort(key=lambda f: f.count, reverse=True)

    return TemporalFlowsResponse(flows=flows, total_new_flows=len(flows))


# ─── POST /jobs/{jobId}/temporal-narrative ────────────────────────────────

@router.post("/jobs/{job_id}/temporal-narrative", response_model=TemporalNarrativeResponse)
async def generate_temporal_narrative(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Generate a natural-language narrative summarising the temporal delta."""
    _require_job(db, job_id)
    label_a, label_b = _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

    delta = _build_temporal_delta_payload(db, job_id, label_a, label_b)
    return TemporalNarrativeResponse(narrative_markdown=_build_temporal_narrative_markdown(delta))


@router.get("/jobs/{job_id}/temporal-export", response_model=TemporalExportResponse)
async def export_temporal_report(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    format: TEMPORAL_EXPORT_FORMAT = Query("markdown"),
):
    """Generate a structured comparison report as markdown or HTML."""
    _require_job(db, job_id)
    label_a, label_b = _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

    delta = _build_temporal_delta_payload(db, job_id, label_a, label_b)
    narrative_markdown = _build_temporal_narrative_markdown(delta)
    if format == "html":
        return TemporalExportResponse(
            content=_render_temporal_export_html(job_id, delta, narrative_markdown),
            filename=f"temporal-comparison-{job_id}.html",
        )

    return TemporalExportResponse(
        content=_render_temporal_export_markdown(job_id, delta, narrative_markdown),
        filename=f"temporal-comparison-{job_id}.md",
    )