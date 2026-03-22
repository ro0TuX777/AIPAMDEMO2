"""
Temporal Analysis API endpoints — before/after PCAP comparison.

GET  /jobs/{jobId}/temporal-delta      – compute delta between before/after phases
GET  /jobs/{jobId}/temporal-flows      – list new connection flows in the after phase
POST /jobs/{jobId}/temporal-narrative  – generate LLM narrative of temporal changes
"""

import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select
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
    CountDelta,
    DnsDiffs,
    FindingDiffItem,
    HostChangedItem,
    HostDiffItem,
    HostDiffs,
    IocDiffs,
    SeverityCounts,
    TemporalDeltaResponse,
    TemporalFlowItem,
    TemporalFlowsResponse,
    TemporalNarrativeResponse,
    TemporalSummary,
    TrafficDelta,
    TrafficSnapshot,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Temporal"], dependencies=[Depends(verify_token)])

BEFORE = "before"
AFTER = "after"


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _require_temporal(db: Session, job_id: str) -> None:
    """Verify that the job has both before and after PCAP labels."""
    labels = set(
        db.execute(
            select(JobPcap.label).where(JobPcap.job_id == job_id)
        ).scalars().all()
    )
    if BEFORE not in labels or AFTER not in labels:
        raise HTTPException(
            status_code=400,
            detail="Job does not have both 'before' and 'after' PCAP phases",
        )


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




# ─── GET /jobs/{jobId}/temporal-delta ─────────────────────────────────────

@router.get("/jobs/{job_id}/temporal-delta", response_model=TemporalDeltaResponse)
async def get_temporal_delta(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """Compute the delta between 'before' and 'after' PCAP analysis phases."""
    _require_job(db, job_id)
    _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

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

    bh, ah = _hosts(BEFORE), _hosts(AFTER)
    ba, aa = _alerts(BEFORE), _alerts(AFTER)
    bf, af = _findings(BEFORE), _findings(AFTER)
    bi, ai = _iocs(BEFORE), _iocs(AFTER)
    bd, ad = _dns(BEFORE), _dns(AFTER)
    bc_, ac = _conns(BEFORE), _conns(AFTER)
    bt, at_ = _theories(BEFORE), _theories(AFTER)
    btls, atls = _tls(BEFORE), _tls(AFTER)

    # ── Host diffs ──
    bh_ips = {h.ip: h for h in bh}
    ah_ips = {h.ip: h for h in ah}
    added_hosts = [HostDiffItem(ip=h.ip, role=h.role or "unknown", conn_count=h.conn_count or 0, alert_count=h.alert_count or 0)
                   for h in ah if h.ip not in bh_ips]
    removed_hosts = [HostDiffItem(ip=h.ip, role=h.role or "unknown", conn_count=h.conn_count or 0, alert_count=h.alert_count or 0)
                     for h in bh if h.ip not in ah_ips]
    changed_hosts = []
    for ip, hb in bh_ips.items():
        ha = ah_ips.get(ip)
        if ha and ((ha.conn_count or 0) != (hb.conn_count or 0) or (ha.alert_count or 0) != (hb.alert_count or 0)):
            changed_hosts.append(HostChangedItem(
                ip=ip, role=ha.role or "unknown",
                conn_before=hb.conn_count or 0, conn_after=ha.conn_count or 0,
                alert_before=hb.alert_count or 0, alert_after=ha.alert_count or 0,
            ))

    # ── Alert signature diffs ──
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
            signature=sig, severity=asev.get(sig, bsev.get(sig, "info")),
            status=status, before_count=bc_count, after_count=ac_count,
        ))

    # ── Finding diffs ──
    bf_titles = {f.title for f in bf}
    af_titles = {f.title for f in af}
    finding_diffs = []
    for f in af:
        if f.title not in bf_titles:
            finding_diffs.append(FindingDiffItem(title=f.title, severity=f.severity, sensor=f.sensor, status="new"))
    for f in bf:
        if f.title not in af_titles:
            finding_diffs.append(FindingDiffItem(title=f.title, severity=f.severity, sensor=f.sensor, status="removed"))

    # ── IOC diffs ──
    bi_vals = {i.value for i in bi}
    ai_vals = {i.value for i in ai}

    # ── DNS diffs ──
    bd_qnames = {d.query for d in bd}
    ad_qnames = {d.query for d in ad}

    # ── Traffic stats ──
    def _traffic(conns):
        return TrafficSnapshot(
            connections=len(conns),
            bytes_sent=sum(c.bytes_sent or 0 for c in conns),
            bytes_recv=sum(c.bytes_recv or 0 for c in conns),
        )

    summary = TemporalSummary(
        hosts=CountDelta(before=len(bh), after=len(ah), new=len(added_hosts), removed=len(removed_hosts)),
        alerts=AlertCountDelta(
            before=len(ba), after=len(aa),
            new_signatures=sum(1 for d in alert_diffs if d.status == "new"),
            removed_signatures=sum(1 for d in alert_diffs if d.status == "removed"),
        ),
        findings=CountDelta(before=len(bf), after=len(af),
                            new=sum(1 for d in finding_diffs if d.status == "new"),
                            removed=sum(1 for d in finding_diffs if d.status == "removed")),
        iocs=CountDelta(before=len(bi), after=len(ai), new=len(ai_vals - bi_vals), removed=len(bi_vals - ai_vals)),
        dns_domains=CountDelta(before=len(bd_qnames), after=len(ad_qnames), new=len(ad_qnames - bd_qnames), removed=len(bd_qnames - ad_qnames)),
        traffic=TrafficDelta(before=_traffic(bc_), after=_traffic(ac)),
        theories=CountDelta(before=len(bt), after=len(at_)),
        tls_sessions=CountDelta(before=len(btls), after=len(atls)),
        severity_before=_sev_counts(ba),
        severity_after=_sev_counts(aa),
    )

    return TemporalDeltaResponse(
        summary=summary,
        hosts=HostDiffs(added=added_hosts, removed=removed_hosts, changed=changed_hosts),
        alerts=alert_diffs,
        findings=finding_diffs,
        iocs=IocDiffs(added=sorted(ai_vals - bi_vals), removed=sorted(bi_vals - ai_vals)),
        dns=DnsDiffs(added=sorted(ad_qnames - bd_qnames), removed=sorted(bd_qnames - ad_qnames)),
    )



# ─── GET /jobs/{jobId}/temporal-flows ─────────────────────────────────────

@router.get("/jobs/{job_id}/temporal-flows", response_model=TemporalFlowsResponse)
async def get_temporal_flows(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
):
    """List new connection flows that only appear in the 'after' phase."""
    _require_job(db, job_id)
    _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

    before_conns = db.execute(
        select(Connection).where(Connection.job_id == job_id, Connection.pcap_label == BEFORE)
    ).scalars().all()
    after_conns = db.execute(
        select(Connection).where(Connection.job_id == job_id, Connection.pcap_label == AFTER)
    ).scalars().all()

    # Build set of (src_ip, dest_ip, dest_port, proto) tuples from before
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
    _require_temporal(db, job_id)
    response.headers["X-Request-Id"] = request_id

    # Compute delta inline (reuse the same logic)
    delta = await get_temporal_delta(job_id, response, request_id, db)
    s = delta.summary

    lines: list[str] = ["# Temporal Analysis Narrative\n"]
    lines.append(f"## Overview\n")
    lines.append(f"Comparing **before** ({s.hosts.before} hosts, {s.alerts.before} alerts) "
                 f"with **after** ({s.hosts.after} hosts, {s.alerts.after} alerts).\n")

    if s.hosts.new or s.hosts.removed:
        lines.append(f"### Host Changes\n")
        if s.hosts.new:
            lines.append(f"- **{s.hosts.new}** new host(s) appeared\n")
        if s.hosts.removed:
            lines.append(f"- **{s.hosts.removed}** host(s) disappeared\n")

    if s.alerts.new_signatures or s.alerts.removed_signatures:
        lines.append(f"### Alert Signature Changes\n")
        if s.alerts.new_signatures:
            lines.append(f"- **{s.alerts.new_signatures}** new alert signature(s)\n")
        if s.alerts.removed_signatures:
            lines.append(f"- **{s.alerts.removed_signatures}** alert signature(s) no longer seen\n")

    if s.findings.new or s.findings.removed:
        lines.append(f"### Finding Changes\n")
        lines.append(f"- {s.findings.new} new, {s.findings.removed} removed\n")

    if s.iocs.new or s.iocs.removed:
        lines.append(f"### IOC Changes\n")
        lines.append(f"- {s.iocs.new} new IOC(s), {s.iocs.removed} removed\n")

    if s.dns_domains.new or s.dns_domains.removed:
        lines.append(f"### DNS Changes\n")
        lines.append(f"- {s.dns_domains.new} new domain(s) queried, {s.dns_domains.removed} removed\n")

    tb, ta = s.traffic.before, s.traffic.after
    if tb.connections or ta.connections:
        lines.append(f"### Traffic\n")
        lines.append(f"- Before: {tb.connections} connections ({tb.bytes_sent + tb.bytes_recv} bytes total)\n")
        lines.append(f"- After: {ta.connections} connections ({ta.bytes_sent + ta.bytes_recv} bytes total)\n")

    return TemporalNarrativeResponse(narrative_markdown="\n".join(lines))