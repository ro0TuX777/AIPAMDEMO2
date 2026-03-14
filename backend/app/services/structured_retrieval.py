"""
Structured DB retrieval service (Route A of the hybrid retrieval router).

Given extracted entities and a job_id, queries the appropriate DB tables
directly and returns formatted context blocks for the LLM.

This is much faster and more accurate than vector search for questions
about specific IPs, domains, hashes, finding IDs, etc.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.tls import TlsSession
from backend.app.services.entity_extractor import ExtractedEntities

logger = logging.getLogger("aipam.structured_retrieval")


@dataclass
class StructuredContext:
    """Result of a structured DB retrieval."""

    blocks: list[str] = field(default_factory=list)
    entity_matches: dict[str, int] = field(default_factory=dict)

    @property
    def has_results(self) -> bool:
        return bool(self.blocks)

    def to_context_string(self, max_chars: int = 3000) -> str:
        """Serialize blocks into a context string within budget."""
        if not self.blocks:
            return ""
        header = "\n=== STRUCTURED DB LOOKUP RESULTS ==="
        parts = [header]
        total = len(header)
        for block in self.blocks:
            if total + len(block) + 5 > max_chars:
                break
            parts.append(block)
            total += len(block) + 1
        parts.append("=== END STRUCTURED RESULTS ===")
        return "\n".join(parts)


def _fmt_host(h: Host) -> str:
    """Format a Host record into a concise context block."""
    try:
        svcs = json.loads(h.top_services_json) if h.top_services_json else []
    except Exception:
        svcs = []
    try:
        sev = json.loads(h.alerts_by_severity_json) if h.alerts_by_severity_json else {}
    except Exception:
        sev = {}
    lines = [
        f"[Host] {h.ip} (role: {h.role or 'unknown'})",
        f"  Connections: {h.conn_count or 0}, Alerts: {h.alert_count or 0}, Findings: {h.finding_count or 0}",
        f"  Bytes: sent={h.bytes_sent or 0}, recv={h.bytes_recv or 0}",
        f"  Active: {h.first_seen or '?'} – {h.last_seen or '?'}",
        f"  DNS queries: {h.dns_query_count or 0}",
    ]
    if svcs:
        lines.append(f"  Services: {', '.join(svcs[:5])}")
    if sev:
        lines.append(f"  Alerts by severity: {sev}")
    return "\n".join(lines)


def _fmt_finding(f: Finding) -> str:
    """Format a Finding record."""
    conf = getattr(f, "confidence", 0.0) or 0.0
    lines = [
        f"[Finding] {f.finding_id}: {f.title}",
        f"  Severity: {f.severity} | Confidence: {round(conf * 100)}% | Sensor: {f.sensor}",
    ]
    if f.category:
        lines.append(f"  Category: {f.category}")
    if f.summary:
        lines.append(f"  Summary: {f.summary[:300]}")
    return "\n".join(lines)


def _fmt_alert(a: Alert) -> str:
    """Format an Alert record."""
    return (
        f"[Alert] {a.signature} | severity={a.severity} | "
        f"{a.src_ip}:{a.src_port or '?'} → {a.dest_ip}:{a.dest_port or '?'} | "
        f"SID={a.sid or '?'} | ts={a.ts}"
    )


def _fmt_ioc(i: Ioc) -> str:
    """Format an IOC record."""
    conf = i.confidence or 0.0
    return (
        f"[IOC] {i.ioc_type}={i.value} | severity={i.severity} | "
        f"confidence={round(conf * 100)}% | sensor={i.source_sensor}"
    )


def _fmt_dns(d: DnsQuery) -> str:
    """Format a DNS query record."""
    answers = ""
    if d.answers_json:
        try:
            answers = ", ".join(json.loads(d.answers_json)[:3])
        except Exception:
            pass
    return (
        f"[DNS] {d.query} (type={d.qtype or '?'}) → {answers or 'no answer'} | "
        f"rcode={d.rcode or '?'} | from={d.src_ip} | ts={d.ts}"
    )


def _fmt_tls(t: TlsSession) -> str:
    """Format a TLS session record."""
    return (
        f"[TLS] sni={t.sni or '?'} | {t.src_ip} → {t.dest_ip}:{t.dest_port or '?'} | "
        f"ja3={t.ja3 or '?'} | version={t.version or '?'} | ts={t.ts}"
    )


def _fmt_connection(c: Connection) -> str:
    """Format a Connection record."""
    return (
        f"[Conn] {c.src_ip}:{c.src_port or '?'} → {c.dest_ip}:{c.dest_port or '?'} | "
        f"proto={c.proto} service={c.service or '?'} | "
        f"bytes={c.bytes_sent or 0}↑/{c.bytes_recv or 0}↓ | ts={c.ts}"
    )


def retrieve_structured(
    db: Session,
    job_id: str,
    entities: ExtractedEntities,
    *,
    max_results_per_type: int = 8,
) -> StructuredContext:
    """Query DB tables for exact matches against extracted entities.

    Returns a StructuredContext with formatted blocks ready for LLM consumption.
    """
    ctx = StructuredContext()

    # ── IP lookups ───────────────────────────────────────────────────
    if entities.ips:
        # Hosts
        hosts = db.execute(
            select(Host).where(Host.job_id == job_id, Host.ip.in_(entities.ips))
            .limit(max_results_per_type)
        ).scalars().all()
        for h in hosts:
            ctx.blocks.append(_fmt_host(h))
        ctx.entity_matches["hosts"] = len(hosts)

        # Alerts involving these IPs (as src or dest)
        ip_alerts = db.execute(
            select(Alert).where(
                Alert.job_id == job_id,
                or_(Alert.src_ip.in_(entities.ips), Alert.dest_ip.in_(entities.ips)),
            ).order_by(Alert.severity.asc()).limit(max_results_per_type)
        ).scalars().all()
        for a in ip_alerts:
            ctx.blocks.append(_fmt_alert(a))
        ctx.entity_matches["ip_alerts"] = len(ip_alerts)

        # Findings — search title/summary for IP mentions
        for ip in entities.ips[:3]:
            ip_findings = db.execute(
                select(Finding).where(
                    Finding.job_id == job_id,
                    or_(
                        Finding.title.contains(ip),
                        Finding.summary.contains(ip),
                        Finding.evidence_json.contains(ip),
                    ),
                ).limit(4)
            ).scalars().all()
            for f in ip_findings:
                block = _fmt_finding(f)
                if block not in ctx.blocks:
                    ctx.blocks.append(block)

        # DNS queries from these IPs
        dns_queries = db.execute(
            select(DnsQuery).where(
                DnsQuery.job_id == job_id,
                DnsQuery.src_ip.in_(entities.ips),
            ).order_by(DnsQuery.ts.desc()).limit(max_results_per_type)
        ).scalars().all()
        for d in dns_queries:
            ctx.blocks.append(_fmt_dns(d))
        ctx.entity_matches["dns_from_ips"] = len(dns_queries)

        # Connections involving these IPs
        ip_conns = db.execute(
            select(Connection).where(
                Connection.job_id == job_id,
                or_(Connection.src_ip.in_(entities.ips), Connection.dest_ip.in_(entities.ips)),
            ).order_by(Connection.ts.desc()).limit(max_results_per_type)
        ).scalars().all()
        for c in ip_conns:
            ctx.blocks.append(_fmt_connection(c))
        ctx.entity_matches["ip_connections"] = len(ip_conns)

        # TLS sessions involving these IPs
        ip_tls = db.execute(
            select(TlsSession).where(
                TlsSession.job_id == job_id,
                or_(TlsSession.src_ip.in_(entities.ips), TlsSession.dest_ip.in_(entities.ips)),
            ).limit(max_results_per_type)
        ).scalars().all()
        for t in ip_tls:
            ctx.blocks.append(_fmt_tls(t))
        ctx.entity_matches["ip_tls"] = len(ip_tls)

    # ── Domain lookups ───────────────────────────────────────────────
    if entities.domains:
        # DNS queries for these domains
        for domain in entities.domains[:5]:
            dns_hits = db.execute(
                select(DnsQuery).where(
                    DnsQuery.job_id == job_id,
                    DnsQuery.query.contains(domain),
                ).limit(max_results_per_type)
            ).scalars().all()
            for d in dns_hits:
                block = _fmt_dns(d)
                if block not in ctx.blocks:
                    ctx.blocks.append(block)
            ctx.entity_matches.setdefault("dns_domains", 0)
            ctx.entity_matches["dns_domains"] += len(dns_hits)

        # TLS sessions with matching SNI
        for domain in entities.domains[:5]:
            tls_hits = db.execute(
                select(TlsSession).where(
                    TlsSession.job_id == job_id,
                    TlsSession.sni.contains(domain),
                ).limit(max_results_per_type)
            ).scalars().all()
            for t in tls_hits:
                block = _fmt_tls(t)
                if block not in ctx.blocks:
                    ctx.blocks.append(block)

        # IOCs of type 'domain'
        domain_iocs = db.execute(
            select(Ioc).where(
                Ioc.job_id == job_id,
                Ioc.ioc_type == "domain",
                Ioc.value.in_(entities.domains),
            ).limit(max_results_per_type)
        ).scalars().all()
        for i in domain_iocs:
            ctx.blocks.append(_fmt_ioc(i))
        ctx.entity_matches["domain_iocs"] = len(domain_iocs)

    # ── Hash lookups ─────────────────────────────────────────────────
    if entities.hashes:
        hash_iocs = db.execute(
            select(Ioc).where(
                Ioc.job_id == job_id,
                Ioc.ioc_type == "hash",
                Ioc.value.in_(entities.hashes),
            ).limit(max_results_per_type)
        ).scalars().all()
        for i in hash_iocs:
            ctx.blocks.append(_fmt_ioc(i))
        ctx.entity_matches["hash_iocs"] = len(hash_iocs)

    # ── Finding ID lookups ───────────────────────────────────────────
    if entities.finding_ids:
        for fid in entities.finding_ids[:5]:
            finding = db.execute(
                select(Finding).where(
                    Finding.job_id == job_id,
                    Finding.finding_id == fid,
                )
            ).scalars().first()
            if finding:
                ctx.blocks.append(_fmt_finding(finding))
                ctx.entity_matches.setdefault("finding_ids", 0)
                ctx.entity_matches["finding_ids"] += 1

    # ── Alert SID lookups ────────────────────────────────────────────
    if entities.alert_sids:
        sid_alerts = db.execute(
            select(Alert).where(
                Alert.job_id == job_id,
                Alert.sid.in_(entities.alert_sids),
            ).limit(max_results_per_type)
        ).scalars().all()
        for a in sid_alerts:
            ctx.blocks.append(_fmt_alert(a))
        ctx.entity_matches["sid_alerts"] = len(sid_alerts)

    # ── JA3 fingerprint lookups ──────────────────────────────────────
    if entities.ja3_fingerprints:
        ja3_sessions = db.execute(
            select(TlsSession).where(
                TlsSession.job_id == job_id,
                or_(
                    TlsSession.ja3.in_(entities.ja3_fingerprints),
                    TlsSession.ja3s.in_(entities.ja3_fingerprints),
                ),
            ).limit(max_results_per_type)
        ).scalars().all()
        for t in ja3_sessions:
            ctx.blocks.append(_fmt_tls(t))
        ctx.entity_matches["ja3_sessions"] = len(ja3_sessions)

    # ── Community ID lookups ─────────────────────────────────────────
    if entities.community_ids:
        cid_alerts = db.execute(
            select(Alert).where(
                Alert.job_id == job_id,
                Alert.community_id.in_(entities.community_ids),
            ).limit(max_results_per_type)
        ).scalars().all()
        for a in cid_alerts:
            block = _fmt_alert(a)
            if block not in ctx.blocks:
                ctx.blocks.append(block)

        cid_conns = db.execute(
            select(Connection).where(
                Connection.job_id == job_id,
                Connection.community_id.in_(entities.community_ids),
            ).limit(max_results_per_type)
        ).scalars().all()
        for c in cid_conns:
            block = _fmt_connection(c)
            if block not in ctx.blocks:
                ctx.blocks.append(block)
        ctx.entity_matches["community_id"] = len(cid_alerts) + len(cid_conns)

    if ctx.blocks:
        logger.info(
            "Structured retrieval for job=%s: %d blocks, matches=%s",
            job_id, len(ctx.blocks), ctx.entity_matches,
        )

    return ctx

