"""
Correlator Module (§12) — merges sensor outputs into the unified V2 schema.

Reads from job directory:
  - sensors/<name>/sensor.results.jsonl (each sensor's output)
  - sensors/<name>/sensor.meta.json

Produces DB rows:
  - hosts, findings, iocs, connections, dns_queries, tls_sessions, alerts, files, timeline_events

Correlation keys (priority order):
  1. community_id — primary pivot
  2. zeek uid — per-connection
  3. suricata flow_id
  4. 5-tuple + time window (default 5s)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ipaddress

from sqlalchemy.orm import Session

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.dns import DnsQuery
from backend.app.models.file import File
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.timeline import TimelineEvent
from backend.app.models.tls import TlsSession

logger = logging.getLogger("aipam.correlator")


def _emit_finding_event(job_id: str, finding: Finding) -> None:
    """Publish a sensor.finding SSE event for high-severity findings."""
    try:
        from backend.app.events import publish_job_event
        publish_job_event(job_id, "sensor.finding", {
            "job_id": job_id,
            "sensor": finding.sensor or "unknown",
            "finding_id": finding.finding_id or "",
            "severity": finding.severity or "info",
            "title": finding.title,
            "confidence": round(getattr(finding, "confidence", 0.0) or 0.0, 2),
        })
    except Exception:
        pass  # Best-effort — never block correlator


def _uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _safe_json_list(raw: str | None) -> list:
    """Parse JSON list from string, returning [] on failure."""
    if not raw:
        return []
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file, returning list of dicts. Skips bad lines."""
    results = []
    if not path.exists():
        return results
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Bad JSONL line in %s: %s", path, line[:80])
    return results


# ---- Type + field normalization for handler output ----

# Maps handler "type" wrappers to correlator event_type
_HANDLER_TYPE_MAP = {
    "flow": "connection",
    "conn": "connection",
    "event": None,  # needs sub-dispatch on data.event_type
    "alert": "alert",
    "tls_session": "tls",
    "x509": None,  # skip raw x509 records
    "x509_cert": None,
    "anomaly": "finding",
    "extracted_file": "file",
    "ti_indicator": "ioc",
}

# Field renames applied after flattening
_FIELD_RENAMES = {
    "dst_ip": "dest_ip",
    "dst_port": "dest_port",
    "transport_proto": "proto",
    "duration_sec": "duration_seconds",
    "bytes_from_src": "bytes_sent",
    "bytes_from_dst": "bytes_recv",
    "app_proto": "service",
    "signature_name": "signature",
    "signature_id": "sid",
    "timestamp": "ts",
    "server_name": "sni",
    "subject": "cert_subject",
    "issuer": "cert_issuer",
}


def _normalize_event(raw: dict) -> dict | None:
    """Normalize a handler-produced event into the flat correlator format.

    Handles two formats:
      1. Nested: ``{"type": "flow", "data": {...}}``
      2. Flat: ``{"event_type": "connection", "src_ip": ...}``  (pass-through)
    """
    # Already flat format — pass through
    if "event_type" in raw and "data" not in raw:
        return raw

    handler_type = raw.get("type")
    data = raw.get("data")

    if handler_type and isinstance(data, dict):
        # Nested format from sensor handlers
        evt = dict(data)

        mapped = _HANDLER_TYPE_MAP.get(handler_type)
        if mapped is None:
            if handler_type == "event":
                # Sub-dispatch: Zeek events carry their own event_type inside data
                mapped = evt.get("event_type")
                if not mapped:
                    return None
                # Expand "details" dict into top-level keys
                details = evt.pop("details", None)
                if isinstance(details, dict):
                    evt.update(details)
            else:
                return None  # skip x509, etc.

        evt["event_type"] = mapped

        # --- special transforms per handler type ---
        if handler_type == "anomaly":
            # AnomalyFinding.to_dict() → correlator finding
            evt.setdefault("title", evt.get("description", "Anomaly detected"))
            evt.setdefault("severity", "medium")
            evt.setdefault("summary", evt.get("chain_of_thought", ""))
            evidence = evt.get("evidence")
            if isinstance(evidence, list):
                evt["evidence"] = {"items": evidence}
            hosts = evt.get("affected_hosts", [])
            if hosts:
                evt.setdefault("host_ip", hosts[0])

        elif handler_type == "ti_indicator":
            # Convert TI indicator into IOC format
            evt["ioc_type"] = evt.get("ioc_type", "ip")
            evt.setdefault("value", evt.get("ip", ""))
            matched_feed = evt.get("matched_feed", "unknown")
            alert_sigs = evt.get("alert_signatures", [])

            if matched_feed == "ti_bundle":
                evt.setdefault("severity", "high")
                evt.setdefault("confidence", "high")
                evt["context"] = "Matched threat intelligence feed (TI bundle)"
            elif matched_feed == "suricata_correlated":
                evt.setdefault("severity", "medium")
                evt.setdefault("confidence", "medium")
                if alert_sigs:
                    sig_str = "; ".join(alert_sigs[:5])
                    evt["context"] = f"Triggered Suricata IDS alerts: {sig_str}"
                else:
                    evt["context"] = "Correlated with Suricata IDS alert activity"
            else:
                evt.setdefault("severity", "low")
                evt.setdefault("confidence", 0.3)
                evt["context"] = "Observed in network traffic"

        elif handler_type == "extracted_file":
            # Ensure sha256 is top-level (already is from handler)
            pass

        # Apply field renames
        for old_key, new_key in _FIELD_RENAMES.items():
            if old_key in evt and new_key not in evt:
                evt[new_key] = evt.pop(old_key)

        # Preserve sensor attribution and pcap_label
        for key in ("sensor", "pcap_label"):
            if key in raw and key not in evt:
                evt[key] = raw[key]

        return evt

    # Unknown format — try to pass through if it has event_type
    if "event_type" in raw:
        return raw
    return None


def _collect_sensor_outputs(job_dir: Path) -> list[dict]:
    """Gather all sensor.results.jsonl events from all sensors, normalized."""
    all_events: list[dict] = []
    sensors_dir = job_dir / "sensors"
    if not sensors_dir.exists():
        return all_events
    for sensor_dir in sorted(sensors_dir.iterdir()):
        if not sensor_dir.is_dir():
            continue
        results_file = sensor_dir / "sensor.results.jsonl"
        raw_events = _read_jsonl(results_file)
        sensor_name = sensor_dir.name
        for raw in raw_events:
            raw.setdefault("sensor", sensor_name)
            normalized = _normalize_event(raw)
            if normalized is not None:
                normalized.setdefault("sensor", sensor_name)
                all_events.append(normalized)
    return all_events


_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def _classify_role(ip: str) -> str:
    """Return 'internal' for RFC-1918 / link-local / loopback, else 'external'."""
    try:
        addr = ipaddress.ip_address(ip)
        for net in _PRIVATE_NETS:
            if addr in net:
                return "internal"
        if addr.is_multicast or addr.is_reserved:
            return "internal"
        return "external"
    except ValueError:
        return "unknown"


class HostAccumulator:
    """Accumulates host statistics across all events."""

    def __init__(self) -> None:
        self._hosts: dict[str, dict[str, Any]] = {}

    def observe_ip(self, ip: str, **kwargs: Any) -> None:
        if not ip:
            return
        if ip not in self._hosts:
            self._hosts[ip] = {
                "ip": ip,
                "role": "unknown",
                "conn_count": 0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "alert_count": 0,
                "finding_count": 0,
                "first_seen": None,
                "last_seen": None,
                "domains": set(),
                "services": set(),
                "pcap_labels": set(),
            }
        h = self._hosts[ip]
        for k, v in kwargs.items():
            if k == "role" and v and v != "unknown":
                h["role"] = v
            elif k == "conn_count":
                h["conn_count"] += v
            elif k == "bytes_sent":
                h["bytes_sent"] += (v or 0)
            elif k == "bytes_recv":
                h["bytes_recv"] += (v or 0)
            elif k == "alert_count":
                h["alert_count"] += v
            elif k == "finding_count":
                h["finding_count"] += v
            elif k == "domain" and v:
                h["domains"].add(v)
            elif k == "service" and v:
                h["services"].add(v)
            elif k == "pcap_label" and v:
                h["pcap_labels"].add(v)
            elif k == "ts" and v:
                if h["first_seen"] is None or v < h["first_seen"]:
                    h["first_seen"] = v
                if h["last_seen"] is None or v > h["last_seen"]:
                    h["last_seen"] = v

    def to_db_rows(self, job_id: str) -> list[Host]:
        rows = []
        for ip, h in self._hosts.items():
            # For hosts seen in multiple PCAPs, store comma-separated labels
            labels = sorted(h["pcap_labels"])
            pcap_label = ",".join(labels) if labels else None
            rows.append(Host(
                job_id=job_id,
                ip=ip,
                role=h["role"],
                conn_count=h["conn_count"],
                bytes_sent=h["bytes_sent"] or None,
                bytes_recv=h["bytes_recv"] or None,
                alert_count=h["alert_count"],
                finding_count=h["finding_count"],
                first_seen=h["first_seen"],
                last_seen=h["last_seen"],
                top_domains_json=json.dumps(sorted(h["domains"])[:20]),
                top_services_json=json.dumps(sorted(h["services"])[:10]),
                pcap_label=pcap_label,
            ))
        return rows


def _process_connection(evt: dict, job_id: str, hosts: HostAccumulator) -> Connection | None:
    """Process a connection event into a Connection row."""
    src_ip = evt.get("src_ip", "")
    dest_ip = evt.get("dest_ip", "")
    if not src_ip or not dest_ip:
        return None

    hosts.observe_ip(src_ip, role=_classify_role(src_ip), conn_count=1,
                     bytes_sent=evt.get("bytes_sent"), ts=evt.get("ts"),
                     service=evt.get("service"), pcap_label=evt.get("pcap_label"))
    hosts.observe_ip(dest_ip, role=_classify_role(dest_ip), conn_count=1,
                     bytes_recv=evt.get("bytes_recv"), ts=evt.get("ts"),
                     pcap_label=evt.get("pcap_label"))

    return Connection(
        job_id=job_id,
        connection_id=evt.get("connection_id") or _uuid(),
        community_id=evt.get("community_id"),
        host_ip=src_ip,
        src_ip=src_ip,
        src_port=evt.get("src_port"),
        dest_ip=dest_ip,
        dest_port=evt.get("dest_port"),
        proto=evt.get("proto", "unknown"),
        duration_seconds=evt.get("duration_seconds"),
        bytes_sent=evt.get("bytes_sent"),
        bytes_recv=evt.get("bytes_recv"),
        service=evt.get("service"),
        ts=evt.get("ts", _now_iso()),
        pcap_label=evt.get("pcap_label"),
    )


def _process_alert(evt: dict, job_id: str, hosts: HostAccumulator) -> Alert | None:
    """Process an alert event into an Alert row."""
    sig = evt.get("signature") or evt.get("title", "")
    if not sig:
        return None

    host_ip = evt.get("src_ip") or evt.get("host_ip", "unknown")
    hosts.observe_ip(host_ip, alert_count=1, ts=evt.get("ts"),
                     pcap_label=evt.get("pcap_label"))

    return Alert(
        job_id=job_id,
        alert_id=evt.get("alert_id") or _uuid(),
        host_ip=host_ip,
        community_id=evt.get("community_id"),
        severity=evt.get("severity", "medium"),
        engine=evt.get("engine") or evt.get("sensor"),
        signature=sig,
        category=evt.get("category"),
        sid=evt.get("sid"),
        src_ip=evt.get("src_ip"),
        src_port=evt.get("src_port"),
        dest_ip=evt.get("dest_ip"),
        dest_port=evt.get("dest_port"),
        proto=evt.get("proto"),
        refs_json=json.dumps(evt.get("refs", [])),
        tags_json=json.dumps(evt.get("tags", [])),
        ts=evt.get("ts", _now_iso()),
        pcap_label=evt.get("pcap_label"),
    )


def _process_dns(evt: dict, job_id: str, hosts: HostAccumulator) -> DnsQuery | None:
    """Process a DNS event into a DnsQuery row."""
    query_str = evt.get("query", "")
    if not query_str:
        return None

    src_ip = evt.get("src_ip", "unknown")
    hosts.observe_ip(src_ip, domain=query_str, ts=evt.get("ts"),
                     pcap_label=evt.get("pcap_label"))

    return DnsQuery(
        job_id=job_id,
        dns_id=evt.get("dns_id") or _uuid(),
        host_ip=src_ip,
        community_id=evt.get("community_id"),
        src_ip=src_ip,
        query=query_str,
        qtype=evt.get("qtype"),
        answers_json=json.dumps(evt.get("answers", [])),
        rcode=evt.get("rcode"),
        ttl_seconds=evt.get("ttl_seconds"),
        dest_ip=evt.get("dest_ip"),
        ts=evt.get("ts", _now_iso()),
        pcap_label=evt.get("pcap_label"),
    )


def _process_tls(evt: dict, job_id: str, hosts: HostAccumulator) -> TlsSession | None:
    """Process a TLS event into a TlsSession row."""
    src_ip = evt.get("src_ip", "")
    dest_ip = evt.get("dest_ip", "")
    if not src_ip or not dest_ip:
        return None

    hosts.observe_ip(src_ip, ts=evt.get("ts"),
                     pcap_label=evt.get("pcap_label"))

    return TlsSession(
        job_id=job_id,
        tls_id=evt.get("tls_id") or _uuid(),
        host_ip=src_ip,
        community_id=evt.get("community_id"),
        src_ip=src_ip,
        dest_ip=dest_ip,
        dest_port=evt.get("dest_port"),
        sni=evt.get("sni"),
        ja3=evt.get("ja3"),
        ja3s=evt.get("ja3s"),
        alpn=evt.get("alpn"),
        version=evt.get("version"),
        cert_subject=evt.get("cert_subject"),
        cert_issuer=evt.get("cert_issuer"),
        cert_fingerprint_sha1=evt.get("cert_fingerprint_sha1"),
        ts=evt.get("ts", _now_iso()),
        pcap_label=evt.get("pcap_label"),
    )


def _process_finding(evt: dict, job_id: str, hosts: HostAccumulator) -> Finding | None:
    """Process a finding event into a Finding row."""
    title = evt.get("title", "")
    if not title:
        return None

    host_ip = evt.get("host_ip") or evt.get("src_ip")
    if host_ip:
        hosts.observe_ip(host_ip, finding_count=1, ts=evt.get("ts"),
                         pcap_label=evt.get("pcap_label"))

    evidence = evt.get("evidence")
    # Compute confidence from event data or derive from severity
    raw_conf = evt.get("confidence")
    confidence = _to_confidence(raw_conf)
    if confidence is None:
        # Fall back to severity-based confidence
        confidence = _CONFIDENCE_MAP.get(evt.get("severity", "info"), 0.3)
    return Finding(
        job_id=job_id,
        finding_id=evt.get("finding_id") or _uuid(),
        sensor=evt.get("sensor", "unknown"),
        severity=evt.get("severity", "info"),
        category=evt.get("category"),
        title=title,
        summary=evt.get("summary"),
        community_id=evt.get("community_id"),
        evidence_json=json.dumps(evidence) if evidence else None,
        pcap_label=evt.get("pcap_label"),
        confidence=confidence,
    )


_CONFIDENCE_MAP: dict[str, float] = {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.9,
    "critical": 1.0,
    "info": 0.1,
}


def _to_confidence(raw: Any) -> float | None:
    """Convert a confidence value (string label or number) to a float 0-1."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in _CONFIDENCE_MAP:
            return _CONFIDENCE_MAP[lowered]
        try:
            return float(lowered)
        except ValueError:
            return None
    return None


def _process_ioc(evt: dict, job_id: str) -> Ioc | None:
    """Process an IOC event into an Ioc row."""
    ioc_type = evt.get("ioc_type") or evt.get("type", "")
    value = evt.get("value", "")
    if not ioc_type or not value:
        return None

    return Ioc(
        job_id=job_id,
        ioc_id=evt.get("ioc_id") or _uuid(),
        ioc_type=ioc_type,
        value=value,
        severity=evt.get("severity"),
        confidence=_to_confidence(evt.get("confidence")),
        source_sensor=evt.get("sensor"),
        sources_json=json.dumps(evt.get("sources", [evt.get("sensor", "unknown")])),
        context=evt.get("context"),
        pcap_label=evt.get("pcap_label"),
    )


def _process_file(evt: dict, job_id: str, hosts: HostAccumulator) -> File | None:
    """Process a file event into a File row."""
    sha256 = evt.get("sha256", "")
    if not sha256:
        return None

    host_ip = evt.get("host_ip") or evt.get("src_ip")
    if host_ip:
        hosts.observe_ip(host_ip, ts=evt.get("ts"),
                         pcap_label=evt.get("pcap_label"))

    return File(
        job_id=job_id,
        file_id=evt.get("file_id") or _uuid(),
        filename=evt.get("filename"),
        host_ip=host_ip,
        community_id=evt.get("community_id"),
        sha256=sha256,
        md5=evt.get("md5"),
        ssdeep=evt.get("ssdeep"),
        size_bytes=evt.get("size_bytes", 0),
        mime=evt.get("mime"),
        entropy=evt.get("entropy"),
        source=evt.get("source") or evt.get("sensor"),
        extracted_path=evt.get("extracted_path"),
        yara_matches_json=json.dumps(evt.get("yara_matches", [])),
        ts=evt.get("ts"),
        pcap_label=evt.get("pcap_label"),
    )




# ---- Event type dispatch ----

_EVENT_TYPE_MAP = {
    "connection": "connection",
    "conn": "connection",
    "alert": "alert",
    "dns": "dns",
    "dns_query": "dns",
    "tls": "tls",
    "tls_session": "tls",
    "finding": "finding",
    "ioc": "ioc",
    "file": "file",
    "extracted_file": "file",
}


def _make_timeline_event(evt: dict, job_id: str) -> TimelineEvent:
    """Create a timeline event from any sensor event."""
    details = {k: v for k, v in evt.items()
               if k not in ("event_type", "sensor", "ts", "title", "severity")}
    return TimelineEvent(
        job_id=job_id,
        ts=evt.get("ts", _now_iso()),
        type=evt.get("event_type", "unknown"),
        severity=evt.get("severity"),
        title=evt.get("title") or evt.get("signature") or evt.get("query") or
              evt.get("sni") or evt.get("sha256", "event")[:60],
        details_json=json.dumps(details) if details else None,
        pcap_label=evt.get("pcap_label"),
    )


def correlate_job(
    job_id: str,
    job_dir: Path,
    db: Session,
) -> dict[str, int]:
    """
    Main correlator entry point.

    Reads all sensor outputs from job_dir/sensors/*/sensor.results.jsonl,
    processes events by type, and persists to the database.

    Returns a dict of counts: {connections: N, alerts: N, ...}
    """
    events = _collect_sensor_outputs(job_dir)
    logger.info("Correlating %d events for job %s", len(events), job_id)

    hosts = HostAccumulator()
    counts: dict[str, int] = {
        "connections": 0, "alerts": 0, "dns_queries": 0,
        "tls_sessions": 0, "findings": 0, "iocs": 0,
        "files": 0, "timeline_events": 0, "hosts": 0,
    }

    # Deduplicate IOCs by (type, value)
    seen_iocs: set[tuple[str, str]] = set()

    for evt in events:
        event_type = _EVENT_TYPE_MAP.get(evt.get("event_type", ""), "")

        row = None
        if event_type == "connection":
            row = _process_connection(evt, job_id, hosts)
            if row:
                db.add(row)
                counts["connections"] += 1
        elif event_type == "alert":
            row = _process_alert(evt, job_id, hosts)
            if row:
                db.add(row)
                counts["alerts"] += 1
        elif event_type == "dns":
            row = _process_dns(evt, job_id, hosts)
            if row:
                db.add(row)
                counts["dns_queries"] += 1
        elif event_type == "tls":
            row = _process_tls(evt, job_id, hosts)
            if row:
                db.add(row)
                counts["tls_sessions"] += 1
        elif event_type == "finding":
            row = _process_finding(evt, job_id, hosts)
            if row:
                db.add(row)
                counts["findings"] += 1
                # Emit SSE event for high-severity findings
                if row.severity in ("critical", "high"):
                    _emit_finding_event(job_id, row)
        elif event_type == "ioc":
            ioc_key = (evt.get("ioc_type", ""), evt.get("value", ""))
            if ioc_key not in seen_iocs:
                row = _process_ioc(evt, job_id)
                if row:
                    db.add(row)
                    counts["iocs"] += 1
                    seen_iocs.add(ioc_key)
        elif event_type == "file":
            row = _process_file(evt, job_id, hosts)
            if row:
                db.add(row)
                counts["files"] += 1

        # All events get a timeline entry
        if evt.get("ts"):
            tl = _make_timeline_event(evt, job_id)
            db.add(tl)
            counts["timeline_events"] += 1

    # ── Synthesize findings from alerts ──────────────────────────────────
    # Group alerts by signature to create one finding per distinct rule.
    alert_groups: dict[str, list[dict]] = {}
    for evt in events:
        et = _EVENT_TYPE_MAP.get(evt.get("event_type", ""), "")
        if et == "alert":
            sig = evt.get("signature") or evt.get("title", "")
            if sig:
                alert_groups.setdefault(sig, []).append(evt)

    for sig, alert_evts in alert_groups.items():
        # Determine highest severity across occurrences
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        best_sev = max(alert_evts, key=lambda e: sev_order.get(e.get("severity", "medium"), 2))
        severity = best_sev.get("severity", "medium")

        # Collect affected hosts
        affected_ips: set[str] = set()
        for ae in alert_evts:
            for k in ("src_ip", "dest_ip", "host_ip"):
                ip = ae.get(k)
                if ip:
                    affected_ips.add(ip)

        summary_parts = [f"Alert fired {len(alert_evts)} time(s)."]
        if affected_ips:
            summary_parts.append(f"Hosts involved: {', '.join(sorted(affected_ips)[:10])}")
        category = alert_evts[0].get("category")
        engine = alert_evts[0].get("engine") or alert_evts[0].get("sensor", "suricata")

        # Use pcap_label from the first alert in the group (if available)
        pcap_label = alert_evts[0].get("pcap_label")

        # Compute confidence: more alert firings + higher severity = higher confidence
        alert_conf = _CONFIDENCE_MAP.get(severity, 0.6)
        # Bonus for repeated alerts (capped at +0.2)
        repeat_bonus = min(len(alert_evts) - 1, 4) * 0.05
        alert_conf = min(alert_conf + repeat_bonus, 1.0)

        finding = Finding(
            job_id=job_id,
            finding_id=_uuid(),
            sensor=engine,
            severity=severity,
            category=category,
            title=sig,
            summary=" ".join(summary_parts),
            community_id=alert_evts[0].get("community_id"),
            evidence_json=json.dumps({
                "alert_count": len(alert_evts),
                "affected_hosts": sorted(affected_ips),
                "sample_ts": alert_evts[0].get("ts"),
            }),
            pcap_label=pcap_label,
            confidence=round(alert_conf, 2),
        )
        db.add(finding)
        counts["findings"] += 1
        # Emit SSE event for high-severity alert-group findings
        if severity in ("critical", "high"):
            _emit_finding_event(job_id, finding)

        # Update host finding counts
        for ip in affected_ips:
            hosts.observe_ip(ip, finding_count=1)

    # Persist host aggregates
    host_rows = hosts.to_db_rows(job_id)
    for h in host_rows:
        db.add(h)
    counts["hosts"] = len(host_rows)

    db.flush()
    logger.info("Correlation complete for job %s: %s", job_id, counts)
    return counts
