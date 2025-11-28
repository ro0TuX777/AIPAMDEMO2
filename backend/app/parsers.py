from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List

from .models import AlertRecord, EventRecord, FlowRecord


def _parse_timestamp(ts: str) -> datetime:
    # Zeek/Suricata typically use ISO8601 with Z
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _normalize_transport_proto(proto: str | None) -> str:
    p = (proto or "").lower()
    if p == "tcp":
        return "TCP"
    if p == "udp":
        return "UDP"
    if p == "icmp":
        return "ICMP"
    return "OTHER"


def _normalize_app_proto(service: str | None) -> str:
    s = (service or "").lower()
    if s == "http":
        return "HTTP"
    if s in {"https", "ssl", "tls"}:
        # Treat TLS/SSL-based application protocols as TLS for now; downstream
        # logic can refine if needed.
        return "TLS"
    if s == "dns":
        return "DNS"
    if s == "smb":
        return "SMB"
    if s == "rdp":
        return "RDP"
    if s == "ssh":
        return "SSH"
    return "UNKNOWN"


def parse_zeek_conn(logs: Iterable[dict]) -> List[FlowRecord]:
    """Parse Zeek conn.log-style JSON records into FlowRecord objects.

    This is intentionally conservative and expects already-normalized keys,
    but it *does* normalize transport_proto and app_proto to the spec's
    fixed enums.
    """

    records: List[FlowRecord] = []
    for rec in logs:
        try:
            # Handle Zeek JSON keys
            ts_val = rec.get("ts")
            if isinstance(ts_val, (int, float)):
                start = datetime.fromtimestamp(ts_val, timezone.utc)
            else:
                start = _parse_timestamp(str(ts_val))

            duration = float(rec.get("duration", 0.0))
            end = datetime.fromtimestamp(start.timestamp() + duration, timezone.utc)

            records.append(
                FlowRecord(
                    id=str(rec.get("uid", "")),
                    src_ip=str(rec.get("id.orig_h", "")),
                    src_port=int(rec.get("id.orig_p", 0)),
                    dst_ip=str(rec.get("id.resp_h", "")),
                    dst_port=int(rec.get("id.resp_p", 0)),
                    transport_proto=_normalize_transport_proto(rec.get("proto")),
                    app_proto=_normalize_app_proto(rec.get("service")),
                    start_time=start,
                    end_time=end,
                    duration_sec=duration,
                    bytes_from_src=int(rec.get("orig_bytes", 0) or 0),
                    bytes_from_dst=int(rec.get("resp_bytes", 0) or 0),
                    packets_from_src=int(rec.get("orig_pkts", 0) or 0),
                    packets_from_dst=int(rec.get("resp_pkts", 0) or 0),
                    tcp_flags_summary=rec.get("history"),  # Mapping history to tcp_flags_summary roughly
                    num_resets=0,  # Zeek doesn't explicitly give num_resets in conn.log usually
                    state=rec.get("conn_state"),
                    sensor_id=rec.get("sensor_id"),
                    tags=list(rec.get("tags", [])),
                    extra={
                        k: str(v)
                        for k, v in rec.items()
                        if k
                        not in {
                            "ts",
                            "uid",
                            "id.orig_h",
                            "id.orig_p",
                            "id.resp_h",
                            "id.resp_p",
                            "proto",
                            "service",
                            "duration",
                            "orig_bytes",
                            "resp_bytes",
                            "conn_state",
                            "history",
                            "orig_pkts",
                            "resp_pkts",
                        }
                    },
                )
            )
        except Exception:
            # In v1, silently drop malformed records; can be logged by caller.
            continue
    return records


def parse_zeek_events(logs: Iterable[dict]) -> List[EventRecord]:
    """Parse protocol-specific Zeek/tshark JSON into EventRecord objects.

    This function expects each dict to already carry an `event_type` key
    like "DNS_QUERY" or "HTTP_REQUEST" and normalized IP/port fields.
    """

    events: List[EventRecord] = []
    for rec in logs:
        try:
            ts = _parse_timestamp(rec["timestamp"])
            events.append(
                EventRecord(
                    id=str(rec["id"]),
                    event_type=str(rec["event_type"]),
                    timestamp=ts,
                    src_ip=str(rec["src_ip"]),
                    dst_ip=str(rec["dst_ip"]),
                    src_port=int(rec["src_port"]),
                    dst_port=int(rec["dst_port"]),
                    transport_proto=str(rec.get("transport_proto", "OTHER")).upper(),
                    sensor_id=rec.get("sensor_id"),
                    flow_id=rec.get("flow_id"),
                    details=rec.get("details", {}),
                )
            )
        except Exception:
            continue
    return events


def _normalize_suricata_severity(value: int | str | None) -> str:
    """Map Suricata numeric severity to spec strings.

    Suricata commonly uses 1 (high), 2 (medium), 3 (low). We also allow
    strings and fall back to "info" for anything unexpected.
    """

    if value is None:
        return "info"
    try:
        sev_int = int(value)
    except (TypeError, ValueError):
        # If it's already a string like "high", trust it if recognized
        s = str(value).lower()
        if s in {"info", "low", "medium", "high", "critical"}:
            return s
        return "info"

    if sev_int <= 0:
        return "info"
    if sev_int == 1:
        # Treat Suricata's highest level as "high" for now; callers can
        # optionally upgrade to "critical" in post-processing.
        return "high"
    if sev_int == 2:
        return "medium"
    if sev_int == 3:
        return "low"
    return "info"


def parse_suricata_eve(logs: Iterable[dict]) -> List[AlertRecord]:
    """Parse Suricata EVE JSON alert events into AlertRecord objects."""

    alerts: List[AlertRecord] = []
    for rec in logs:
        if rec.get("event_type") != "alert":
            continue
        try:
            ts = _parse_timestamp(rec["timestamp"])
            alert = rec.get("alert", {})
            alerts.append(
                AlertRecord(
                    id=str(
                        rec.get("flow_id")
                        or alert.get("signature_id")
                        or rec["timestamp"]
                    ),
                    timestamp=ts,
                    src_ip=rec.get("src_ip"),
                    src_port=rec.get("src_port"),
                    dst_ip=rec.get("dest_ip") or rec.get("dst_ip"),
                    dst_port=rec.get("dest_port") or rec.get("dst_port"),
                    sensor_id=rec.get("host"),
                    alert_source="SURICATA",
                    signature_id=str(alert.get("signature_id"))
                    if alert.get("signature_id") is not None
                    else None,
                    signature_name=str(alert.get("signature", "unknown")),
                    severity=_normalize_suricata_severity(alert.get("severity")),
                    category=alert.get("category"),
                    flow_id=str(rec.get("flow_id")) if rec.get("flow_id") is not None else None,
                    extra={
                        k: v
                        for k, v in rec.items()
                        if k
                        not in {
                            "timestamp",
                            "src_ip",
                            "src_port",
                            "dest_ip",
                            "dest_port",
                            "dst_ip",
                            "dst_port",
                            "flow_id",
                            "host",
                            "event_type",
                            "alert",
                        }
                    },
                )
            )
        except Exception:
            continue
    return alerts

