from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Tuple

from .models import (
    AlertRecord,
    ChangeSummary,
    FlowRecord,
    HostPairAlertSummary,
    HostPairSummary,
    HostSummary,
    MetricChange,
    ProtocolUsage,
    TimeWindow,
)


@dataclass
class AggregatedData:
    host_summaries: List[HostSummary]
    host_pair_summaries: List[HostPairSummary]


def _time_window_for_records(timestamps: List[datetime]) -> TimeWindow:
    return TimeWindow(start=min(timestamps), end=max(timestamps))


def aggregate_hosts(
    flows: Iterable[FlowRecord | dict],
    alerts: Iterable[AlertRecord],
) -> List[HostSummary]:
    """Aggregate per-host metrics from flow-like dicts or FlowRecord objects and alerts."""

    per_host: Dict[str, Dict[str, object]] = defaultdict(lambda: defaultdict(int))
    host_timestamps: Dict[str, List[datetime]] = defaultdict(list)
    protocol_counters: Dict[str, Counter] = defaultdict(Counter)
    alerts_by_host: Dict[str, List[AlertRecord]] = defaultdict(list)

    for flow in flows:
        if isinstance(flow, FlowRecord):
            src = flow.src_ip
            dst = flow.dst_ip
            ts = flow.start_time
            app = flow.app_proto
            b_src = flow.bytes_from_src
            b_dst = flow.bytes_from_dst
        else:
            src = str(flow["src_ip"])
            dst = str(flow["dst_ip"])
            ts = flow["timestamp"]
            app = str(flow.get("app_proto", "UNKNOWN")).upper()
            b_src = int(flow.get("bytes_from_src", 0))
            b_dst = int(flow.get("bytes_from_dst", 0))

        for host, sent, recv in (
            (src, b_src, b_dst),
            (dst, b_dst, b_src),
        ):
            per_host[host]["total_flows"] = int(per_host[host].get("total_flows", 0)) + 1
            per_host[host]["total_bytes_sent"] = int(per_host[host].get("total_bytes_sent", 0)) + sent
            per_host[host]["total_bytes_received"] = int(
                per_host[host].get("total_bytes_received", 0)
            ) + recv
            host_timestamps[host].append(ts)
            protocol_counters[host][app] += sent + recv

    for alert in alerts:
        if alert.src_ip:
            alerts_by_host[alert.src_ip].append(alert)
        if alert.dst_ip and alert.dst_ip != alert.src_ip:
            alerts_by_host[alert.dst_ip].append(alert)

    host_summaries: List[HostSummary] = []
    for host_ip, metrics in per_host.items():
        timestamps = host_timestamps[host_ip] or [datetime.utcnow()]
        time_window = _time_window_for_records(timestamps)

        alerts_for_host = alerts_by_host.get(host_ip, [])
        alerts_count = len(alerts_for_host)
        alerts_by_severity: Dict[str, int] = defaultdict(int)
        for a in alerts_for_host:
            alerts_by_severity[a.severity] += 1

        protocol_usage: List[ProtocolUsage] = [
            ProtocolUsage(app_proto=app, flow_count=0, bytes=bytes_)
            for app, bytes_ in protocol_counters[host_ip].most_common()
        ]

        host_summaries.append(
            HostSummary(
                host_ip=host_ip,
                role="unknown",
                time_window=time_window,
                total_flows=int(metrics.get("total_flows", 0)),
                total_bytes_sent=int(metrics.get("total_bytes_sent", 0)),
                total_bytes_received=int(metrics.get("total_bytes_received", 0)),
                top_dst_ips=[],  # populated in a later refinement
                protocol_usage=protocol_usage,
                dns_queries_count=0,
                dns_unique_domains=0,
                http_requests_count=0,
                alerts_count=alerts_count,
                alerts_by_severity=dict(alerts_by_severity),
                suspicious_heuristics={},
            )
        )

    return host_summaries


def aggregate_host_pairs(
    flows: Iterable[FlowRecord | dict], alerts: Iterable[AlertRecord]
) -> List[HostPairSummary]:
    pairs: Dict[Tuple[str, str], Dict[str, object]] = defaultdict(lambda: defaultdict(int))
    timestamps: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
    alerts_by_pair: Dict[Tuple[str, str], List[AlertRecord]] = defaultdict(list)

    for flow in flows:
        if isinstance(flow, FlowRecord):
            src = flow.src_ip
            dst = flow.dst_ip
            ts = flow.start_time
            app = flow.app_proto
            bytes_total = flow.bytes_from_src + flow.bytes_from_dst
        else:
            src = str(flow["src_ip"])
            dst = str(flow["dst_ip"])
            ts = flow["timestamp"]
            app = str(flow.get("app_proto", "UNKNOWN")).upper()
            bytes_total = int(flow.get("bytes_from_src", 0)) + int(flow.get("bytes_from_dst", 0))

        key = (src, dst)
        pairs[key]["flow_count"] = int(pairs[key].get("flow_count", 0)) + 1
        pairs[key]["total_bytes"] = int(pairs[key].get("total_bytes", 0)) + bytes_total
        pairs[key].setdefault("first_seen", ts)
        pairs[key]["last_seen"] = ts
        # track protocol usage bytes; we reuse ProtocolUsage at materialization time
        proto_key = f"proto:{app}"
        pairs[key][proto_key] = int(pairs[key].get(proto_key, 0)) + bytes_total
        timestamps[key].append(ts)

    for alert in alerts:
        if alert.src_ip and alert.dst_ip:
            alerts_by_pair[(alert.src_ip, alert.dst_ip)].append(alert)

    host_pair_summaries: List[HostPairSummary] = []
    for (src, dst), metrics in pairs.items():
        tw = _time_window_for_records(timestamps[(src, dst)])
        alert_summaries: List[HostPairAlertSummary] = []
        for a in alerts_by_pair.get((src, dst), []):
            alert_summaries.append(
                HostPairAlertSummary(
                    timestamp=a.timestamp,
                    signature_name=a.signature_name,
                    severity=a.severity,
                )
            )

        proto_usages: List[ProtocolUsage] = []
        for k, v in metrics.items():
            if isinstance(k, str) and k.startswith("proto:"):
                app = k.split(":", 1)[1]
                proto_usages.append(
                    ProtocolUsage(app_proto=app, flow_count=0, bytes=int(v))
                )

        host_pair_summaries.append(
            HostPairSummary(
                src_ip=src,
                dst_ip=dst,
                time_window=tw,
                flow_count=int(metrics.get("flow_count", 0)),
                total_bytes=int(metrics.get("total_bytes", 0)),
                direction="src_to_dst",
                top_app_protos=proto_usages,
                first_seen=metrics["first_seen"],
                last_seen=metrics["last_seen"],
                alerts=alert_summaries,
                interesting_events=[],
            )
        )

    return host_pair_summaries


def diff_change_summaries(
    baseline: Iterable[HostSummary], exploit: Iterable[HostSummary]
) -> List[ChangeSummary]:
    """Compute coarse ChangeSummary objects for baseline vs exploit.

    This is a conservative first version that focuses on total bytes and
    flow count per host and notes any new protocols.
    """

    base_by_host = {h.host_ip: h for h in baseline}
    expl_by_host = {h.host_ip: h for h in exploit}

    all_hosts = set(base_by_host) | set(expl_by_host)
    changes: List[ChangeSummary] = []

    for host in all_hosts:
        b = base_by_host.get(host)
        e = expl_by_host.get(host)
        metric_changes: List[MetricChange] = []

        def add_metric(name: str, b_val: float, e_val: float) -> None:
            ratio = (e_val / b_val) if b_val > 0 else float("inf") if e_val > 0 else 1.0
            metric_changes.append(
                MetricChange(
                    metric=name,
                    baseline_value=b_val,
                    exploit_value=e_val,
                    ratio=ratio,
                )
            )

        if b and e:
            add_metric("total_flows", b.total_flows, e.total_flows)
            add_metric("total_bytes_sent", b.total_bytes_sent, e.total_bytes_sent)
            add_metric(
                "total_bytes_received", b.total_bytes_received, e.total_bytes_received
            )
            base_protos = {p.app_proto for p in b.protocol_usage}
            expl_protos = {p.app_proto for p in e.protocol_usage}
        elif not b and e:
            add_metric("total_flows", 0, e.total_flows)
            add_metric("total_bytes_sent", 0, e.total_bytes_sent)
            add_metric("total_bytes_received", 0, e.total_bytes_received)
            base_protos = set()
            expl_protos = {p.app_proto for p in e.protocol_usage}
        elif b and not e:
            add_metric("total_flows", b.total_flows, 0)
            add_metric("total_bytes_sent", b.total_bytes_sent, 0)
            add_metric("total_bytes_received", b.total_bytes_received, 0)
            base_protos = {p.app_proto for p in b.protocol_usage}
            expl_protos = set()
        else:
            continue

        new_protocols = sorted(expl_protos - base_protos)

        changes.append(
            ChangeSummary(
                entity_type="host",
                entity_id=host,
                metric_changes=metric_changes,
                new_protocols=new_protocols,
                new_alert_signatures=[],
            )
        )

    return changes

