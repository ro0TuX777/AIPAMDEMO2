from datetime import datetime, timezone

from app.aggregation import aggregate_hosts, diff_change_summaries
from app.models import AlertRecord, FlowRecord


def _dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _flow(host: str, bytes_sent: int, ts: str) -> FlowRecord:
    t = _dt(ts)
    return FlowRecord(
        id=f"flow-{host}-{ts}",
        src_ip=host,
        src_port=12345,
        dst_ip="10.0.0.99",
        dst_port=80,
        transport_proto="tcp",
        app_proto="http",
        start_time=t,
        end_time=t,
        duration_sec=0.0,
        bytes_from_src=bytes_sent,
        bytes_from_dst=0,
        packets_from_src=0,
        packets_from_dst=0,
    )


def test_diff_change_summaries_increases_and_new_protocols():
    # Baseline: host 10.0.0.1 with low bytes, only HTTP.
    baseline_flows = [
        _flow("10.0.0.1", 100, "2025-05-01T10:00:00Z"),
        _flow("10.0.0.99", 50, "2025-05-01T10:15:00Z"),  # extra host from dst side
    ]
    baseline_alerts: list[AlertRecord] = []

    # Exploit: same host with higher bytes and new protocol (e.g., DNS via app_proto).
    exploit_flows = [
        _flow("10.0.0.1", 300, "2025-05-01T11:00:00Z"),
    ]

    baseline_hosts = aggregate_hosts(baseline_flows, baseline_alerts)
    exploit_hosts = aggregate_hosts(exploit_flows, baseline_alerts)

    changes = diff_change_summaries(baseline_hosts, exploit_hosts)
    # We care about the host 10.0.0.1 specifically; other hosts may exist.
    change = next(c for c in changes if c.entity_id == "10.0.0.1")

    assert change.entity_type == "host"
    assert change.entity_id == "10.0.0.1"

    metrics = {m.metric: m for m in change.metric_changes}
    assert metrics["total_flows"].baseline_value == 1
    assert metrics["total_flows"].exploit_value == 1
    assert metrics["total_bytes_sent"].baseline_value == 100
    assert metrics["total_bytes_sent"].exploit_value == 300


def test_diff_change_summaries_host_only_in_exploit():
    baseline_hosts = []

    exploit_flows = [
        _flow("10.0.0.2", 500, "2025-05-01T11:00:00Z"),
        _flow("10.0.0.99", 10, "2025-05-01T11:05:00Z"),  # second host via dst side
    ]
    alerts: list[AlertRecord] = []

    exploit_hosts = aggregate_hosts(exploit_flows, alerts)

    changes = diff_change_summaries(baseline_hosts, exploit_hosts)
    # Focus assertion on host 10.0.0.2, ignore others.
    change = next(c for c in changes if c.entity_id == "10.0.0.2")
    metrics = {m.metric: m for m in change.metric_changes}
    assert metrics["total_flows"].baseline_value == 0
    assert metrics["total_flows"].exploit_value == 1
    assert metrics["total_bytes_sent"].baseline_value == 0
    assert metrics["total_bytes_sent"].exploit_value == 500

