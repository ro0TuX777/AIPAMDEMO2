from datetime import datetime, timezone

from app.parsers import parse_zeek_conn, parse_suricata_eve
from app.models import FlowRecord, AlertRecord


def _dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def test_parse_zeek_conn_normalizes_proto_and_service():
    logs = [
        {
            "ts": "2025-05-01T10:00:00Z",
            "uid": "C1",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 1.5,
            "orig_bytes": 100,
            "resp_bytes": 200,
            "orig_pkts": 3,
            "resp_pkts": 4,
        },
        {
            "ts": "2025-05-01T10:00:01Z",
            "uid": "C2",
            "id.orig_h": "10.0.0.3",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.4",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "duration": 0.5,
            "orig_bytes": 10,
            "resp_bytes": 20,
        },
        {
            # Unknown proto/service should fall back to OTHER/UNKNOWN
            "ts": "2025-05-01T10:00:02Z",
            "uid": "C3",
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 1111,
            "id.resp_h": "10.0.0.6",
            "id.resp_p": 2222,
            "proto": "sctp",
            "service": "weirdsvc",
            "duration": 0.1,
        },
    ]

    flows = parse_zeek_conn(logs)
    assert len(flows) == 3

    f1, f2, f3 = flows
    assert isinstance(f1, FlowRecord)
    assert f1.transport_proto == "TCP"
    assert f1.app_proto == "HTTP"

    assert f2.transport_proto == "UDP"
    # DNS normalization
    assert f2.app_proto == "DNS"

    # Unknowns
    assert f3.transport_proto == "OTHER"
    assert f3.app_proto == "UNKNOWN"


def test_parse_suricata_eve_normalizes_severity_and_fields():
    logs = [
        {
            "timestamp": "2025-05-01T10:00:00Z",
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "src_port": 12345,
            "dest_ip": "10.0.0.2",
            "dest_port": 80,
            "host": "sensor1",
            "flow_id": 42,
            "alert": {
                "signature_id": 1,
                "signature": "Test sig high",
                "severity": 1,
                "category": "Attempted Admin Privilege Gain",
            },
        },
        {
            "timestamp": "2025-05-01T10:00:01Z",
            "event_type": "alert",
            "src_ip": "10.0.0.3",
            "src_port": 54321,
            "dest_ip": "10.0.0.4",
            "dest_port": 443,
            "host": "sensor1",
            "flow_id": 43,
            "alert": {
                "signature_id": 2,
                "signature": "Test sig medium",
                "severity": 2,
                "category": "Potentially Bad Traffic",
            },
        },
        {
            "timestamp": "2025-05-01T10:00:02Z",
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "src_port": 1111,
            "dest_ip": "10.0.0.6",
            "dest_port": 2222,
            "host": "sensor1",
            "flow_id": 44,
            "alert": {
                "signature_id": 3,
                "signature": "Test sig low",
                "severity": 3,
                "category": "Misc activity",
            },
        },
        {
            # Missing/invalid severity should default to info
            "timestamp": "2025-05-01T10:00:03Z",
            "event_type": "alert",
            "src_ip": "10.0.0.7",
            "src_port": 7777,
            "dest_ip": "10.0.0.8",
            "dest_port": 8888,
            "host": "sensor1",
            "flow_id": 45,
            "alert": {
                "signature_id": 4,
                "signature": "Test sig info",
                "severity": 99,
                "category": "Misc activity",
            },
        },
    ]

    alerts = parse_suricata_eve(logs)
    assert len(alerts) == 4
    a1, a2, a3, a4 = alerts

    assert isinstance(a1, AlertRecord)
    assert a1.alert_source == "SURICATA"
    assert a1.signature_id == "1"
    assert a1.signature_name == "Test sig high"
    assert a1.severity == "high" or a1.severity == "critical"

    assert a2.severity == "medium"
    assert a3.severity == "low"
    assert a4.severity == "info"

