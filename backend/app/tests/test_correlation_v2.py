
from backend.app.normalize.correlate import (
    _normalize_event,
    _classify_role,
    HostAccumulator,
    _process_connection,
    _process_alert
)
from backend.app.models.connection import Connection
from backend.app.models.alert import Alert

def test_normalize_event_nested():
    raw = {
        "type": "flow",
        "data": {
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "transport_proto": "TCP"
        }
    }
    normalized = _normalize_event(raw)
    assert normalized["event_type"] == "connection"
    assert normalized["src_ip"] == "10.0.0.1"
    assert normalized["dest_ip"] == "8.8.8.8"
    assert normalized["proto"] == "TCP"

def test_normalize_zeek_event():
    raw = {
        "type": "event",
        "data": {
            "event_type": "dns",
            "details": {
                "query": "malware.com",
                "qtype_name": "A",
                "answers": ["1.2.3.4"]
            }
        }
    }
    normalized = _normalize_event(raw)
    assert normalized["event_type"] == "dns"
    assert normalized["query"] == "malware.com"
    assert normalized["answers"] == ["1.2.3.4"]

def test_normalize_anomaly():
    raw = {
        "type": "anomaly",
        "sensor": "beaconing",
        "pcap_label": "capture-a",
        "data": {
            "category": "dns",
            "description": "Beaconing detected",
            "chain_of_thought": "Periodic spikes every 60s",
            "affected_hosts": ["10.0.0.5"],
            "severity": "high",
            "evidence": ["flow-123", "flow-456"]
        }
    }
    normalized = _normalize_event(raw)
    assert normalized["event_type"] == "finding"
    assert normalized["title"] == "Beaconing detected"
    assert normalized["severity"] == "high"
    assert normalized["category"] == "dns"
    assert normalized["sensor"] == "beaconing"
    assert normalized["pcap_label"] == "capture-a"
    assert normalized["host_ip"] == "10.0.0.5"
    assert normalized["evidence"]["items"] == ["flow-123", "flow-456"]

def test_normalize_flat_finding_passthrough():
    raw = {
        "event_type": "finding",
        "sensor": "capa",
        "title": "CAPA identified capabilities in sample.exe",
        "summary": "capa identified 2 capability rule(s).",
        "pcap_label": "capture-a",
    }
    normalized = _normalize_event(raw)
    assert normalized == raw

def test_normalize_ti_indicator():
    raw = {
        "type": "ti_indicator",
        "data": {
            "value": "1.2.3.4",
            "ip": "1.2.3.4",
            "ioc_type": "ip",
            "matched_feed": "ti_bundle",
            "description": "Known C2"
        }
    }
    normalized = _normalize_event(raw)
    assert normalized["event_type"] == "ioc"
    assert normalized["value"] == "1.2.3.4"
    assert normalized["severity"] == "high"
    assert "TI bundle" in normalized["context"]


def test_normalize_ti_indicator_domain_uses_explicit_value():
    raw = {
        "type": "ti_indicator",
        "data": {
            "ioc_type": "domain",
            "value": "bad.example",
            "matched_feed": "ti_bundle",
        }
    }
    normalized = _normalize_event(raw)
    assert normalized["event_type"] == "ioc"
    assert normalized["ioc_type"] == "domain"
    assert normalized["value"] == "bad.example"
    assert "ip" not in normalized

def test_classify_role():
    assert _classify_role("192.168.1.1") == "internal"
    assert _classify_role("10.0.0.1") == "internal"
    assert _classify_role("1.1.1.1") == "external"
    assert _classify_role("invalid") == "unknown"

def test_host_accumulator():
    acc = HostAccumulator()
    acc.observe_ip("10.0.0.1", role="internal", conn_count=1, bytes_sent=100, ts="2024-01-01T12:00:00Z")
    acc.observe_ip("10.0.0.1", conn_count=1, bytes_sent=50, ts="2024-01-01T11:00:00Z", service="http")
    
    rows = acc.to_db_rows("job-123")
    assert len(rows) == 1
    h = rows[0]
    assert h.ip == "10.0.0.1"
    assert h.conn_count == 2
    assert h.bytes_sent == 150
    assert h.first_seen == "2024-01-01T11:00:00Z"
    assert h.last_seen == "2024-01-01T12:00:00Z"
    assert "http" in h.top_services_json

def test_process_connection():
    hosts = HostAccumulator()
    evt = {
        "src_ip": "10.0.0.1",
        "dest_ip": "1.1.1.1",
        "src_port": 1234,
        "dest_port": 443,
        "proto": "TCP",
        "community_id": "1:abc"
    }
    conn = _process_connection(evt, "job-123", hosts)
    assert isinstance(conn, Connection)
    assert conn.src_ip == "10.0.0.1"
    assert conn.dest_ip == "1.1.1.1"
    assert conn.community_id == "1:abc"
    
    # Check accumulator
    assert "10.0.0.1" in hosts._hosts
    assert hosts._hosts["10.0.0.1"]["role"] == "internal"
    assert hosts._hosts["1.1.1.1"]["role"] == "external"

def test_process_alert():
    hosts = HostAccumulator()
    evt = {
        "signature": "ET TROJAN Test Alert",
        "src_ip": "10.0.0.1",
        "severity": "high",
        "category": "Trojan",
        "community_id": "1:abc"
    }
    alert = _process_alert(evt, "job-123", hosts)
    assert isinstance(alert, Alert)
    assert alert.signature == "ET TROJAN Test Alert"
    assert alert.severity == "high"
    assert alert.community_id == "1:abc"
