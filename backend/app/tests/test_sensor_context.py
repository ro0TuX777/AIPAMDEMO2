import pytest
from unittest.mock import MagicMock
from backend.app.llm_client import LLMClient

@pytest.fixture
def llm_client():
    return LLMClient()

def test_get_v(llm_client):
    # Test dict
    assert llm_client._get_v({"a": 1}, "a") == 1
    assert llm_client._get_v({"a": 1}, "b", default=2) == 2
    
    # Test object
    class Obj:
        def __init__(self):
            self.x = 10
    obj = Obj()
    assert llm_client._get_v(obj, "x") == 10
    assert llm_client._get_v(obj, "y", default=5) == 5
    
    # Test None
    assert llm_client._get_v(None, "any", default="default") == "default"

def test_extract_hosts_summary_list(llm_client):
    bundle = {
        "host_summaries": [
            {"host_ip": "10.0.0.1", "bytes_sent": 1000, "connection_count": 5, "protocols": ["TCP", "HTTP"]}
        ],
        "hostpair_summaries": [
            {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "bytes_total": 500}
        ]
    }
    summary = llm_client._extract_hosts_summary(bundle)
    assert "Host 10.0.0.1: 1000 bytes, 5 connections, protocols: TCP, HTTP" in summary
    assert "Connection 10.0.0.1->8.8.8.8: 500 bytes" in summary

def test_extract_hosts_summary_dict(llm_client):
    bundle = {
        "host_summaries": {
            "10.0.0.1": {"bytes_sent": 1000, "connection_count": 5, "protocols": ["TCP", "HTTP"]}
        }
    }
    summary = llm_client._extract_hosts_summary(bundle)
    assert "Host 10.0.0.1: 1000 bytes, 5 connections, protocols: TCP, HTTP" in summary

def test_extract_alerts_summary(llm_client):
    bundle = {
        "alerts": [
            {"signature_name": "ET MALWARE Test", "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1"}
        ],
        "trafficllm_results": {
            "malware_types": ["Pikabot"],
            "malware_detections": 1
        }
    }
    summary = llm_client._extract_alerts_summary(bundle)
    assert "ALERT: ET MALWARE Test (src: 10.0.0.1 -> dst: 1.1.1.1)" in summary
    assert "MALWARE DETECTED: Pikabot (1 flows)" in summary

def test_format_packet_data_raw(llm_client):
    bundle = {
        "raw_packet_samples": ["packet1_hex", "packet2_hex"]
    }
    fmt = llm_client._format_packet_data(bundle)
    assert fmt == "packet1_hex\npacket2_hex"

def test_format_packet_data_fallback(llm_client):
    bundle = {
        "hostpair_summaries_exploit": [
            {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_ports": [443], "total_bytes": 1024}
        ]
    }
    fmt = llm_client._format_packet_data(bundle)
    assert "ip.src: 10.0.0.1, ip.dst: 8.8.8.8, tcp.dstport: 443" in fmt

def test_extract_hosts_summary_empty(llm_client):
    assert "No detailed host information available" in llm_client._extract_hosts_summary({})

def test_extract_alerts_summary_empty(llm_client):
    assert "No alerts or detections" in llm_client._extract_alerts_summary({})
