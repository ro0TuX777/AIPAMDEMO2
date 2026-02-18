"""Gold-standard test harness for the AIPAM analysis pipeline.

Tests the deterministic portions of the pipeline (parsing → aggregation →
ForensicData IR) against known-good sample data.  LLM calls are NOT made
in these tests; instead, pre-recorded LLM outputs are used for the
Finding conversion stage.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

import pytest

from app.domain.forensic_data import ForensicData
from app.domain.finding import Finding, FindingSeverity
from app.domain.finding_adapter import llm_output_to_findings
from app.models import (
    AlertRecord,
    AnalysisSummary,
    AttackChainItem,
    FlowRecord,
    HostFindingLLM,
    LLMOutput,
    MitreTechnique,
    Anomaly,
)
from app.parsers import parse_zeek_conn, parse_suricata_eve
from app.aggregation import aggregate_hosts, aggregate_host_pairs


# ---------------------------------------------------------------------------
# Sample data directory
# ---------------------------------------------------------------------------

SAMPLES_DIR = Path(__file__).parent / "samples"


# ---------------------------------------------------------------------------
# Sample Zeek/Suricata data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def zeek_conn_icedid() -> List[dict]:
    """Sample Zeek conn.log records simulating IcedID C2 traffic."""
    return [
        {
            "ts": 1700000000.0,
            "uid": "CdhXbc2WnVWrx1hLXl",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "185.70.40.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 120.5,
            "orig_bytes": 15000,
            "resp_bytes": 250000,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 150,
            "orig_ip_bytes": 21000,
            "resp_pkts": 200,
            "resp_ip_bytes": 262000,
            "tunnel_parents": [],
        },
        {
            "ts": 1700000300.0,
            "uid": "CdhXbc2WnVWrx1hLX2",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49153,
            "id.resp_h": "185.70.40.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 60.0,
            "orig_bytes": 8000,
            "resp_bytes": 120000,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 80,
            "orig_ip_bytes": 11200,
            "resp_pkts": 100,
            "resp_ip_bytes": 128000,
            "tunnel_parents": [],
        },
        {
            "ts": 1700000010.0,
            "uid": "CdhXbc2WnVWrx1hLX3",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 50000,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "duration": 0.05,
            "orig_bytes": 60,
            "resp_bytes": 200,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "Dd",
            "orig_pkts": 1,
            "orig_ip_bytes": 88,
            "resp_pkts": 1,
            "resp_ip_bytes": 228,
            "tunnel_parents": [],
        },
    ]


@pytest.fixture
def suricata_eve_icedid() -> List[dict]:
    """Sample Suricata EVE JSON records with IcedID-related alerts."""
    return [
        {
            "timestamp": "2023-11-14T18:13:20.000000+0000",
            "flow_id": 123456789,
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "src_port": 49152,
            "dest_ip": "185.70.40.20",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2034636,
                "rev": 1,
                "signature": "ET MALWARE IcedID Request Cookie",
                "category": "A Network Trojan was Detected",
                "severity": 1,
            },
        },
        {
            "timestamp": "2023-11-14T18:13:25.000000+0000",
            "flow_id": 123456790,
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "src_port": 49153,
            "dest_ip": "185.70.40.20",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2034637,
                "rev": 2,
                "signature": "ET MALWARE IcedID Backend CnC Activity",
                "category": "A Network Trojan was Detected",
                "severity": 1,
            },
        },
    ]


@pytest.fixture
def expected_llm_output_icedid() -> LLMOutput:
    """Pre-recorded 'correct' LLM output for the IcedID sample."""
    return LLMOutput(
        classification="IcedID",
        overall_severity="critical",
        attack_chain=[
            AttackChainItem(
                stage="Initial Access",
                description="IcedID dropper delivered via phishing email",
                evidence=["Outbound TLS to 185.70.40.20:443"],
                mitre_techniques=[
                    MitreTechnique(id="T1566", name="Phishing"),
                ],
            ),
            AttackChainItem(
                stage="Command and Control",
                description="IcedID C2 beacon over HTTPS with cookie-based signaling",
                evidence=[
                    "Periodic TLS connections to 185.70.40.20:443",
                    "Suricata alert: ET MALWARE IcedID Request Cookie",
                ],
                mitre_techniques=[
                    MitreTechnique(id="T1071.001", name="Application Layer Protocol: Web Protocols"),
                    MitreTechnique(id="T1573.002", name="Encrypted Channel: Asymmetric Cryptography"),
                ],
            ),
        ],
        host_findings=[
            HostFindingLLM(
                ip="192.168.1.100",
                role_in_attack="victim",
                summary="Compromised workstation communicating with IcedID C2",
                suspicious_behaviors=[
                    "Beaconing to 185.70.40.20:443 every ~5 minutes",
                    "High volume TLS traffic to known malicious IP",
                ],
            ),
        ],
        anomalies=[],
        mitre_techniques_overall=[
            MitreTechnique(id="T1566", name="Phishing"),
            MitreTechnique(id="T1071.001", name="Application Layer Protocol: Web Protocols"),
            MitreTechnique(id="T1573.002", name="Encrypted Channel: Asymmetric Cryptography"),
        ],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParsingPipeline:
    """Test the parse stage of the pipeline against gold data."""

    def test_zeek_parsing_produces_flows(self, zeek_conn_icedid: List[dict]):
        """Zeek conn.log records parse into FlowRecord objects."""
        flows = parse_zeek_conn(zeek_conn_icedid)
        assert len(flows) == 3

        # First flow should be the C2 connection
        c2_flow = flows[0]
        assert c2_flow.src_ip == "192.168.1.100"
        assert c2_flow.dst_ip == "185.70.40.20"
        assert c2_flow.dst_port == 443
        assert c2_flow.transport_proto.lower() == "tcp"

    def test_suricata_parsing_produces_alerts(self, suricata_eve_icedid: List[dict]):
        """Suricata EVE records parse into AlertRecord objects."""
        alerts = parse_suricata_eve(suricata_eve_icedid)
        assert len(alerts) == 2

        # Both alerts should be high severity (Suricata severity 1 = high)
        for alert in alerts:
            assert alert.severity == "high"
            assert "IcedID" in alert.signature_name


class TestAggregationPipeline:
    """Test the aggregation stage produces correct host summaries."""

    def test_aggregate_hosts_from_flows(self, zeek_conn_icedid: List[dict]):
        """Host aggregation identifies the source host."""
        flows = parse_zeek_conn(zeek_conn_icedid)
        alerts = []  # No alerts for this test
        host_summaries = aggregate_hosts(flows, alerts)

        # Should have at least our victim host
        host_ips = [h.host_ip for h in host_summaries]
        assert "192.168.1.100" in host_ips

    def test_aggregate_with_alerts(
        self, zeek_conn_icedid: List[dict], suricata_eve_icedid: List[dict]
    ):
        """Host aggregation includes alert counts."""
        flows = parse_zeek_conn(zeek_conn_icedid)
        alerts = parse_suricata_eve(suricata_eve_icedid)
        host_summaries = aggregate_hosts(flows, alerts)

        victim = next((h for h in host_summaries if h.host_ip == "192.168.1.100"), None)
        assert victim is not None
        assert victim.alerts_count >= 2


class TestForensicDataIR:
    """Test building ForensicData IR from parsed pipeline outputs."""

    def test_build_forensic_data(
        self, zeek_conn_icedid: List[dict], suricata_eve_icedid: List[dict]
    ):
        """ForensicData can be built from parsed pipeline outputs."""
        flows = parse_zeek_conn(zeek_conn_icedid)
        alerts = parse_suricata_eve(suricata_eve_icedid)
        host_summaries = aggregate_hosts(flows, alerts)
        hostpair_summaries = aggregate_host_pairs(flows, alerts)

        data = ForensicData(
            job_id="gold-001",
            exercise_id="icedid_sample",
            mode="single_window",
            flows=flows,
            alerts=alerts,
            host_summaries_exploit=host_summaries,
            hostpair_summaries_exploit=hostpair_summaries,
        )

        assert data.job_id == "gold-001"
        assert len(data.flows) == 3
        assert len(data.alerts) == 2
        assert len(data.host_summaries_exploit) > 0

    def test_forensic_data_serialization(
        self, zeek_conn_icedid: List[dict], suricata_eve_icedid: List[dict]
    ):
        """ForensicData roundtrips through JSON serialization."""
        flows = parse_zeek_conn(zeek_conn_icedid)
        alerts = parse_suricata_eve(suricata_eve_icedid)

        data = ForensicData(
            job_id="gold-002",
            exercise_id="icedid_sample",
            mode="single_window",
            flows=flows,
            alerts=alerts,
        )

        dumped = data.model_dump(mode="json")
        restored = ForensicData.model_validate(dumped)
        assert restored.job_id == "gold-002"
        assert len(restored.flows) == 3
        assert len(restored.alerts) == 2


class TestFindingConversion:
    """Test LLMOutput → Finding conversion with gold-standard expected outputs."""

    def test_icedid_findings_count(self, expected_llm_output_icedid: LLMOutput):
        """IcedID sample produces expected number of findings."""
        findings = llm_output_to_findings(
            "gold-001", expected_llm_output_icedid
        )
        # 2 attack chain stages: 1 technique + 2 techniques = 3 findings
        assert len(findings) == 3

    def test_icedid_mitre_techniques(self, expected_llm_output_icedid: LLMOutput):
        """IcedID findings include expected MITRE techniques."""
        findings = llm_output_to_findings(
            "gold-001", expected_llm_output_icedid
        )
        technique_ids = {
            f.mitre_technique_id for f in findings if f.mitre_technique_id
        }
        assert "T1566" in technique_ids
        assert "T1071.001" in technique_ids
        assert "T1573.002" in technique_ids

    def test_icedid_classification_propagated(self, expected_llm_output_icedid: LLMOutput):
        """All findings carry the IcedID classification."""
        findings = llm_output_to_findings(
            "gold-001", expected_llm_output_icedid
        )
        for f in findings:
            assert f.classification == "IcedID"

    def test_icedid_severity(self, expected_llm_output_icedid: LLMOutput):
        """Findings reflect the critical severity."""
        findings = llm_output_to_findings(
            "gold-001", expected_llm_output_icedid
        )
        for f in findings:
            assert f.severity == FindingSeverity.CRITICAL
