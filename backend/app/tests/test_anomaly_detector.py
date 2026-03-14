"""
Unit tests for the Zero-Day Anomaly Detection Module.

Tests all detection heuristics:
- Beacon detection
- Volume anomalies (data exfiltration)
- Port scanning
- Lateral movement
- DNS beaconing
- TLS anomalies
- DNS anomalies (DGA, tunneling)
- Temporal anomalies
- Entropy anomalies
"""

from datetime import datetime, timedelta
import uuid

from app.models import FlowRecord
from app.anomaly_detector import AnomalyDetector, AnomalyFinding, AnomalyReport


def create_flow(
    src_ip: str = "10.0.1.100",
    dst_ip: str = "8.8.8.8",
    src_port: int = 50000,
    dst_port: int = 443,
    start_time: datetime = None,
    bytes_from_src: int = 1000,
    bytes_from_dst: int = 500,
    app_proto: str = "TCP",
    duration_sec: float = 1.0,
) -> FlowRecord:
    """Helper to create a FlowRecord for testing."""
    if start_time is None:
        start_time = datetime(2024, 1, 1, 12, 0, 0)
    return FlowRecord(
        id=str(uuid.uuid4()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport_proto="TCP",
        app_proto=app_proto,
        bytes_from_src=bytes_from_src,
        bytes_from_dst=bytes_from_dst,
        packets_from_src=10,
        packets_from_dst=8,
        start_time=start_time,
        end_time=start_time + timedelta(seconds=duration_sec),
        duration_sec=duration_sec,
    )


class TestBeaconDetection:
    """Tests for C2 beacon pattern detection."""

    def test_detects_periodic_beacon(self):
        """Periodic connections at regular intervals should be detected as beacons."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        flows = []
        # Create 10 connections at 60-second intervals
        for i in range(10):
            start = base_time + timedelta(seconds=i * 60)
            flows.append(create_flow(
                src_ip="10.0.1.50",
                dst_ip="185.220.101.42",
                dst_port=443,
                start_time=start,
            ))
        
        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])
        
        beacon_findings = [f for f in report.findings if f.category == "beacon"]
        assert len(beacon_findings) >= 1
        assert beacon_findings[0].severity in ("high", "critical")
        assert "185.220.101.42" in beacon_findings[0].description

    def test_no_beacon_for_random_traffic(self):
        """Non-periodic traffic should not trigger beacon detection."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        flows = []
        # Create connections at random intervals
        intervals = [5, 120, 30, 200, 15, 90, 45, 180]
        cumulative = 0
        for interval in intervals:
            cumulative += interval
            flows.append(create_flow(
                src_ip="10.0.1.50",
                dst_ip="8.8.8.8",
                dst_port=443,
                start_time=base_time + timedelta(seconds=cumulative),
            ))
        
        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])
        
        beacon_findings = [f for f in report.findings if f.category == "beacon"]
        # Should not detect this as beacon due to high variance
        assert len(beacon_findings) == 0


class TestVolumeAnomalies:
    """Tests for data exfiltration detection."""

    def test_detects_high_outbound_volume(self):
        """Large outbound data transfers should be flagged."""
        flows = [
            create_flow(
                src_ip="192.168.1.100",
                dst_ip="91.134.222.18",
                bytes_from_src=60_000_000,  # 60MB outbound
                bytes_from_dst=5000,
            )
        ]
        
        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])
        
        volume_findings = [f for f in report.findings if f.category == "volume"]
        assert len(volume_findings) >= 1
        assert "192.168.1.100" in volume_findings[0].description

    def test_no_alert_for_normal_volume(self):
        """Normal traffic volumes should not trigger alerts."""
        flows = [
            create_flow(bytes_from_src=50000, bytes_from_dst=100000)  # Normal
            for _ in range(10)
        ]
        
        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])
        
        volume_findings = [f for f in report.findings if f.category == "volume"]
        assert len(volume_findings) == 0


class TestPortScanning:
    """Tests for port scanning detection."""

    def test_detects_port_scan(self):
        """Scanning many ports on a single target should be detected."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        flows = []
        # Scan ports 20-100 on target
        for port in range(20, 100):
            flows.append(create_flow(
                src_ip="10.0.1.200",
                dst_ip="192.168.1.1",
                dst_port=port,
                start_time=base_time + timedelta(milliseconds=port * 10),
                bytes_from_src=60,
                bytes_from_dst=0,
            ))
        
        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])
        
        scan_findings = [f for f in report.findings if f.category == "port_scan"]
        assert len(scan_findings) >= 1
        assert "10.0.1.200" in scan_findings[0].description

    def test_no_scan_for_few_ports(self):
        """Connections to just a few ports should not trigger scan detection."""
        flows = [
            create_flow(dst_port=80),
            create_flow(dst_port=443),
            create_flow(dst_port=8080),
        ]

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        scan_findings = [f for f in report.findings if f.category == "port_scan"]
        assert len(scan_findings) == 0


class TestLateralMovement:
    """Tests for lateral movement detection."""

    def test_detects_lateral_movement(self):
        """Internal host connecting to many internal hosts with admin ports."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        flows = []

        # Compromised host connecting to multiple internal targets
        targets = [
            ("192.168.1.10", 445),   # SMB
            ("192.168.1.11", 3389),  # RDP
            ("192.168.1.12", 22),    # SSH
            ("192.168.1.13", 445),   # SMB
            ("192.168.1.14", 5985),  # WinRM
        ]

        for dst_ip, dst_port in targets:
            flows.append(create_flow(
                src_ip="192.168.1.50",
                dst_ip=dst_ip,
                dst_port=dst_port,
                start_time=base_time,
            ))

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        lateral_findings = [f for f in report.findings if f.category == "lateral_movement"]
        assert len(lateral_findings) >= 1
        assert lateral_findings[0].severity in ("high", "critical")

    def test_no_lateral_for_external_traffic(self):
        """External connections should not trigger lateral movement."""
        flows = [
            create_flow(
                src_ip="192.168.1.50",
                dst_ip="8.8.8.8",  # External
                dst_port=443,
            )
            for _ in range(10)
        ]

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        lateral_findings = [f for f in report.findings if f.category == "lateral_movement"]
        assert len(lateral_findings) == 0


class TestDNSBeaconing:
    """Tests for DNS beaconing detection."""

    def test_detects_dns_beacon(self):
        """Periodic DNS queries should be detected as beaconing."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        dns_queries = []

        # 15 DNS queries at 30-second intervals
        for i in range(15):
            dns_queries.append({
                "query": f"beacon{i}.malware-c2.com",
                "src_ip": "10.0.1.55",
                "timestamp": (base_time + timedelta(seconds=i * 30)).timestamp(),
            })

        detector = AnomalyDetector()
        report = detector.analyze(flows=[], alerts=[], dns_queries=dns_queries)

        dns_beacon_findings = [f for f in report.findings if f.category == "dns_beacon"]
        assert len(dns_beacon_findings) >= 1
        assert "malware-c2.com" in dns_beacon_findings[0].description

    def test_no_dns_beacon_for_random_queries(self):
        """Non-periodic DNS queries should not trigger beacon detection."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        dns_queries = []

        # Random query times
        intervals = [2, 45, 120, 5, 200, 10, 300]
        cumulative = 0
        for i, interval in enumerate(intervals):
            cumulative += interval
            dns_queries.append({
                "query": f"host{i}.example.com",
                "src_ip": "10.0.1.55",
                "timestamp": (base_time + timedelta(seconds=cumulative)).timestamp(),
            })

        detector = AnomalyDetector()
        report = detector.analyze(flows=[], alerts=[], dns_queries=dns_queries)

        dns_beacon_findings = [f for f in report.findings if f.category == "dns_beacon"]
        assert len(dns_beacon_findings) == 0


class TestTLSAnomalies:
    """Tests for TLS anomaly detection."""

    def test_detects_tls_nonstandard_port(self):
        """TLS on non-standard ports should be detected."""
        flows = [
            create_flow(
                dst_ip="45.33.32.156",
                dst_port=4443,  # Non-standard
                app_proto="TLS",
            )
            for _ in range(5)
        ]

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        tls_findings = [f for f in report.findings if f.category == "tls_anomaly"]
        assert len(tls_findings) >= 1

    def test_detects_suspicious_tls_high_port_small_payload(self):
        """TLS to high ports with small payloads should be detected."""
        flows = []
        dests = ["91.134.100.1", "185.220.101.5"]
        for dst in dests:
            flows.append(create_flow(
                dst_ip=dst,
                dst_port=9443,
                app_proto="TLS",
                bytes_from_src=200,  # Small payload
            ))

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        tls_findings = [f for f in report.findings if f.category == "tls_anomaly"]
        # Should detect suspicious pattern
        assert len(tls_findings) >= 1

    def test_no_tls_anomaly_for_standard_https(self):
        """Standard HTTPS on port 443 should not be flagged."""
        flows = [
            create_flow(
                dst_ip="142.250.185.46",  # google.com
                dst_port=443,
                app_proto="HTTPS",
                bytes_from_src=5000,
            )
            for _ in range(10)
        ]

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        tls_findings = [f for f in report.findings if f.category == "tls_anomaly"]
        assert len(tls_findings) == 0


class TestDNSAnomalies:
    """Tests for DNS anomaly detection (DGA, tunneling)."""

    def test_detects_long_dns_queries(self):
        """Long DNS queries indicating tunneling should be detected."""
        dns_queries = [
            {
                "query": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBlbmNvZGVkIG1lc3NhZ2U.tunnel.malware.com",
                "src_ip": "10.0.1.100",
                "timestamp": datetime(2024, 1, 1, 12, 0, 0).timestamp(),
            }
            for _ in range(5)
        ]

        detector = AnomalyDetector()
        report = detector.analyze(flows=[], alerts=[], dns_queries=dns_queries)

        dns_findings = [f for f in report.findings if f.category == "dns"]
        assert len(dns_findings) >= 1
        assert "tunneling" in dns_findings[0].description.lower()

    def test_detects_high_subdomain_diversity(self):
        """Many unique subdomains (DGA indicator) should be detected."""
        dns_queries = []
        for i in range(60):  # 60 unique subdomains
            dns_queries.append({
                "query": f"x{i}abc{i*2}def.suspicious-domain.com",
                "src_ip": "10.0.1.100",
                "timestamp": datetime(2024, 1, 1, 12, 0, i).timestamp(),
            })

        detector = AnomalyDetector()
        report = detector.analyze(flows=[], alerts=[], dns_queries=dns_queries)

        dns_findings = [f for f in report.findings if f.category == "dns"]
        assert len(dns_findings) >= 1
        assert "dga" in dns_findings[0].description.lower()


class TestAnomalyReport:
    """Tests for the anomaly report and scoring."""

    def test_report_structure(self):
        """Verify report structure is correct."""
        detector = AnomalyDetector()
        report = detector.analyze(flows=[], alerts=[])

        assert isinstance(report, AnomalyReport)
        assert hasattr(report, "findings")
        assert hasattr(report, "overall_anomaly_score")
        assert hasattr(report, "zero_day_likelihood")
        assert hasattr(report, "summary")

    def test_empty_flows_no_findings(self):
        """Empty input should produce no findings."""
        detector = AnomalyDetector()
        report = detector.analyze(flows=[], alerts=[])

        assert len(report.findings) == 0
        assert report.overall_anomaly_score == 0.0
        assert report.zero_day_likelihood == "none"

    def test_high_score_for_multiple_findings(self):
        """Multiple high-severity findings should increase overall score."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        flows = []

        # Create beacon pattern
        for i in range(10):
            flows.append(create_flow(
                src_ip="10.0.1.50",
                dst_ip="185.220.101.42",
                dst_port=443,
                start_time=base_time + timedelta(seconds=i * 60),
            ))

        # Add volume anomaly
        flows.append(create_flow(
            src_ip="192.168.1.100",
            dst_ip="91.134.222.18",
            bytes_from_src=60_000_000,
        ))

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        assert report.overall_anomaly_score > 0.5
        assert report.zero_day_likelihood in ("medium", "high")

    def test_finding_to_dict(self):
        """Verify AnomalyFinding serialization."""
        finding = AnomalyFinding(
            category="beacon",
            severity="high",
            description="Test beacon",
            evidence=["Evidence 1", "Evidence 2"],
            affected_hosts=["10.0.1.50"],
            confidence=0.8,
            chain_of_thought="Test analysis",
        )

        data = finding.to_dict()
        assert data["category"] == "beacon"
        assert data["severity"] == "high"
        assert len(data["evidence"]) == 2
        assert data["confidence"] == 0.8


class TestChainOfThought:
    """Tests to verify chain-of-thought forensic reasoning is generated."""

    def test_beacon_has_chain_of_thought(self):
        """Beacon detection should include forensic reasoning."""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        flows = [
            create_flow(
                src_ip="10.0.1.50",
                dst_ip="185.220.101.42",
                dst_port=443,
                start_time=base_time + timedelta(seconds=i * 60),
            )
            for i in range(10)
        ]

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        beacon_findings = [f for f in report.findings if f.category == "beacon"]
        assert len(beacon_findings) >= 1
        assert beacon_findings[0].chain_of_thought
        assert "FORENSIC ANALYSIS" in beacon_findings[0].chain_of_thought
        assert "WHY THIS IS SUSPICIOUS" in beacon_findings[0].chain_of_thought

    def test_lateral_movement_has_recommendations(self):
        """Lateral movement detection should include recommended actions."""
        flows = []
        targets = [
            ("192.168.1.10", 445),
            ("192.168.1.11", 3389),
            ("192.168.1.12", 22),
            ("192.168.1.13", 445),
            ("192.168.1.14", 5985),
        ]

        for dst_ip, dst_port in targets:
            flows.append(create_flow(
                src_ip="192.168.1.50",
                dst_ip=dst_ip,
                dst_port=dst_port,
            ))

        detector = AnomalyDetector()
        report = detector.analyze(flows=flows, alerts=[])

        lateral_findings = [f for f in report.findings if f.category == "lateral_movement"]
        assert len(lateral_findings) >= 1
        cot = lateral_findings[0].chain_of_thought
        assert "RECOMMENDED ACTIONS" in cot
        assert "Isolate" in cot or "isolate" in cot

