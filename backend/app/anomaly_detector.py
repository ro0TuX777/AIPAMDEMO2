"""
Zero-Day Anomaly Detection Module

Heuristic-based detection for unknown threats that don't match known signatures.
Provides behavioral anomaly scoring that feeds into LLM analysis for forensic reasoning.

Detection Categories:
1. Beacon Detection - Periodic C2 communication patterns
2. Entropy Analysis - Encrypted/encoded payload detection
3. Protocol Deviation - Non-RFC compliant behavior
4. Temporal Anomalies - Unusual timing patterns
5. Volume Anomalies - Data exfiltration indicators
6. DNS Anomalies - DGA, tunneling, fast-flux
7. Connection Patterns - Unusual port/protocol combinations
8. Port Scanning - Reconnaissance and service enumeration
9. Lateral Movement - Internal host-to-host propagation
10. DNS Beaconing - Periodic DNS queries for covert C2
11. TLS Anomalies - Non-standard TLS usage, suspicious certificates
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .models import FlowRecord, AlertRecord


@dataclass
class AnomalyFinding:
    """A single anomaly finding with forensic context."""
    category: str  # beacon, entropy, protocol, temporal, volume, dns, connection
    severity: str  # low, medium, high, critical
    description: str
    evidence: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    chain_of_thought: str = ""  # Forensic reasoning for LLM context
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "affected_hosts": self.affected_hosts,
            "confidence": self.confidence,
            "chain_of_thought": self.chain_of_thought,
        }


@dataclass 
class AnomalyReport:
    """Complete anomaly analysis report."""
    findings: List[AnomalyFinding] = field(default_factory=list)
    overall_anomaly_score: float = 0.0  # 0.0 to 1.0
    zero_day_likelihood: str = "none"  # none, low, medium, high
    summary: str = ""
    interaction_graph: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "overall_anomaly_score": self.overall_anomaly_score,
            "zero_day_likelihood": self.zero_day_likelihood,
            "summary": self.summary,
            "interaction_graph": self.interaction_graph,
        }


class AnomalyDetector:
    """
    Heuristic-based anomaly detector for zero-day threat identification.
    
    Uses statistical analysis and behavioral heuristics to identify
    traffic patterns that don't match known signatures but exhibit
    suspicious characteristics.
    """
    
    # Thresholds for detection (can be tuned)
    BEACON_JITTER_THRESHOLD = 0.15  # 15% variance indicates periodic beacon
    ENTROPY_HIGH_THRESHOLD = 7.5    # High entropy (encrypted/compressed)
    ENTROPY_SUSPICIOUS_THRESHOLD = 6.5
    MIN_FLOWS_FOR_BEACON = 5        # Minimum flows to detect beacon
    EXFIL_BYTES_THRESHOLD = 10_000_000  # 10MB outbound is suspicious
    DNS_QUERY_LENGTH_SUSPICIOUS = 50    # Long DNS queries may indicate tunneling
    
    def __init__(self):
        self.findings: List[AnomalyFinding] = []
        
    def analyze(
        self,
        flows: List[FlowRecord],
        alerts: List[AlertRecord],
        dns_queries: Optional[List[Dict[str, Any]]] = None,
        payload_samples: Optional[List[bytes]] = None,
    ) -> AnomalyReport:
        """
        Run all anomaly detection heuristics on the provided data.
        
        Args:
            flows: Network flow records
            alerts: Existing alert records (to correlate with)
            dns_queries: Optional DNS query data
            payload_samples: Optional raw payload samples for entropy analysis
            
        Returns:
            AnomalyReport with all findings and overall assessment
        """
        self.findings = []
        
        graph_data = {}
        if flows:
            self._detect_beacon_patterns(flows)
            self._detect_volume_anomalies(flows)
            self._detect_connection_anomalies(flows)
            self._detect_port_scanning(flows)
            self._detect_lateral_movement(flows)
            self._detect_temporal_anomalies(flows)
            self._detect_tls_anomalies(flows)
            graph_data = self._detect_graph_anomalies(flows)

        if dns_queries:
            self._detect_dns_anomalies(dns_queries)
            self._detect_dns_beaconing(dns_queries)

        if payload_samples:
            self._detect_entropy_anomalies(payload_samples, flows)
        
        # Calculate overall score
        overall_score = self._calculate_overall_score()
        likelihood = self._assess_zero_day_likelihood(overall_score)
        summary = self._generate_summary()
        
        return AnomalyReport(
            findings=self.findings,
            overall_anomaly_score=overall_score,
            zero_day_likelihood=likelihood,
            summary=summary,
            interaction_graph=graph_data,
        )
    
    def _detect_graph_anomalies(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Generate a topological summary of the network interaction graph.
        Identifies Hubs (fan-out), Authorities (fan-in), and Pivot points.
        """
        src_to_dsts = defaultdict(set)
        dst_to_srcs = defaultdict(set)
        
        for flow in flows:
            src_to_dsts[flow.src_ip].add(flow.dst_ip)
            dst_to_srcs[flow.dst_ip].add(flow.src_ip)
            
        hubs = {ip: len(dsts) for ip, dsts in src_to_dsts.items() if len(dsts) > 5}
        authorities = {ip: len(srcs) for ip, srcs in dst_to_srcs.items() if len(srcs) > 5}
        
        # Pivots: Hosts that act as both a significant target (Authority) and a source (Hub)
        pivots = set(hubs.keys()) & set(authorities.keys())
        
        summary_parts = []
        if hubs:
            summary_parts.append(f"Identified {len(hubs)} Hubs (Source IPs with >5 targets)")
        if authorities:
            summary_parts.append(f"Identified {len(authorities)} Authorities (Target IPs with >5 sources)")
        if pivots:
            summary_parts.append(f"CRITICAL: {len(pivots)} hosts identified as PIVOTS (targets becoming sources): {list(pivots)}")
            
        return {
            "hubs": hubs,
            "authorities": authorities,
            "pivots": list(pivots),
            "summary": " | ".join(summary_parts) if summary_parts else "Simple point-to-point topology detected."
        }

    def _detect_beacon_patterns(self, flows: List[FlowRecord]) -> None:
        """
        Detect periodic C2 beacon patterns.
        
        C2 beacons typically exhibit:
        - Regular intervals between connections
        - Similar packet sizes
        - Consistent destination
        - Low jitter (< 15-20%)
        """
        # Group flows by src_ip -> dst_ip:dst_port
        connections: Dict[str, List[FlowRecord]] = defaultdict(list)
        for flow in flows:
            key = f"{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}"
            connections[key].append(flow)
        
        for conn_key, conn_flows in connections.items():
            if len(conn_flows) < self.MIN_FLOWS_FOR_BEACON:
                continue
                
            # Sort by time and calculate intervals
            sorted_flows = sorted(conn_flows, key=lambda f: f.start_time)
            intervals = []
            for i in range(1, len(sorted_flows)):
                delta = (sorted_flows[i].start_time - sorted_flows[i-1].start_time).total_seconds()
                if delta > 0:
                    intervals.append(delta)
            
            if len(intervals) < 3:
                continue

            # Calculate jitter (coefficient of variation)
            mean_interval = statistics.mean(intervals)
            if mean_interval > 0:
                try:
                    stdev = statistics.stdev(intervals)
                    jitter = stdev / mean_interval  # CV = coefficient of variation
                except statistics.StatisticsError:
                    continue

                # Low jitter + regular interval = beacon
                if jitter < self.BEACON_JITTER_THRESHOLD and mean_interval < 3600:  # < 1hr interval
                    src_ip = sorted_flows[0].src_ip
                    dst = f"{sorted_flows[0].dst_ip}:{sorted_flows[0].dst_port}"

                    # Check packet size consistency
                    sizes = [f.bytes_from_src for f in sorted_flows]
                    size_cv = statistics.stdev(sizes) / statistics.mean(sizes) if statistics.mean(sizes) > 0 else 1

                    confidence = 0.7 if jitter < 0.1 else 0.5
                    if size_cv < 0.2:  # Consistent packet sizes
                        confidence += 0.2

                    severity = "high" if confidence > 0.8 else "medium"

                    self.findings.append(AnomalyFinding(
                        category="beacon",
                        severity=severity,
                        description=f"Periodic beacon pattern detected: {conn_key}",
                        evidence=[
                            f"Connection count: {len(sorted_flows)}",
                            f"Mean interval: {mean_interval:.1f}s",
                            f"Jitter (CV): {jitter:.2%}",
                            f"Packet size variance: {size_cv:.2%}",
                        ],
                        affected_hosts=[src_ip],
                        confidence=confidence,
                        chain_of_thought=f"""FORENSIC ANALYSIS - Potential C2 Beacon:
I've detected a suspicious periodic communication pattern that warrants investigation.

OBSERVATION: Host {src_ip} is making regular connections to {dst}
- {len(sorted_flows)} connections over the analysis period
- Average interval: {mean_interval:.1f} seconds between connections
- Very low timing variance (jitter): {jitter:.2%} - this is unusually consistent
- Packet sizes are {'highly consistent' if size_cv < 0.2 else 'somewhat variable'}

WHY THIS IS SUSPICIOUS:
Normal user traffic has high variance in timing (browsing, clicking, etc.)
This pattern shows machine-like precision typical of:
1. Command & Control (C2) beacons checking in with a controller
2. Heartbeat mechanisms in malware maintaining persistence
3. Data exfiltration on a schedule

RECOMMENDED ACTIONS:
1. Check if {dst} is a known legitimate service
2. Examine the payload content for these connections
3. Review what process on {src_ip} is initiating these connections
4. Check for similar patterns to other destinations from this host

This is a potential ZERO-DAY indicator if the destination is not a known threat."""
                    ))

    def _detect_volume_anomalies(self, flows: List[FlowRecord]) -> None:
        """Detect potential data exfiltration based on volume patterns."""
        # Aggregate outbound bytes per source IP
        outbound_by_host: Dict[str, int] = defaultdict(int)
        dest_diversity: Dict[str, set] = defaultdict(set)

        for flow in flows:
            outbound_by_host[flow.src_ip] += flow.bytes_from_src
            dest_diversity[flow.src_ip].add(flow.dst_ip)

        for host, total_bytes in outbound_by_host.items():
            if total_bytes > self.EXFIL_BYTES_THRESHOLD:
                num_dests = len(dest_diversity[host])

                # High volume to few destinations is more suspicious
                confidence = 0.6 if num_dests < 5 else 0.4
                severity = "high" if total_bytes > 50_000_000 else "medium"

                self.findings.append(AnomalyFinding(
                    category="volume",
                    severity=severity,
                    description=f"High outbound data volume from {host}",
                    evidence=[
                        f"Total outbound: {total_bytes / 1_000_000:.2f} MB",
                        f"Unique destinations: {num_dests}",
                        f"Average per destination: {total_bytes / max(num_dests, 1) / 1_000_000:.2f} MB",
                    ],
                    affected_hosts=[host],
                    confidence=confidence,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Potential Data Exfiltration:
Detected unusually high outbound data transfer that could indicate exfiltration.

OBSERVATION: Host {host} sent {total_bytes / 1_000_000:.2f} MB of data
- Data went to {num_dests} unique destination(s)
- {'Concentrated to few destinations - MORE SUSPICIOUS' if num_dests < 5 else 'Distributed across many destinations'}

WHY THIS IS SUSPICIOUS:
Large outbound transfers could indicate:
1. Data exfiltration to attacker-controlled infrastructure
2. Database or file server being drained
3. Staging data for later pickup

CONTEXT NEEDED:
- Is this host normally a high-bandwidth server?
- What is the baseline outbound volume for this host?
- Are the destinations legitimate cloud services or unknown IPs?

If this exceeds normal baseline by >200%, treat as HIGH priority."""
                ))

    def _detect_connection_anomalies(self, flows: List[FlowRecord]) -> None:
        """Detect unusual port/protocol combinations and connection patterns."""
        # Track unusual ports and failed connections
        high_ports: Dict[str, List[int]] = defaultdict(list)
        failed_connections: Dict[str, int] = defaultdict(int)

        for flow in flows:
            # High ephemeral ports as destination (unusual for servers)
            if flow.dst_port > 49152:
                high_ports[flow.dst_ip].append(flow.dst_port)

            # Track connection states indicating failures/resets
            if flow.state and any(s in flow.state.lower() for s in ['reset', 'refused', 'timeout']):
                failed_connections[flow.src_ip] += 1

        # Alert on hosts with many high-port connections (potential reverse shells)
        for dst_ip, ports in high_ports.items():
            if len(ports) > 10:
                unique_ports = len(set(ports))
                self.findings.append(AnomalyFinding(
                    category="connection",
                    severity="medium",
                    description=f"Unusual high-port connections to {dst_ip}",
                    evidence=[
                        f"High port connections: {len(ports)}",
                        f"Unique high ports: {unique_ports}",
                    ],
                    affected_hosts=[dst_ip],
                    confidence=0.5,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Unusual Port Usage:
Detected connections to high ephemeral ports that may indicate reverse shells or backdoors.

OBSERVATION: {dst_ip} received {len(ports)} connections on high ports (>49152)
- {unique_ports} unique ports used

WHY THIS IS SUSPICIOUS:
- Legitimate servers typically listen on well-known ports (<1024) or registered ports (1024-49151)
- High ephemeral ports are normally used for client-side connections
- Reverse shells and backdoors often use high random ports to evade detection

RECOMMENDED ACTIONS:
1. Identify what service is listening on these ports
2. Check if this is a legitimate P2P application
3. Examine the process binding to these ports"""
                ))

        # Alert on hosts with many failed connections (scanning/probing)
        for src_ip, fail_count in failed_connections.items():
            if fail_count > 20:
                self.findings.append(AnomalyFinding(
                    category="connection",
                    severity="medium",
                    description=f"Many failed connections from {src_ip}",
                    evidence=[
                        f"Failed/reset connections: {fail_count}",
                    ],
                    affected_hosts=[src_ip],
                    confidence=0.6,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Connection Failures:
High number of failed connections may indicate scanning or lateral movement attempts.

OBSERVATION: {src_ip} had {fail_count} failed/reset connections

WHY THIS IS SUSPICIOUS:
- Port scanning generates many refused connections
- Lateral movement attempts often fail before finding open services
- Brute force attacks cause connection resets

RECOMMENDED ACTIONS:
1. Check destination IPs/ports for these failures
2. Look for successful connections after the failures (breakthrough)
3. Correlate with authentication logs"""
                ))

    def _detect_port_scanning(self, flows: List[FlowRecord]) -> None:
        """Detect port scanning behavior (single source hitting many ports on target)."""
        if not flows:
            return

        # Track: source -> destination -> set of ports
        port_scan_matrix: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

        for flow in flows:
            port_scan_matrix[flow.src_ip][flow.dst_ip].add(flow.dst_port)

        # Detect scanners: source hitting many ports on one or more targets
        for src_ip, targets in port_scan_matrix.items():
            total_unique_ports = sum(len(ports) for ports in targets.values())

            for dst_ip, ports in targets.items():
                if len(ports) >= 15:  # 15+ different ports on same target = likely scan
                    port_list = sorted(ports)[:20]

                    # Check if it's sequential scanning (more suspicious)
                    sequential = 0
                    for i in range(1, len(port_list)):
                        if port_list[i] - port_list[i-1] <= 2:
                            sequential += 1

                    is_sequential = sequential > len(port_list) * 0.3
                    severity = "high" if len(ports) >= 50 or is_sequential else "medium"

                    self.findings.append(AnomalyFinding(
                        category="port_scan",
                        severity=severity,
                        description=f"Port scanning detected: {src_ip} -> {dst_ip}",
                        evidence=[
                            f"Unique ports scanned: {len(ports)}",
                            f"Sample ports: {port_list[:10]}",
                            f"Sequential scan pattern: {'YES' if is_sequential else 'NO'}",
                            f"Total unique ports from this source: {total_unique_ports}",
                        ],
                        affected_hosts=[src_ip, dst_ip],
                        confidence=0.8 if len(ports) >= 30 else 0.6,
                        chain_of_thought=f"""FORENSIC ANALYSIS - Port Scanning Activity:
Detected systematic port enumeration indicative of reconnaissance.

OBSERVATION: {src_ip} connected to {len(ports)} different ports on {dst_ip}
- Sample ports: {port_list[:15]}
- {'Sequential scanning detected - indicates automated scanner' if is_sequential else 'Random port selection - may be targeted or tool-based'}

WHY THIS IS SUSPICIOUS:
Port scanning is a classic reconnaissance technique used to:
1. Identify running services on target hosts
2. Find vulnerable or misconfigured services
3. Map network topology before exploitation

ATTACK PROGRESSION:
Scanning → Service enumeration → Vulnerability identification → Exploitation

RECOMMENDED ACTIONS:
1. Block source IP if external
2. Investigate if this is an authorized pentest
3. Check for exploitation attempts following the scan
4. Review firewall logs for additional scanning activity"""
                    ))

    def _detect_lateral_movement(self, flows: List[FlowRecord]) -> None:
        """Detect lateral movement patterns (internal host connecting to many internal hosts)."""
        if not flows:
            return

        # Define internal IP ranges (RFC 1918)
        def is_internal(ip: str) -> bool:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            try:
                first = int(parts[0])
                second = int(parts[1])
                if first == 10:  # 10.0.0.0/8
                    return True
                if first == 172 and 16 <= second <= 31:  # 172.16.0.0/12
                    return True
                if first == 192 and second == 168:  # 192.168.0.0/16
                    return True
            except ValueError:
                pass
            return False

        # Track internal-to-internal connections
        internal_connections: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        internal_ports: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

        for flow in flows:
            if is_internal(flow.src_ip) and is_internal(flow.dst_ip):
                if flow.src_ip != flow.dst_ip:  # Exclude self-connections
                    internal_connections[flow.src_ip][flow.dst_ip] += 1
                    internal_ports[flow.src_ip][flow.dst_ip].add(flow.dst_port)

        # Detect lateral movement: internal host connecting to many other internal hosts
        for src_ip, targets in internal_connections.items():
            if len(targets) >= 5:  # Connecting to 5+ different internal hosts
                total_connections = sum(targets.values())
                admin_ports_hit = set()
                suspicious_services = []

                for dst_ip, ports in internal_ports[src_ip].items():
                    # Check for administrative/sensitive ports
                    admin_ports = {22, 23, 135, 139, 445, 3389, 5985, 5986}  # SSH, Telnet, SMB, RDP, WinRM
                    hit_admin = ports & admin_ports
                    if hit_admin:
                        admin_ports_hit.update(hit_admin)
                        suspicious_services.extend([f"{dst_ip}:{p}" for p in hit_admin])

                # Calculate suspiciousness
                severity = "critical" if len(targets) >= 10 or admin_ports_hit else "high"
                confidence = 0.85 if admin_ports_hit else 0.65

                self.findings.append(AnomalyFinding(
                    category="lateral_movement",
                    severity=severity,
                    description=f"Potential lateral movement from {src_ip}",
                    evidence=[
                        f"Internal targets contacted: {len(targets)}",
                        f"Total internal connections: {total_connections}",
                        f"Administrative ports accessed: {list(admin_ports_hit)}" if admin_ports_hit else "No admin ports detected",
                        f"Suspicious connections: {suspicious_services[:10]}" if suspicious_services else "No high-risk services targeted",
                    ],
                    affected_hosts=[src_ip] + list(targets.keys())[:10],
                    confidence=confidence,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Lateral Movement Indicators:
Detected internal host making connections to multiple other internal systems.

OBSERVATION: {src_ip} connected to {len(targets)} different internal hosts
- Total connections: {total_connections}
- {'CRITICAL: Administrative ports accessed including ' + str(list(admin_ports_hit)) if admin_ports_hit else 'No administrative ports detected'}

WHY THIS IS SUSPICIOUS:
Lateral movement is a key phase of advanced attacks:
1. Attackers move from initial foothold to higher-value targets
2. Multiple internal connections from one host is abnormal for most workstations
3. Access to admin ports (SMB, RDP, WinRM) suggests credential theft/reuse

ATTACK PROGRESSION:
Initial Access → Privilege Escalation → Lateral Movement → Data Access

{f"⚠️ HIGH ALERT: Access to ports {list(admin_ports_hit)} indicates active exploitation of:" if admin_ports_hit else ""}
{f"- Port 445 (SMB): Credential harvesting, ransomware spread" if 445 in admin_ports_hit else ""}
{f"- Port 3389 (RDP): Remote desktop hijacking" if 3389 in admin_ports_hit else ""}
{f"- Port 22 (SSH): SSH key theft or brute force" if 22 in admin_ports_hit else ""}
{f"- Port 5985/5986 (WinRM): PowerShell remoting abuse" if (5985 in admin_ports_hit or 5986 in admin_ports_hit) else ""}

RECOMMENDED ACTIONS:
1. Isolate {src_ip} for forensic analysis
2. Check for stolen credentials (hash pass-the-hash, Kerberos tickets)
3. Review authentication logs on all target hosts
4. Search for persistence mechanisms on compromised systems"""
                ))

    def _detect_temporal_anomalies(self, flows: List[FlowRecord]) -> None:
        """Detect unusual timing patterns (off-hours activity, bursts)."""
        if not flows:
            return

        # Group flows by hour
        hour_counts: Counter = Counter()
        for flow in flows:
            hour_counts[flow.start_time.hour] += 1

        total_flows = sum(hour_counts.values())
        if total_flows < 100:
            return  # Not enough data

        # Check for off-hours concentration (11 PM - 5 AM)
        off_hours = sum(hour_counts.get(h, 0) for h in [23, 0, 1, 2, 3, 4, 5])
        off_hours_pct = off_hours / total_flows

        if off_hours_pct > 0.4:  # >40% traffic in off-hours
            peak_hour = max(hour_counts.items(), key=lambda x: x[1])
            self.findings.append(AnomalyFinding(
                category="temporal",
                severity="medium",
                description="Significant off-hours network activity detected",
                evidence=[
                    f"Off-hours traffic: {off_hours_pct:.1%}",
                    f"Peak hour: {peak_hour[0]:02d}:00 ({peak_hour[1]} flows)",
                    f"Total flows analyzed: {total_flows}",
                ],
                affected_hosts=[],
                confidence=0.5,
                chain_of_thought=f"""FORENSIC ANALYSIS - Off-Hours Activity:
Detected unusual concentration of network activity during non-business hours.

OBSERVATION: {off_hours_pct:.1%} of traffic occurred between 11 PM - 5 AM
- Peak activity at {peak_hour[0]:02d}:00 with {peak_hour[1]} flows

WHY THIS IS SUSPICIOUS:
- Malware often operates during off-hours to avoid detection
- Data exfiltration frequently occurs overnight
- C2 activity may be timed to attacker's timezone

CONTEXT NEEDED:
- Is this environment expected to have 24/7 activity?
- Are there scheduled backup jobs at night?
- What hosts are generating this off-hours traffic?"""
            ))

    def _detect_dns_anomalies(self, dns_queries: List[Dict[str, Any]]) -> None:
        """Detect DNS-based anomalies (DGA, tunneling, unusual queries)."""
        if not dns_queries:
            return

        long_queries = []
        subdomain_counts: Dict[str, int] = defaultdict(int)

        for query in dns_queries:
            domain = query.get("query", query.get("domain", ""))
            if not domain:
                continue

            # Long domain names may indicate tunneling
            if len(domain) > self.DNS_QUERY_LENGTH_SUSPICIOUS:
                long_queries.append(domain)

            # Count unique subdomains per base domain
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                subdomain_counts[base_domain] += 1

        # Alert on long queries (potential tunneling)
        if long_queries:
            self.findings.append(AnomalyFinding(
                category="dns",
                severity="high",
                description="Unusually long DNS queries detected (potential DNS tunneling)",
                evidence=[
                    f"Long queries found: {len(long_queries)}",
                    f"Sample: {long_queries[0][:80]}...",
                ],
                affected_hosts=[],
                confidence=0.7,
                chain_of_thought=f"""FORENSIC ANALYSIS - DNS Tunneling Indicators:
Detected unusually long DNS queries that may indicate DNS tunneling.

OBSERVATION: {len(long_queries)} DNS queries exceeded {self.DNS_QUERY_LENGTH_SUSPICIOUS} characters
- Sample query: {long_queries[0][:80]}...

WHY THIS IS SUSPICIOUS:
DNS tunneling encodes data in DNS queries to:
1. Exfiltrate data through DNS (often allowed through firewalls)
2. Establish covert C2 channels
3. Bypass content filtering

CHARACTERISTICS OF TUNNELING:
- High entropy in subdomain portion
- Long query strings
- High volume of queries to same domain

RECOMMENDED ACTIONS:
1. Decode the subdomain portion (may be base64/hex encoded data)
2. Check if the authoritative DNS server is legitimate
3. Block or monitor the suspicious domain"""
            ))

        # Alert on domains with many unique subdomains (potential DGA or tunneling)
        for base_domain, count in subdomain_counts.items():
            if count > 50:  # Many unique subdomains
                self.findings.append(AnomalyFinding(
                    category="dns",
                    severity="high",
                    description=f"High subdomain diversity for {base_domain} (potential DGA)",
                    evidence=[
                        f"Unique subdomains: {count}",
                        f"Base domain: {base_domain}",
                    ],
                    affected_hosts=[],
                    confidence=0.6,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Domain Generation Algorithm (DGA) Indicators:
Detected unusually high subdomain diversity that may indicate DGA activity.

OBSERVATION: {count} unique subdomains queried for {base_domain}

WHY THIS IS SUSPICIOUS:
Domain Generation Algorithms (DGA) are used by malware to:
1. Generate pseudo-random domain names for C2
2. Evade static domain blocklists
3. Maintain resilience if some C2 domains are taken down

COMMON DGA FAMILIES:
- Conficker, CryptoLocker, Necurs, Emotet

RECOMMENDED ACTIONS:
1. Check if subdomains follow a pattern (date-based, random-looking)
2. Verify {base_domain} reputation
3. Block the domain and hunt for infected hosts"""
                ))

    def _detect_dns_beaconing(self, dns_queries: List[Dict[str, Any]]) -> None:
        """Detect periodic DNS queries indicating C2 beaconing over DNS."""
        if not dns_queries or len(dns_queries) < 10:
            return

        # Group queries by (source_ip, domain) and track timestamps
        query_times: Dict[Tuple[str, str], List[float]] = defaultdict(list)

        for query in dns_queries:
            domain = query.get("query", query.get("domain", ""))
            src_ip = query.get("src_ip", query.get("client", "unknown"))
            timestamp = query.get("timestamp", query.get("ts"))

            if not domain or not timestamp:
                continue

            # Extract base domain (e.g., malware.com from sub.malware.com)
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
            else:
                base_domain = domain

            # Convert timestamp to float if needed
            if isinstance(timestamp, datetime):
                ts = timestamp.timestamp()
            elif isinstance(timestamp, str):
                try:
                    ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                except ValueError:
                    continue
            else:
                ts = float(timestamp)

            query_times[(src_ip, base_domain)].append(ts)

        # Analyze each (source, domain) pair for periodic patterns
        for (src_ip, domain), timestamps in query_times.items():
            if len(timestamps) < 5:  # Need at least 5 queries to detect periodicity
                continue

            timestamps = sorted(timestamps)
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

            if not intervals:
                continue

            mean_interval = statistics.mean(intervals)
            if mean_interval < 1:  # Too fast, likely burst traffic
                continue

            # Calculate coefficient of variation (lower = more periodic)
            if len(intervals) >= 2:
                stdev = statistics.stdev(intervals)
                cv = (stdev / mean_interval) * 100 if mean_interval > 0 else 100
            else:
                cv = 100  # Not enough data

            # DNS beaconing typically has very regular intervals
            if cv < 20 and mean_interval > 5:  # <20% variance, >5 second intervals
                self.findings.append(AnomalyFinding(
                    category="dns_beacon",
                    severity="high",
                    description=f"Periodic DNS beaconing detected: {src_ip} -> {domain}",
                    evidence=[
                        f"Query count: {len(timestamps)}",
                        f"Mean interval: {mean_interval:.1f}s",
                        f"Jitter (CV): {cv:.2f}%",
                        f"Duration: {timestamps[-1] - timestamps[0]:.1f}s",
                    ],
                    affected_hosts=[src_ip],
                    confidence=0.85 if cv < 10 else 0.7,
                    chain_of_thought=f"""FORENSIC ANALYSIS - DNS C2 Beaconing:
Detected periodic DNS queries that may indicate command-and-control communication.

OBSERVATION: {src_ip} is making regular DNS queries to {domain}
- {len(timestamps)} queries over {timestamps[-1] - timestamps[0]:.1f} seconds
- Average interval: {mean_interval:.1f} seconds between queries
- Very low timing variance: {cv:.2f}% - machine-like precision

WHY THIS IS SUSPICIOUS:
DNS beaconing is a covert C2 technique because:
1. DNS traffic is often allowed through firewalls
2. DNS queries can encode commands in subdomains
3. DNS responses can deliver commands/data back
4. Blends in with normal DNS resolution

MALWARE USING DNS C2:
- DNSMessenger, FrameworkPOS, Pisloader
- APT groups: APT34, OilRig, Sea Turtle

DETECTION INDICATORS:
- Regular timing intervals (machine-generated)
- Queries to low-reputation or newly registered domains
- Unusual TXT record queries (often used for data transfer)

RECOMMENDED ACTIONS:
1. Check DNS query types (TXT queries are more suspicious)
2. Inspect subdomain content for encoded data
3. Block the domain at DNS level
4. Isolate {src_ip} for investigation"""
                ))

    def _detect_tls_anomalies(self, flows: List[FlowRecord]) -> None:
        """Detect suspicious TLS patterns (unusual ports, certificate issues, cipher anomalies)."""
        if not flows:
            return

        # Track TLS on non-standard ports
        tls_nonstandard_ports: Dict[str, List[int]] = defaultdict(list)
        # Track potential self-signed cert indicators (TLS with no SNI on unusual ports)
        suspicious_tls: List[Dict[str, Any]] = []

        standard_tls_ports = {443, 8443, 993, 995, 465, 636, 989, 990, 5061}

        for flow in flows:
            app_proto = (flow.app_proto or "").lower()

            # TLS on non-standard port
            if app_proto in ("tls", "ssl", "https") or flow.dst_port == 443:
                if flow.dst_port not in standard_tls_ports:
                    tls_nonstandard_ports[flow.dst_ip].append(flow.dst_port)

                    # Additional suspicion: TLS to high port with small payload
                    if flow.dst_port > 8000 and flow.bytes_from_src < 1000:
                        suspicious_tls.append({
                            "src": flow.src_ip,
                            "dst": flow.dst_ip,
                            "port": flow.dst_port,
                            "bytes": flow.bytes_from_src,
                        })

        # Alert on TLS to non-standard ports
        for dst_ip, ports in tls_nonstandard_ports.items():
            if len(ports) >= 3:  # Multiple TLS connections to unusual ports
                unique_ports = sorted(set(ports))
                self.findings.append(AnomalyFinding(
                    category="tls_anomaly",
                    severity="medium",
                    description=f"TLS on non-standard ports to {dst_ip}",
                    evidence=[
                        f"Non-standard TLS ports: {unique_ports[:10]}",
                        f"Connection count: {len(ports)}",
                    ],
                    affected_hosts=[dst_ip],
                    confidence=0.6,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Suspicious TLS Usage:
Detected TLS/SSL on non-standard ports which may indicate C2 or tunneling.

OBSERVATION: {dst_ip} received {len(ports)} TLS connections on unusual ports
- Ports: {unique_ports[:10]}
- Standard TLS ports are: 443, 8443, 993, 995, 465

WHY THIS IS SUSPICIOUS:
- Malware often uses TLS on high ports to evade detection
- C2 frameworks (Cobalt Strike, Metasploit) default to non-443 ports
- SSL/TLS hides payload content from inspection

COMMON MALICIOUS TLS PORTS:
- 4443, 8080, 8443 - Common C2 alternates
- Random high ports - Avoid pattern detection
- Port 53 with TLS - DNS-over-TLS or masquerading

RECOMMENDED ACTIONS:
1. Verify if {dst_ip} is a legitimate server
2. Check TLS certificate validity
3. Inspect JA3/JA3S fingerprints if available
4. Correlate with threat intelligence"""
                ))

        # Alert on suspicious TLS patterns
        if suspicious_tls:
            unique_dests = set(s["dst"] for s in suspicious_tls)
            if len(unique_dests) >= 2:
                self.findings.append(AnomalyFinding(
                    category="tls_anomaly",
                    severity="high",
                    description="Suspicious TLS to high ports with small payloads",
                    evidence=[
                        f"Suspicious connections: {len(suspicious_tls)}",
                        f"Unique destinations: {len(unique_dests)}",
                        f"Sample: {suspicious_tls[0]}",
                    ],
                    affected_hosts=list(unique_dests)[:5],
                    confidence=0.7,
                    chain_of_thought=f"""FORENSIC ANALYSIS - Potential C2 TLS Pattern:
Detected TLS connections to high ports with unusually small payloads.

OBSERVATION: {len(suspicious_tls)} connections with TLS to ports >8000 and <1KB data
- This pattern is consistent with C2 check-ins or heartbeats

WHY THIS IS SUSPICIOUS:
- Normal HTTPS traffic has larger payloads (web pages, APIs)
- Small TLS payloads to high ports suggest:
  1. C2 beacon check-ins
  2. Keep-alive/heartbeat connections
  3. Encrypted command delivery

C2 FRAMEWORKS WITH THIS PATTERN:
- Cobalt Strike (small beacon payloads)
- Empire (PowerShell C2)
- Custom implants

RECOMMENDED ACTIONS:
1. Extract and analyze TLS certificates
2. Check JA3 fingerprints against threat intel
3. Correlate with beacon timing analysis
4. Block suspicious destinations at firewall"""
                ))

    def _detect_entropy_anomalies(
        self,
        payload_samples: List[bytes],
        flows: List[FlowRecord]
    ) -> None:
        """Detect high-entropy payloads indicating encryption/encoding."""
        high_entropy_count = 0
        sample_entropies = []

        for payload in payload_samples:
            if len(payload) < 16:
                continue
            entropy = self._calculate_entropy(payload)
            sample_entropies.append(entropy)
            if entropy > self.ENTROPY_HIGH_THRESHOLD:
                high_entropy_count += 1

        if not sample_entropies:
            return

        avg_entropy = statistics.mean(sample_entropies)

        if high_entropy_count > len(payload_samples) * 0.3:  # >30% high entropy
            self.findings.append(AnomalyFinding(
                category="entropy",
                severity="medium",
                description="High entropy payloads detected (potential encrypted C2)",
                evidence=[
                    f"High entropy samples: {high_entropy_count}/{len(payload_samples)}",
                    f"Average entropy: {avg_entropy:.2f} bits",
                ],
                affected_hosts=[],
                confidence=0.5,
                chain_of_thought=f"""FORENSIC ANALYSIS - Encrypted Payload Detection:
Detected payloads with high entropy suggesting encryption or encoding.

OBSERVATION: {high_entropy_count} of {len(payload_samples)} samples have entropy > {self.ENTROPY_HIGH_THRESHOLD}
- Average entropy: {avg_entropy:.2f} bits (max is 8.0)
- Random/encrypted data typically has entropy > 7.5

WHY THIS IS SUSPICIOUS:
- Normal HTTP/text has entropy ~4-5 bits
- Encrypted C2 traffic shows entropy ~7.5-8.0 bits
- Malware increasingly uses encryption to evade inspection

CAVEATS:
- HTTPS traffic is legitimately encrypted
- Compressed files also have high entropy
- Need to correlate with other indicators

RECOMMENDED ACTIONS:
1. Check if high-entropy traffic is on expected encrypted protocols (HTTPS, SSH)
2. Look for encrypted traffic on non-standard ports
3. Correlate with beacon detection findings"""
            ))

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _calculate_overall_score(self) -> float:
        """Calculate overall anomaly score from all findings."""
        if not self.findings:
            return 0.0

        severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        total_weight = 0.0
        weighted_sum = 0.0

        for finding in self.findings:
            weight = severity_weights.get(finding.severity, 0.3)
            weighted_sum += finding.confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        # Normalize to 0-1 range, capped
        raw_score = weighted_sum / max(total_weight, 1)
        # Boost score if multiple findings (corroborating evidence)
        if len(self.findings) >= 3:
            raw_score = min(raw_score * 1.3, 1.0)
        return min(raw_score, 1.0)

    def _assess_zero_day_likelihood(self, score: float) -> str:
        """Assess likelihood of zero-day based on anomaly score."""
        if score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        elif score >= 0.3:
            return "low"
        return "none"

    def _generate_summary(self) -> str:
        """Generate human-readable summary of findings."""
        if not self.findings:
            return "No behavioral anomalies detected."

        categories = Counter(f.category for f in self.findings)
        severities = Counter(f.severity for f in self.findings)

        parts = [f"Detected {len(self.findings)} anomalies:"]
        for cat, count in categories.most_common():
            parts.append(f"  - {cat}: {count}")

        if severities.get("high", 0) + severities.get("critical", 0) > 0:
            parts.append(f"\n⚠️ {severities.get('high', 0) + severities.get('critical', 0)} HIGH/CRITICAL findings require immediate review.")

        return '\n'.join(parts)

