#!/usr/bin/env python3
"""
Process raw PCAP data into training samples.

This script processes PCAP files through the same pipeline as AIPAM
to create consistent training data.

Phase 6.2: Session-Level IR mode (--session-ir) aggregates 1,000+ flows
into a single training sample with temporal metadata for 32k context.
"""

import json
import sys
import random
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# Add backend to path for importing AIPAM modules
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

try:
    from app.parsers import parse_zeek_conn, parse_suricata_eve
    from app.aggregation import aggregate_hosts, aggregate_host_pairs
    from app.anomaly_detector import AnomalyDetector
except ImportError as e:
    print(f"Warning: Could not import AIPAM modules: {e}")
    # Fallback/mock logic could go here, but for training data generation we really need the real parser
    print("Ensure backend is in PYTHONPATH.")
    sys.exit(1)


LABEL_MAPPING = {
    # Modern Malware Families (PROTECT THESE FROM MERGING)
    # Loaders
    "Pikabot": "Pikabot",
    "DarkGate": "DarkGate",
    "Latrodectus": "Latrodectus",
    "BumbleBee": "BumbleBee",
    "GuLoader": "GuLoader",
    "BazarLoader": "BazarLoader",
    "SSLoad": "SSLoad",
    "SocGholish": "SocGholish",
    "Matanbuchus": "Matanbuchus",

    # Stealers
    "Lumma_Stealer": "Lumma_Stealer",
    "Lumma": "Lumma_Stealer",
    "Meduza_Stealer": "Meduza_Stealer",
    "Meduza": "Meduza_Stealer",
    "Vidar_Stealer": "Vidar_Stealer",
    "Vidar": "Vidar_Stealer",
    "Redline_Stealer": "Redline_Stealer",
    "Redline": "Redline_Stealer",
    "StealC": "StealC",
    "Raccoon": "Raccoon",
    "AgentTesla": "AgentTesla",
    "Formbook": "Formbook",
    "XLoader": "XLoader",
    "Astaroth": "Astaroth",
    "Guildma": "Astaroth",

    # RATs
    "NetSupport_RAT": "NetSupport_RAT",
    "NetSupport": "NetSupport_RAT",
    "Remcos_RAT": "Remcos_RAT",
    "Remcos": "Remcos_RAT",
    "AsyncRAT": "AsyncRAT",
    "XWorm": "XWorm",
    "QuasarRAT": "QuasarRAT",
    "WarZone": "WarZone",

    # Banking Trojans
    "IcedID": "IcedID",
    "BokBot": "IcedID",
    "Qakbot": "Qakbot",
    "Qbot": "Qakbot",
    "Emotet": "Emotet",
    "TrickBot": "TrickBot",
    "Danabot": "Danabot",
    "Ursnif": "Ursnif",
    "Gozi": "Ursnif",
    "Pikabot": "Pikabot",
    "DarkGate": "DarkGate",
    "SocGholish": "SocGholish",
    "Latrodectus": "Latrodectus",
    "GuLoader": "GuLoader",
    "SmartLoader": "Lumma_Stealer",
    "Lumma": "Lumma_Stealer",
    "Lumma_Stealer": "Lumma_Stealer",
    "Redline": "Redline_Stealer",
    "Redline_Stealer": "Redline_Stealer",
    "AgentTesla": "AgentTesla",
    "Formbook": "Formbook",
    "XLoader": "Formbook",
    "NjRAT": "RAT",
    "NanoCore": "RAT",
    "Vidar": "Stealer",

    # C2/Pentest
    "CobaltStrike": "CobaltStrike",
    "Sliver": "Sliver",

    # Exploit Kits
    "RigEK": "RigEK",
    "Rig": "RigEK",

    # USTC-TFC-2016 labels (Keep legacy generic to avoid noise)
    "Cridex": "malware",
    "Geodo": "malware",
    "Htbot": "malware",
    "Miuref": "malware",
    "Neris": "malware",
    "Nsis-ay": "malware",
    "Shifu": "malware",
    "Tinba": "malware",
    "Virut": "malware",
    "Zeus": "malware",

    # Benign Applications
    "BitTorrent": "normal",
    "Facetime": "normal",
    "FTP": "normal",
    "Gmail": "normal",
    "MySQL": "normal",
    "Outlook": "normal",
    "Skype": "normal",
    "SMB_Transfer": "normal",
    "FTP_Benign": "normal",
    "DNS_Normal": "normal",
    "HTTP_Benign": "normal",
    "SMB": "normal",
    "Weibo": "normal",
    "WorldOfWarcraft": "normal",

    # Generic labels (Fallback)
    "malicious": "malware",
    "benign": "normal",
    "normal": "normal",
    "attack": "malware",
    "botnet": "botnet",
    "apt": "apt",
    "vpn": "vpn",
    "tor": "tor",
}


def run_zeek(pcap_path: str, output_dir: Path) -> Path:
    """Run Zeek on a PCAP file and return the directory containing logs."""
    pcap_path = str(Path(pcap_path).absolute())
    output_dir = Path(output_dir)
    
    # Try Host Zeek first
    if shutil.which("zeek"):
        try:
            cmd = [
                "zeek", "-r", pcap_path,
                "LogAscii::use_json=T"
            ]
            subprocess.run(cmd, cwd=output_dir, check=True, capture_output=True)
            return output_dir
        except subprocess.CalledProcessError as e:
            print(f"  [Zeek Error] {pcap_path}: {e.stderr.decode()[:200]}...")

    # Fallback to Docker (aipam-worker container)
    container = "aipam-worker"
    try:
        # Check if container is running
        check_proc = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", container], capture_output=True, text=True)
        if check_proc.returncode != 0 or "true" not in check_proc.stdout:
            raise Exception("Container 'aipam-worker' not running or not found")

        container_temp = f"/tmp/zeek_{os.getpid()}_{random.randint(1000, 9999)}"
        subprocess.run(["docker", "exec", container, "mkdir", "-p", container_temp], check=True)
        
        # Copy PCAP to container
        subprocess.run(["docker", "cp", pcap_path, f"{container}:{container_temp}/input.pcap"], check=True)
        
        # Run Zeek in container
        cmd = [
            "docker", "exec", "-w", container_temp, container,
            "zeek", "-r", "input.pcap",
            "LogAscii::use_json=T"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        
        # Copy logs back
        subprocess.run(f"docker cp {container}:{container_temp}/. {output_dir}/", shell=True, check=True)
        
        # Cleanup
        subprocess.run(["docker", "exec", container, "rm", "-rf", container_temp], check=True)
        return output_dir
        
    except Exception as e:
        print(f"  [Docker Zeek Error] {e}")
        # If we failed both host and docker, we can't really proceed for this PCAP
        return None


def run_suricata(pcap_path: str, output_dir: Path) -> Path:
    """Run Suricata on a PCAP file and return the directory containing logs."""
    pcap_path = str(Path(pcap_path).absolute())
    output_dir = Path(output_dir)

    # Try Host Suricata first
    if shutil.which("suricata"):
        try:
            cmd = ["suricata", "-r", pcap_path, "-l", str(output_dir), "-k", "none"]
            subprocess.run(cmd, check=True, capture_output=True)
            return output_dir
        except subprocess.CalledProcessError as e:
            print(f"  [Suricata Error] {pcap_path}: {e.stderr.decode()[:200]}...")

    # Fallback to Docker
    container = "aipam-worker"
    try:
        container_temp = f"/tmp/suricata_{os.getpid()}_{random.randint(1000, 9999)}"
        subprocess.run(["docker", "exec", container, "mkdir", "-p", container_temp], check=True)
        subprocess.run(["docker", "cp", pcap_path, f"{container}:{container_temp}/input.pcap"], check=True)
        
        cmd = [
            "docker", "exec", "-w", container_temp, container,
            "suricata", "-r", "input.pcap", "-l", ".", "-k", "none"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        
        subprocess.run(f"docker cp {container}:{container_temp}/. {output_dir}/", shell=True, check=True)
        subprocess.run(["docker", "exec", container, "rm", "-rf", container_temp], check=True)
        return output_dir
    except Exception as e:
        print(f"  [Docker Suricata Warning] {e}")
    
    return output_dir


def parse_zeek_dns(log_path: Path) -> List[Dict]:
    """Parse Zeek dns.log into raw dicts for anomaly detector."""
    queries = []
    if log_path.exists():
        with open(log_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # Standardize keys for AnomalyDetector
                    queries.append({
                        "query": data.get("query"),
                        "src_ip": data.get("id.orig_h"),
                        "timestamp": data.get("ts")
                    })
                except json.JSONDecodeError:
                    continue
    return queries


def _extract_payload_bytes(pcap_path: str, max_packets: int = 50) -> List[bytes]:
    """Extract raw payload bytes for entropy analysis."""
    try:
        from scapy.all import rdpcap, TCP, UDP
    except ImportError:
        return []

    payloads = []
    try:
        pkts = rdpcap(pcap_path, count=max_packets)
        for pkt in pkts:
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                payloads.append(bytes(pkt[TCP].payload))
            elif pkt.haslayer(UDP) and pkt[UDP].payload:
                payloads.append(bytes(pkt[UDP].payload))
    except:
        pass
    return payloads


def _extract_raw_packets(pcap_path: str, max_packets: int = 5) -> List[str]:
    """Extract raw packet fields using Scapy."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        print("  [Warning] Scapy not installed or importable.")
        return []

    packet_strings = []
    try:
        if not Path(pcap_path).exists():
            return []
            
        pkts = rdpcap(pcap_path, count=max_packets)
        for pkt in pkts:
            if not pkt.haslayer(IP):
                continue
            
            ip = pkt[IP]
            fields = [
                f"ip.version: {ip.version}",
                f"ip.len: {ip.len}",
                f"ip.ttl: {ip.ttl}",
                f"ip.proto: {ip.proto}",
                f"ip.src: {ip.src}",
                f"ip.dst: {ip.dst}"
            ]
            
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                fields.extend([
                    f"tcp.srcport: {tcp.sport}",
                    f"tcp.dstport: {tcp.dport}",
                    f"tcp.seq: {tcp.seq}",
                    f"tcp.ack: {tcp.ack}",
                    f"tcp.flags: {tcp.flags}",
                    f"tcp.window: {tcp.window}"
                ])
                if tcp.payload:
                    import binascii
                    try:
                        payload_hex = binascii.hexlify(bytes(tcp.payload)[:128]).decode()
                        fields.append(f"tcp.payload: {payload_hex}")
                    except:
                        pass
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                fields.extend([
                    f"udp.srcport: {udp.sport}",
                    f"udp.dstport: {udp.dport}",
                    f"udp.len: {udp.len}"
                ])
                if udp.payload:
                    import binascii
                    try:
                        payload_hex = binascii.hexlify(bytes(udp.payload)[:128]).decode()
                        fields.append(f"udp.payload: {payload_hex}")
                    except:
                         pass
            
            packet_strings.append(", ".join(fields))
            if len(packet_strings) >= max_packets:
                break
    except Exception as e:
        print(f"  [Scapy Error] {e}")
    
    return packet_strings


def process_pcap_file(pcap_path: str, label: str) -> Optional[Dict]:
    """Process a single PCAP file and return aggregated data."""
    try:
        # Create temp dir for Zeek logs
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Run Zeek
            try:
                run_zeek(pcap_path, output_dir=temp_path)
            except Exception:
                print(f"  Skipping {pcap_path}: Zeek execution failed")
                return None

            # Run Suricata
            run_suricata(pcap_path, output_dir=temp_path)

            # Parse Zeek flows
            conn_log = temp_path / "conn.log"
            flows = []
            if conn_log.exists():
                with open(conn_log, "r") as f:
                    zeek_data = []
                    for line in f:
                        try:
                            if line.strip():
                                zeek_data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                flows = parse_zeek_conn(zeek_data)

            # Parse Suricata alerts
            eve_json = temp_path / "eve.json"
            alerts = []
            if eve_json.exists():
                with open(eve_json, "r") as f:
                    eve_data = []
                    for line in f:
                        try:
                            if line.strip():
                                eve_data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                alerts = parse_suricata_eve(eve_data)

            if not flows:
                print(f"  Skipping {pcap_path}: No flows found")
                return None

            # Aggregate data
            host_summaries = aggregate_hosts(flows, alerts)
            hostpair_summaries = aggregate_host_pairs(flows, alerts)

            # Run Anomaly Detector (CRITICAL for v4)
            dns_queries = parse_zeek_dns(temp_path / "dns.log")
            payload_samples = _extract_payload_bytes(pcap_path)
            
            detector = AnomalyDetector()
            anomaly_report = detector.analyze(
                flows=flows,
                alerts=alerts,
                dns_queries=dns_queries,
                payload_samples=payload_samples
            )

            # Extract raw packets
            raw_packets = _extract_raw_packets(pcap_path)

            return {
                "pcap_file": os.path.basename(pcap_path),
                "label": label,
                "normalized_label": LABEL_MAPPING.get(label, label),
                "host_summaries": [hs.model_dump(mode='json') for hs in host_summaries],
                "hostpair_summaries": [hps.model_dump(mode='json') for hps in hostpair_summaries],
                "raw_packet_samples": raw_packets,
                "anomaly_report": anomaly_report.to_dict(),  # NEW
                "flow_count": len(flows),
                "alert_count": len(alerts),
            }
            
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        return None


def process_dataset(dataset_dir: Path, dataset_type: str, base_dir: Path, limit: Optional[int] = None) -> List[Dict]:
    """Process all PCAP files in a dataset directory."""
    results = []
    dataset_path = Path(dataset_dir)

    if not dataset_path.exists():
        print(f"Dataset directory not found: {dataset_dir}")
        return results

    # Find all PCAP files
    pcap_files = list(dataset_path.glob("**/*.pcap")) + \
                 list(dataset_path.glob("**/*.pcapng"))

    print(f"Found {len(pcap_files)} PCAP files in {dataset_dir}")

    if limit:
        pcap_files = pcap_files[:limit]
        print(f"Limiting to first {limit} files.")

    # Sort files to ensure deterministic behavior (useful for debugging)
    pcap_files.sort()

    def get_label_for_file(pcap_file: Path) -> str:
        # Phase 6.4: Check for sidecar .metadata.json first
        sidecar = pcap_file.with_suffix(".metadata.json")
        if sidecar.exists():
            try:
                with open(sidecar) as f:
                    meta = json.load(f)
                return meta.get("label", pcap_file.parent.name)
            except (json.JSONDecodeError, KeyError):
                pass
        parent_name = pcap_file.parent.name
        if parent_name in ["pcap", "raw", "data", "modern"]:
            return pcap_file.stem.split("_")[0]
        return parent_name

    # Use parallel processing for speedup
    max_workers = os.cpu_count() or 4
    # Cap workers to avoid overwhelming docker
    max_workers = min(max_workers, 8) 
    
    print(f"Starting parallel processing with {max_workers} workers...")
    
    output_file = base_dir / "processed/processed_samples_v5.jsonl"
    
    with open(output_file, "a") as f_out: # Use append mode for robustness
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(process_pcap_file, str(pcap), get_label_for_file(pcap)): pcap 
                for pcap in pcap_files
            }
            
            iterator = as_completed(futures)
            if tqdm:
                iterator = tqdm(iterator, total=len(futures), desc=f"Processing {dataset_type}")
                
            for future in iterator:
                pcap = futures[future]
                try:
                    result = future.result()
                    if result:
                        result["dataset_type"] = dataset_type
                        f_out.write(json.dumps(result) + "\n")
                        f_out.flush() # Ensure it hits disk
                        results.append(result)
                except Exception as e:
                    print(f"  Failed to process {pcap.name}: {e}")

    return results


# =============================================================================
# Phase 6.2 — Session-Level IR Generation
# =============================================================================

def aggregate_session_flows(
    flows: List,
    window_minutes: int = 15,
) -> List[Dict]:
    """Group flows into time windows with temporal metadata.

    Preserves inter-arrival times so the model's attention mechanism
    can detect periodic C2 heartbeats and low-and-slow exfiltration.

    Args:
        flows: List of parsed flow objects (from parse_zeek_conn).
        window_minutes: Time window size in minutes (default 15).

    Returns:
        List of flow dicts enriched with temporal metadata,
        grouped into windows.
    """
    if not flows:
        return []

    # Extract timestamps and sort chronologically
    timed_flows = []
    for flow in flows:
        # Flow objects may have different attribute names
        ts = None
        if hasattr(flow, 'timestamp'):
            ts = flow.timestamp
        elif hasattr(flow, 'ts'):
            ts = flow.ts
        elif isinstance(flow, dict):
            ts = flow.get('timestamp', flow.get('ts', 0))

        try:
            ts = float(ts) if ts else 0.0
        except (TypeError, ValueError):
            ts = 0.0

        duration = 0.0
        if hasattr(flow, 'duration'):
            try:
                duration = float(flow.duration) if flow.duration else 0.0
            except (TypeError, ValueError):
                duration = 0.0
        elif isinstance(flow, dict):
            try:
                duration = float(flow.get('duration', 0))
            except (TypeError, ValueError):
                duration = 0.0

        timed_flows.append({
            'flow': flow,
            'timestamp': ts,
            'duration': duration,
        })

    # Sort by timestamp
    timed_flows.sort(key=lambda x: x['timestamp'])

    # Compute inter-arrival times
    for i in range(len(timed_flows)):
        if i == 0:
            timed_flows[i]['inter_arrival_time'] = 0.0
        else:
            delta = timed_flows[i]['timestamp'] - timed_flows[i - 1]['timestamp']
            timed_flows[i]['inter_arrival_time'] = round(delta, 4)

    # Group into time windows
    window_seconds = window_minutes * 60
    windows = []
    current_window = []
    window_start = timed_flows[0]['timestamp'] if timed_flows else 0

    for tf in timed_flows:
        if tf['timestamp'] - window_start > window_seconds and current_window:
            windows.append(current_window)
            current_window = []
            window_start = tf['timestamp']
        current_window.append(tf)

    if current_window:
        windows.append(current_window)

    # Build enriched output
    enriched_flows = []
    for window_idx, window in enumerate(windows):
        for tf in window:
            flow = tf['flow']
            # Serialize the flow object
            if hasattr(flow, 'model_dump'):
                flow_dict = flow.model_dump(mode='json')
            elif isinstance(flow, dict):
                flow_dict = flow
            else:
                flow_dict = {'raw': str(flow)}

            flow_dict['_temporal'] = {
                'window_index': window_idx,
                'timestamp': tf['timestamp'],
                'duration': tf['duration'],
                'inter_arrival_time': tf['inter_arrival_time'],
            }
            enriched_flows.append(flow_dict)

    return enriched_flows


def process_pcap_session(
    pcap_path: str,
    label: str,
    max_raw_packets: int = 100,
    max_payload_packets: int = 500,
    window_minutes: int = 15,
) -> Optional[Dict]:
    """Process a PCAP in session-level mode for 32k context.

    Unlike process_pcap_file (which caps at 5 raw packets / 50 payloads),
    this function extracts up to 100 raw packets and 500 payload samples,
    and enriches all flows with temporal metadata.

    Args:
        pcap_path: Path to PCAP file.
        label: Ground truth label.
        max_raw_packets: Max raw packet extractions (default 100 for 32k).
        max_payload_packets: Max payload extractions (default 500).
        window_minutes: Time window for flow grouping.

    Returns:
        Enriched sample dict, or None on failure.
    """
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Run Zeek
            try:
                run_zeek(pcap_path, output_dir=temp_path)
            except Exception:
                print(f"  Skipping {pcap_path}: Zeek execution failed")
                return None

            # Run Suricata
            run_suricata(pcap_path, output_dir=temp_path)

            # Parse Zeek flows
            conn_log = temp_path / "conn.log"
            flows = []
            if conn_log.exists():
                with open(conn_log, "r") as f:
                    zeek_data = []
                    for line in f:
                        try:
                            if line.strip():
                                zeek_data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                flows = parse_zeek_conn(zeek_data)

            # Parse Suricata alerts
            eve_json = temp_path / "eve.json"
            alerts = []
            if eve_json.exists():
                with open(eve_json, "r") as f:
                    eve_data = []
                    for line in f:
                        try:
                            if line.strip():
                                eve_data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                alerts = parse_suricata_eve(eve_data)

            if not flows:
                print(f"  Skipping {pcap_path}: No flows found")
                return None

            # Session-level aggregation with temporal metadata
            session_flows = aggregate_session_flows(
                flows, window_minutes=window_minutes
            )

            # Standard aggregations (same as v5)
            host_summaries = aggregate_hosts(flows, alerts)
            hostpair_summaries = aggregate_host_pairs(flows, alerts)

            # Anomaly detection
            dns_queries = parse_zeek_dns(temp_path / "dns.log")
            payload_samples = _extract_payload_bytes(
                pcap_path, max_packets=max_payload_packets
            )

            detector = AnomalyDetector()
            anomaly_report = detector.analyze(
                flows=flows,
                alerts=alerts,
                dns_queries=dns_queries,
                payload_samples=payload_samples,
            )

            # Extended raw packets (100 instead of 5)
            raw_packets = _extract_raw_packets(
                pcap_path, max_packets=max_raw_packets
            )

            return {
                "pcap_file": os.path.basename(pcap_path),
                "label": label,
                "normalized_label": LABEL_MAPPING.get(label, label),
                "mode": "session_ir",
                "session_flows": session_flows,
                "host_summaries": [
                    hs.model_dump(mode='json') for hs in host_summaries
                ],
                "hostpair_summaries": [
                    hps.model_dump(mode='json') for hps in hostpair_summaries
                ],
                "raw_packet_samples": raw_packets,
                "anomaly_report": anomaly_report.to_dict(),
                "flow_count": len(flows),
                "session_flow_count": len(session_flows),
                "alert_count": len(alerts),
                "raw_packet_count": len(raw_packets),
                "payload_sample_count": len(payload_samples),
            }

    except Exception as e:
        print(f"Error processing session {pcap_path}: {e}")
        return None


def process_dataset_session(
    dataset_dir: Path,
    dataset_type: str,
    base_dir: Path,
    limit: Optional[int] = None,
) -> List[Dict]:
    """Process PCAP files in session-IR mode for 32k context."""
    results = []
    dataset_path = Path(dataset_dir)

    if not dataset_path.exists():
        print(f"Dataset directory not found: {dataset_dir}")
        return results

    pcap_files = list(dataset_path.glob("**/*.pcap")) + \
                 list(dataset_path.glob("**/*.pcapng"))

    print(f"Found {len(pcap_files)} PCAP files in {dataset_dir}")

    if limit:
        pcap_files = pcap_files[:limit]
        print(f"Limiting to first {limit} files.")

    pcap_files.sort()

    def get_label_for_file(pcap_file: Path) -> str:
        parent_name = pcap_file.parent.name
        if parent_name in ["pcap", "raw", "data", "modern"]:
            return pcap_file.stem.split("_")[0]
        return parent_name

    max_workers = min(os.cpu_count() or 4, 8)
    print(f"Starting session-IR processing with {max_workers} workers...")

    output_file = base_dir / "processed/processed_samples_v6_session.jsonl"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "a") as f_out:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    process_pcap_session, str(pcap), get_label_for_file(pcap)
                ): pcap
                for pcap in pcap_files
            }

            iterator = as_completed(futures)
            if tqdm:
                iterator = tqdm(
                    iterator, total=len(futures),
                    desc=f"Session-IR {dataset_type}"
                )

            for future in iterator:
                pcap = futures[future]
                try:
                    result = future.result()
                    if result:
                        result["dataset_type"] = dataset_type
                        f_out.write(json.dumps(result) + "\n")
                        f_out.flush()
                        results.append(result)
                except Exception as e:
                    print(f"  Failed to process {pcap.name}: {e}")

    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Process PCAPs into training data")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of PCAPs per dataset")
    parser.add_argument("--dataset", type=str, default=None, help="Process only specific dataset")
    parser.add_argument(
        "--session-ir", action="store_true",
        help="Phase 6.2: Session-level IR with 1,000+ flows and temporal metadata"
    )
    parser.add_argument("--data-dir", type=str, default="data", help="Base directory for data storage (default: ./data)")
    args = parser.parse_args()

    # Resolve absolute path for data directory
    if args.data_dir == "data":
        base_dir = Path("data")
    else:
        base_dir = Path(args.data_dir)

    mode_label = "Session-Level IR (Phase 6.2)" if args.session_ir else "Standard (v5)"
    print("=" * 60)
    print(f"PCAP Training Data Processor — {mode_label}")
    print(f"Data Directory: {base_dir.resolve()}")
    print("=" * 60)

    raw_data_dir = base_dir / "raw"
    processed_dir = base_dir / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    dataset_types = {
        "modern": "malware",
        "adversarial_benign": "normal",
        "ustc-tfc-2016": "malware",
        "iscx-botnet-2014": "botnet",
        "csic-2010": "web_attack",
        "dapt-2020": "apt",
        "iscx-vpn-2016": "vpn",
        "iscx-tor-2016": "tor",
        "synthetic": "synthetic",  # Phase 6.4: Purple Team augmented data
    }

    all_samples = []
    processor = process_dataset_session if args.session_ir else process_dataset

    for dataset_name, dataset_type in dataset_types.items():
        if args.dataset and dataset_name != args.dataset:
            continue
            
        dataset_dir = raw_data_dir / dataset_name
        if dataset_dir.exists():
            print(f"\nProcessing {dataset_name}...")
            samples = processor(dataset_dir, dataset_type, base_dir, limit=args.limit)
            if args.limit:
                samples = samples[:args.limit]
            
            all_samples.extend(samples)
            print(f"  Processed {len(samples)} samples")

    output_name = "processed_samples_v6_session.jsonl" if args.session_ir else "processed_samples_v5.jsonl"
    print(f"\n✓ Finished processing. Dataset is at {processed_dir}/{output_name}")
    if args.session_ir:
        total_flows = sum(s.get('session_flow_count', 0) for s in all_samples)
        print(f"  Total session flows: {total_flows}")
        print(f"  Avg flows/sample: {total_flows / max(len(all_samples), 1):.0f}")


if __name__ == "__main__":
    main()
