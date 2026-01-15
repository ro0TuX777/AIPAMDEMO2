#!/usr/bin/env python3
"""
Process raw PCAP data into training samples.

This script processes PCAP files through the same pipeline as AIPAM
to create consistent training data.
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


def process_dataset(dataset_dir: str, dataset_type: str, limit: Optional[int] = None) -> List[Dict]:
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
        parent_name = pcap_file.parent.name
        if parent_name in ["pcap", "raw", "data", "modern"]:
            return pcap_file.stem.split("_")[0]
        return parent_name

    # Use parallel processing for speedup
    max_workers = os.cpu_count() or 4
    # Cap workers to avoid overwhelming docker
    max_workers = min(max_workers, 8) 
    
    print(f"Starting parallel processing with {max_workers} workers...")
    
    output_file = Path("data/processed/processed_samples_v5.jsonl")
    
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


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Process PCAPs into training data")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of PCAPs per dataset")
    parser.add_argument("--dataset", type=str, default=None, help="Process only specific dataset")
    args = parser.parse_args()

    print("=" * 60)
    print("PCAP Training Data Processor")
    print("=" * 60)

    raw_data_dir = Path("data/raw")
    processed_dir = Path("data/processed")
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
    }

    all_samples = []

    for dataset_name, dataset_type in dataset_types.items():
        if args.dataset and dataset_name != args.dataset:
            continue
            
        dataset_dir = raw_data_dir / dataset_name
        if dataset_dir.exists():
            print(f"\nProcessing {dataset_name}...")
            # We filter in process_dataset or just slice here
            samples = process_dataset(str(dataset_dir), dataset_type, limit=args.limit)
            if args.limit:
                samples = samples[:args.limit]
            
            all_samples.extend(samples)
            print(f"  Processed {len(samples)} samples")

    print(f"\n✓ Finished processing. Dataset is at data/processed/processed_samples_v5.jsonl")


if __name__ == "__main__":
    main()
