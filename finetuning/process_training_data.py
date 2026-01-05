#!/usr/bin/env python3
"""
Process raw PCAP data into training samples.

This script processes PCAP files through the same pipeline as AIPAM
to create consistent training data.
"""

import json
import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

# Add backend to path for importing AIPAM modules
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

try:
    from app.parsers import parse_zeek_conn
    from app.aggregation import aggregate_hosts, aggregate_host_pairs
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
    pcap_file = Path(pcap_path)
    
    # Check if Zeek is installed
    if not shutil.which("zeek"):
        # If running in a container where zeek might be in a different path or not in PATH for shutil
        if Path("/opt/zeek/bin/zeek").exists():
            zeek_bin = "/opt/zeek/bin/zeek"
        else:
            raise RuntimeError("Zeek is not installed or not in PATH.")
    else:
        zeek_bin = "zeek"

    try:
        # Run Zeek with JSON output
        cmd = [
            zeek_bin, 
            "-C", 
            "-r", str(pcap_file), 
            f"Log::default_logdir={output_dir}", 
            "LogAscii::use_json=T"
        ]
        # capture_output=True prevents external noise, but check=True ensures we catch errors
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"  [Zeek Error] {pcap_path}: {e.stderr.decode()[:200]}...")
        # Check if any logs were generated despite failure (sometimes Zeek errors on partial pcaps)
        if not list(output_dir.glob("*.log")):
             raise e

    return output_dir


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
            except Exception as e:
                print(f"  Skipping {pcap_path}: Zeek execution failed")
                return None

            # Parse Zeek logs
            # conn.log is primary for flow data
            conn_log = temp_path / "conn.log"
            flows = []
            if conn_log.exists():
                with open(conn_log, "r") as f:
                    zeek_data = []
                    # Try reading as JSON list first
                    try:
                        zeek_data = json.load(f)
                    except json.JSONDecodeError:
                        # Try reading as JSON Lines
                        f.seek(0)
                        for line in f:
                            try:
                                if line.strip():
                                    zeek_data.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                flows = parse_zeek_conn(zeek_data)

            events = [] 
            
            if not flows:
                print(f"  Skipping {pcap_path}: No flows found in conn.log")
                return None

            # Aggregate data
            host_summaries = aggregate_hosts(flows, [])
            hostpair_summaries = aggregate_host_pairs(flows, [])

            # Extract raw packets
            raw_packets = _extract_raw_packets(pcap_path)

            return {
                "pcap_file": os.path.basename(pcap_path),
                "label": label,
                "normalized_label": LABEL_MAPPING.get(label, label),
                "host_summaries": [hs.model_dump(mode='json') for hs in host_summaries],
                "hostpair_summaries": [hps.model_dump(mode='json') for hps in hostpair_summaries],
                "raw_packet_samples": raw_packets,
                "flow_count": len(flows),
                "event_count": len(events),
            }
            
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        return None


def process_dataset(dataset_dir: str, dataset_type: str) -> List[Dict]:
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

    for pcap_file in pcap_files:
        # Try to extract label from directory structure or filename
        parent_name = pcap_file.parent.name
        
        # If parent is a generic name, go up one level or use filename
        if parent_name in ["pcap", "raw", "data", "modern"]:
            label = pcap_file.stem.split("_")[0]
        else:
            label = parent_name
            
        print(f"Processing: {pcap_file.name} (label: {label})")
        result = process_pcap_file(str(pcap_file), label)

        if result:
            result["dataset_type"] = dataset_type
            results.append(result)

    return results


def main():
    print("=" * 60)
    print("PCAP Training Data Processor")
    print("=" * 60)

    raw_data_dir = Path("data/raw")
    processed_dir = Path("data/processed")
    processed_dir.mkdir(parents=True, exist_ok=True)

    dataset_types = {
        "modern": "malware",
        "ustc-tfc-2016": "malware",
        "iscx-botnet-2014": "botnet",
        "csic-2010": "web_attack",
        "dapt-2020": "apt",
        "iscx-vpn-2016": "vpn",
        "iscx-tor-2016": "tor",
    }

    all_samples = []

    for dataset_name, dataset_type in dataset_types.items():
        dataset_dir = raw_data_dir / dataset_name
        if dataset_dir.exists():
            print(f"\nProcessing {dataset_name}...")
            samples = process_dataset(str(dataset_dir), dataset_type)
            all_samples.extend(samples)
            print(f"  Processed {len(samples)} samples")

    # Save processed data
    output_file = processed_dir / "processed_samples.jsonl"
    with open(output_file, "w") as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + "\n")

    print(f"\n✓ Saved {len(all_samples)} samples to {output_file}")


if __name__ == "__main__":
    main()
