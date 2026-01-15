#!/usr/bin/env python3
"""
Process PCAPs into training data organized by family and batch.
Generates JSON training files for each malware family and batch.
"""

import os
import json
import random
import binascii
from pathlib import Path
from typing import List, Dict
from collections import defaultdict
from training_batches import TRAINING_BATCHES, FAMILY_TO_BATCH, ALL_FAMILIES

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.run(["pip", "install", "scapy", "-q"])
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw

PCAPS_DIR = Path("pcaps")
OUTPUT_DIR = Path("training_data_batches")
MAX_PACKETS_PER_PCAP = 50  # Limit packets per PCAP for balanced training

# Enhanced instruction template
INSTRUCTION_TEMPLATE = """Analyze this network traffic and identify the malware family.

Traffic Data:
{packet_data}

Identify the malware family from: {categories}"""

OUTPUT_TEMPLATE = """Based on the traffic patterns, this is **{malware_label}** malware traffic.

Key indicators:
- C2 communication patterns consistent with {malware_label}
- Protocol usage and timing typical of this malware family
- Network behavior matches known {malware_label} signatures"""


def extract_packet_features(pcap_file: str, max_packets: int = MAX_PACKETS_PER_PCAP) -> List[Dict]:
    """Extract detailed packet features from PCAP."""
    try:
        packets_data = []
        pkts = rdpcap(str(pcap_file), count=max_packets * 5)
        
        for pkt in pkts:
            if len(packets_data) >= max_packets:
                break
            if not pkt.haslayer(IP):
                continue
                
            ip = pkt[IP]
            features = {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "proto": ip.proto,
                "ttl": ip.ttl,
                "len": ip.len,
            }
            
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                features.update({
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "tcp_flags": str(tcp.flags),
                    "seq": tcp.seq,
                    "window": tcp.window,
                })
                if tcp.payload:
                    payload = bytes(tcp.payload)[:128]
                    features["payload_hex"] = binascii.hexlify(payload).decode()[:256]
                    features["payload_len"] = len(bytes(tcp.payload))
                    
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                features.update({
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "udp_len": udp.len,
                })
                if udp.payload:
                    payload = bytes(udp.payload)[:128]
                    features["payload_hex"] = binascii.hexlify(payload).decode()[:256]
            else:
                continue
                
            packets_data.append(features)
        return packets_data
    except Exception as e:
        print(f"  Error: {e}")
        return []


def format_packet_data(packets: List[Dict]) -> str:
    """Format packet list into readable string."""
    lines = []
    for i, pkt in enumerate(packets[:10], 1):  # Show first 10 packets
        proto = "TCP" if "tcp_flags" in pkt else "UDP"
        line = f"[{i}] {pkt['src_ip']}:{pkt.get('src_port', '?')} -> {pkt['dst_ip']}:{pkt.get('dst_port', '?')} ({proto})"
        if "payload_len" in pkt:
            line += f" payload={pkt['payload_len']}bytes"
        if "tcp_flags" in pkt:
            line += f" flags={pkt['tcp_flags']}"
        lines.append(line)
    if len(packets) > 10:
        lines.append(f"... and {len(packets) - 10} more packets")
    return "\n".join(lines)


def create_training_sample(packets: List[Dict], family: str, batch_families: List[str]) -> Dict:
    """Create a training sample."""
    packet_str = format_packet_data(packets)
    return {
        "instruction": INSTRUCTION_TEMPLATE.format(
            packet_data=packet_str,
            categories=", ".join(batch_families)
        ),
        "output": OUTPUT_TEMPLATE.format(malware_label=family),
        "malware_family": family,
        "packet_count": len(packets),
    }


def process_family(family: str, batch_families: List[str] = None) -> List[Dict]:
    """Process all PCAPs for a single malware family."""
    family_dir = PCAPS_DIR / family
    if not family_dir.exists():
        print(f"  Warning: No directory for {family}")
        return []

    if batch_families is None:
        batch_families = [family]

    samples = []
    pcap_files = list(family_dir.glob("*.pcap"))
    print(f"  Processing {family}: {len(pcap_files)} PCAPs")

    for pcap_file in pcap_files:
        packets = extract_packet_features(pcap_file)
        if packets:
            sample = create_training_sample(packets, family, batch_families)
            samples.append(sample)

    return samples


def process_batch(batch_name: str) -> Dict:
    """Process all families in a batch."""
    batch_info = TRAINING_BATCHES.get(batch_name)
    if not batch_info:
        print(f"Unknown batch: {batch_name}")
        return {}

    print(f"\n{'='*60}")
    print(f"Processing {batch_name}: {batch_info['description']}")
    print(f"{'='*60}")

    all_samples = []
    family_counts = {}
    batch_families = batch_info["families"]

    for family in batch_families:
        samples = process_family(family, batch_families)
        family_counts[family] = len(samples)
        all_samples.extend(samples)

    return {
        "batch_name": batch_name,
        "description": batch_info["description"],
        "samples": all_samples,
        "family_counts": family_counts,
        "total_samples": len(all_samples),
    }


def save_batch_data(batch_result: Dict, output_dir: Path):
    """Save batch training data to files."""
    batch_name = batch_result["batch_name"]
    samples = batch_result["samples"]

    if not samples:
        print(f"  No samples for {batch_name}")
        return

    # Shuffle samples
    random.shuffle(samples)

    # Split 90/10 train/val
    split_idx = int(len(samples) * 0.9)
    train_samples = samples[:split_idx]
    val_samples = samples[split_idx:]

    # Save files
    batch_dir = output_dir / batch_name
    batch_dir.mkdir(parents=True, exist_ok=True)

    with open(batch_dir / "train.json", "w") as f:
        json.dump(train_samples, f, indent=2)

    with open(batch_dir / "val.json", "w") as f:
        json.dump(val_samples, f, indent=2)

    with open(batch_dir / "metadata.json", "w") as f:
        json.dump({
            "batch_name": batch_name,
            "description": batch_result["description"],
            "family_counts": batch_result["family_counts"],
            "train_samples": len(train_samples),
            "val_samples": len(val_samples),
        }, f, indent=2)

    print(f"  Saved {batch_name}: {len(train_samples)} train, {len(val_samples)} val")


def save_family_data(family: str, samples: List[Dict], output_dir: Path):
    """Save individual family training data."""
    if not samples:
        return

    family_dir = output_dir / "by_family" / family
    family_dir.mkdir(parents=True, exist_ok=True)

    random.shuffle(samples)
    split_idx = int(len(samples) * 0.9)

    with open(family_dir / "train.json", "w") as f:
        json.dump(samples[:split_idx], f, indent=2)

    with open(family_dir / "val.json", "w") as f:
        json.dump(samples[split_idx:], f, indent=2)


def main():
    """Main processing function."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    print("=" * 60)
    print("PCAP BATCH PROCESSING")
    print("=" * 60)

    all_family_samples = {}
    batch_results = {}

    # Process each batch
    for batch_name in TRAINING_BATCHES.keys():
        result = process_batch(batch_name)
        batch_results[batch_name] = result
        save_batch_data(result, OUTPUT_DIR)

        # Also save per-family data
        for family in TRAINING_BATCHES[batch_name]["families"]:
            if family not in all_family_samples:
                all_family_samples[family] = process_family(family)
            save_family_data(family, all_family_samples[family], OUTPUT_DIR)

    # Print summary
    print("\n" + "=" * 60)
    print("PROCESSING COMPLETE")
    print("=" * 60)

    total_samples = 0
    for batch_name, result in batch_results.items():
        print(f"\n{batch_name}:")
        print(f"  Total: {result['total_samples']} samples")
        for family, count in sorted(result["family_counts"].items()):
            print(f"    {family}: {count}")
        total_samples += result["total_samples"]

    print(f"\n{'='*60}")
    print(f"GRAND TOTAL: {total_samples} training samples")
    print(f"Output directory: {OUTPUT_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()

