#!/usr/bin/env python3
"""
Add benchmark PCAPs to the LoRA v2 training data.

This script processes the 46 benchmark PCAPs and adds them to the training dataset
in the correct format for fine-tuning.
"""

import os
import json
import random
import binascii
from pathlib import Path
from typing import List, Dict

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.run(["pip", "install", "scapy", "-q"])
    from scapy.all import rdpcap, IP, TCP, UDP

# Paths
BENCHMARK_MANIFEST = Path(__file__).parent.parent / "benchmark/manifests/available_benchmark.json"
TRAINING_DATA = Path(__file__).parent / "aipam_gpu_training/data/new_unified_train.jsonl"
OUTPUT_FILE = Path(__file__).parent / "aipam_gpu_training/data/benchmark_training_samples.jsonl"

# Training format constants
MAX_PACKET_LENGTH = 1024
PACKETS_PER_PCAP = 100  # Generate more samples per PCAP to increase family representation

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in network traffic analysis. 
You analyze packet data to detect malware, identify attack patterns, and provide security insights.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings."""

# Extended categories list matching the most common training format
CATEGORIES = "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft, Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, IcedID, Qakbot, Emotet, TrickBot, Formbook, CobaltStrike, BazarLoader, DarkGate, Ursnif, Pikabot, BumbleBee, Matanbuchus, Astaroth, AgentTesla, Lumma_Stealer, Danabot, SSLoad, Remcos_RAT, Sliver, Latrodectus, NetSupport_RAT, Redline_Stealer, SocGholish, Raccoon, Meduza_Stealer, GuLoader, AsyncRAT, XWorm, XLoader, StealC, RigEK"

INSTRUCTION_TEMPLATE = f"""Given the following traffic data <packet> that contains protocol fields, traffic features, and payloads. Please conduct the ENCRYPTED MALWARE DETECTION TASK to determine which application category the encrypted benign or malicious traffic belongs to. The categories include '{CATEGORIES}'.
<packet>: {{packet_data}}"""

OUTPUT_TEMPLATE = "This might be a Malware traffic packet. The category is likely to be recognized as {label}."


def extract_packets(pcap_path: str, max_packets: int = PACKETS_PER_PCAP) -> List[str]:
    """Extract packet data in training format."""
    packets_data = []
    try:
        pkts = rdpcap(pcap_path, count=max_packets * 3)
        
        for pkt in pkts:
            if len(packets_data) >= max_packets:
                break
                
            if not pkt.haslayer(IP):
                continue
                
            ip = pkt[IP]
            fields = []
            
            # IP layer
            fields.append(f"ip.version: {ip.version}")
            fields.append(f"ip.len: {ip.len}")
            fields.append(f"ip.ttl: {ip.ttl}")
            fields.append(f"ip.proto: {ip.proto}")
            fields.append(f"ip.src: {ip.src}")
            fields.append(f"ip.dst: {ip.dst}")
            
            # TCP layer
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                fields.append(f"tcp.srcport: {tcp.sport}")
                fields.append(f"tcp.dstport: {tcp.dport}")
                fields.append(f"tcp.seq: {tcp.seq}")
                fields.append(f"tcp.ack: {tcp.ack}")
                fields.append(f"tcp.flags: {tcp.flags}")
                fields.append(f"tcp.window: {tcp.window}")
                
                if tcp.payload:
                    payload_bytes = bytes(tcp.payload)[:256]
                    payload_hex = binascii.hexlify(payload_bytes).decode()[:512]
                    fields.append(f"tcp.payload: {payload_hex}")
                    
            # UDP layer
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                fields.append(f"udp.srcport: {udp.sport}")
                fields.append(f"udp.dstport: {udp.dport}")
                fields.append(f"udp.len: {udp.len}")
                
                if udp.payload:
                    payload_bytes = bytes(udp.payload)[:256]
                    payload_hex = binascii.hexlify(payload_bytes).decode()[:512]
                    fields.append(f"udp.payload: {payload_hex}")
            else:
                continue
                
            packet_str = ", ".join(fields)
            if len(packet_str) < MAX_PACKET_LENGTH:
                packets_data.append(packet_str)
                
    except Exception as e:
        print(f"  Error reading {pcap_path}: {e}")
        
    return packets_data


def create_training_sample(packet_data: str, label: str) -> Dict:
    """Create a training sample in chat format."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": INSTRUCTION_TEMPLATE.format(packet_data=packet_data)},
            {"role": "assistant", "content": OUTPUT_TEMPLATE.format(label=label)}
        ]
    }


def main():
    # Load benchmark manifest
    with open(BENCHMARK_MANIFEST) as f:
        manifest = json.load(f)
    
    samples = manifest["samples"]
    print(f"Processing {len(samples)} benchmark PCAPs...")
    print(f"Generating up to {PACKETS_PER_PCAP} samples per PCAP")
    print("=" * 60)
    
    all_samples = []
    family_counts = {}
    
    for i, sample in enumerate(samples):
        pcap_path = Path(__file__).parent.parent / sample["pcap"]
        label = sample["label"]
        
        print(f"[{i+1}/{len(samples)}] {label}: {pcap_path.name}...", end=" ")
        
        packets = extract_packets(str(pcap_path), max_packets=PACKETS_PER_PCAP)
        print(f"{len(packets)} packets")
        
        for packet in packets:
            training_sample = create_training_sample(packet, label)
            all_samples.append(training_sample)
        
        family_counts[label] = family_counts.get(label, 0) + len(packets)
    
    # Shuffle samples
    random.shuffle(all_samples)
    
    # Save to file
    print(f"\n{'=' * 60}")
    print(f"Total new training samples: {len(all_samples)}")
    print(f"\nSamples per family:")
    for family, count in sorted(family_counts.items(), key=lambda x: -x[1]):
        print(f"  {family}: {count}")
    
    # Write samples
    with open(OUTPUT_FILE, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + "\n")
    
    print(f"\nSaved to: {OUTPUT_FILE}")
    print(f"\nTo add to training data, run:")
    print(f"  cat {OUTPUT_FILE} >> {TRAINING_DATA}")


if __name__ == "__main__":
    main()

