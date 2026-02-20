#!/usr/bin/env python3
"""
Preprocess malware PCAPs into TrafficLLM training format.

TrafficLLM expects data in format:
{
    "instruction": "Given the following traffic data <packet>... Please conduct the ENCRYPTED MALWARE DETECTION TASK...",
    "output": "This might be a Malware traffic packet. The category is likely to be recognized as Lumma_Stealer."
}
"""

import os
import json
import random
import binascii
from typing import List, Dict

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.run(["pip", "install", "scapy", "-q"])
    from scapy.all import rdpcap, IP, TCP, UDP

PCAPS_DIR = "pcaps"
OUTPUT_DIR = "training_data"
MAX_PACKET_LENGTH = 1024

# Instruction template (matching TrafficLLM's EMD task)
CATEGORIES = (
    "AZORult, AgentTesla, AnglerEK, Astaroth, AsyncRAT, BazarLoader, "
    "BitTorrent, BumbleBee, Cerber, CobaltStrike, Cridex, Danabot, DarkGate, "
    "Dridex, Emotet, FTP, Facetime, Formbook, Geodo, Gmail, GootLoader, "
    "GuLoader, Hancitor, Htbot, IcedID, Latrodectus, Locky, LokiBot, "
    "Lumma_Stealer, Matanbuchus, Meduza_Stealer, Miuref, MySQL, Necurs, "
    "Neris, NetSupport_RAT, NeutrinoEK, Nsis-ay, Nymaim, Outlook, Pikabot, "
    "Pony, Qakbot, Raccoon, Ransomware, Redline_Stealer, Remcos_RAT, "
    "Rhadamanthys, RigEK, SMB, SSLoad, Shifu, Skype, Sliver, SmokeLoader, "
    "SnakeKeylogger, SocGholish, StealC, Tinba, TrickBot, Ursnif, Vawtrak, "
    "Virut, Weibo, WorldOfWarcraft, XLoader, XWorm, ZLoader, Zeus"
)

INSTRUCTION_TEMPLATE = (
    "Given the following traffic data <packet> that contains protocol fields, "
    "traffic features, and payloads. Please conduct the ENCRYPTED MALWARE "
    "DETECTION TASK to determine which application category the encrypted "
    "benign or malicious traffic belongs to. The categories include "
    "'{categories}'.\n<packet>: {packet_data}"
)

OUTPUT_TEMPLATE = "This might be a Malware traffic packet. The category is likely to be recognized as {malware_label}."


def extract_packets_scapy(pcap_file: str, max_packets: int = 300) -> List[str]:
    """Extract packet data using scapy."""
    try:
        packets_data = []
        pkts = rdpcap(pcap_file, count=max_packets * 3)  # Read more, filter later

        for i, pkt in enumerate(pkts):
            if len(packets_data) >= max_packets:
                break

            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            fields = []

            # IP layer fields
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

                # Payload
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
                continue  # Skip non-TCP/UDP

            packet_str = ", ".join(fields)
            if len(packet_str) < MAX_PACKET_LENGTH:
                packets_data.append(packet_str)

        return packets_data

    except Exception as e:
        print(f"  Error reading {pcap_file}: {e}")
        return []


def create_training_sample(packet_data: str, malware_label: str) -> Dict:
    """Create a training sample in TrafficLLM format."""
    return {
        "instruction": INSTRUCTION_TEMPLATE.format(
            categories=CATEGORIES, packet_data=packet_data
        ),
        "output": OUTPUT_TEMPLATE.format(malware_label=malware_label)
    }


def process_all_pcaps():
    """Process all PCAPs and create training dataset."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    all_samples = []
    labels = set()
    
    for malware_dir in sorted(os.listdir(PCAPS_DIR)):
        malware_path = os.path.join(PCAPS_DIR, malware_dir)
        if not os.path.isdir(malware_path):
            continue
        
        labels.add(malware_dir)
        
        for pcap_file in os.listdir(malware_path):
            if not pcap_file.endswith('.pcap'):
                continue
            
            pcap_path = os.path.join(malware_path, pcap_file)
            print(f"Processing {malware_dir}/{pcap_file}...")
            
            packets = extract_packets_scapy(pcap_path, max_packets=300)
            print(f"  Extracted {len(packets)} packets")
            
            for packet in packets:
                sample = create_training_sample(packet, malware_dir)
                all_samples.append(sample)
    
    # Shuffle and split
    random.shuffle(all_samples)
    split_idx = int(len(all_samples) * 0.9)
    train_samples = all_samples[:split_idx]
    test_samples = all_samples[split_idx:]
    
    # Save datasets
    train_file = os.path.join(OUTPUT_DIR, "malware_detection_train.json")
    test_file = os.path.join(OUTPUT_DIR, "malware_detection_test.json")
    labels_file = os.path.join(OUTPUT_DIR, "malware_detection_labels.json")
    
    with open(train_file, 'w') as f:
        json.dump(train_samples, f, indent=2)
    
    with open(test_file, 'w') as f:
        json.dump(test_samples, f, indent=2)
    
    with open(labels_file, 'w') as f:
        json.dump(list(labels), f, indent=2)
    
    print(f"\n=== Dataset Created ===")
    print(f"Total samples: {len(all_samples)}")
    print(f"Train samples: {len(train_samples)}")
    print(f"Test samples: {len(test_samples)}")
    print(f"Labels: {sorted(labels)}")
    print(f"\nSaved to: {OUTPUT_DIR}/")


if __name__ == "__main__":
    process_all_pcaps()

