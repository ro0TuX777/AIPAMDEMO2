#!/usr/bin/env python3
"""
Process all downloaded PCAPs through Zeek and generate training samples.
Then merge with benchmark samples and create balanced train/valid split.
"""
import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from collections import Counter
import random

PCAP_DIR = Path("finetuning/data/raw/modern")
OUTPUT_DIR = Path("finetuning/aipam_gpu_training/data")
CONTAINER = "aipam-backend"

# Training format
SYSTEM_PROMPT = """You are AIPAM (AI-Powered Advanced Packet Analysis for Malware Detection), a specialized AI for analyzing network traffic and detecting malware.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings."""

CATEGORIES = "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft, Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, IcedID, Qakbot, Emotet, TrickBot, Formbook, CobaltStrike, BazarLoader, DarkGate, Ursnif, Pikabot, BumbleBee, Matanbuchus, Astaroth, AgentTesla, Lumma_Stealer, Danabot, SSLoad, Remcos_RAT, Sliver, Latrodectus, NetSupport_RAT, Redline_Stealer, SocGholish, Raccoon, Meduza_Stealer, GuLoader, AsyncRAT, XWorm, XLoader, StealC, RigEK"

def run_zeek_on_pcap(pcap_path: str) -> dict:
    """Run Zeek on a PCAP file via Docker container."""
    pcap_name = os.path.basename(pcap_path)
    
    # Copy PCAP to container
    cmd = f"docker cp '{pcap_path}' {CONTAINER}:/tmp/{pcap_name}"
    subprocess.run(cmd, shell=True, capture_output=True)
    
    # Run Zeek
    zeek_cmd = f"docker exec {CONTAINER} bash -c 'cd /tmp && zeek -r {pcap_name} 2>/dev/null && cat conn.log 2>/dev/null'"
    result = subprocess.run(zeek_cmd, shell=True, capture_output=True, text=True)
    
    # Parse conn.log
    flows = []
    if result.stdout:
        for line in result.stdout.strip().split('\n'):
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 10:
                flows.append({
                    'ts': parts[0],
                    'src_ip': parts[2] if len(parts) > 2 else '',
                    'src_port': parts[3] if len(parts) > 3 else '',
                    'dst_ip': parts[4] if len(parts) > 4 else '',
                    'dst_port': parts[5] if len(parts) > 5 else '',
                    'proto': parts[6] if len(parts) > 6 else '',
                    'service': parts[7] if len(parts) > 7 else '-',
                    'duration': parts[8] if len(parts) > 8 else '0',
                    'bytes': parts[9] if len(parts) > 9 else '0',
                })
    
    # Cleanup
    subprocess.run(f"docker exec {CONTAINER} rm -f /tmp/{pcap_name} /tmp/*.log", shell=True, capture_output=True)
    
    return {'flows': flows, 'flow_count': len(flows)}

def format_flow_for_training(flow: dict) -> str:
    """Format a flow as training input."""
    return f"[{flow.get('proto', 'TCP')}] {flow.get('src_ip', '?')}:{flow.get('src_port', '?')} -> {flow.get('dst_ip', '?')}:{flow.get('dst_port', '?')} | service={flow.get('service', '-')} duration={flow.get('duration', '0')}s bytes={flow.get('bytes', '0')}"

def create_training_sample(flows: list, label: str) -> dict:
    """Create a ChatML training sample."""
    # Format packet data
    packet_data = "\n".join(format_flow_for_training(f) for f in flows[:10])
    
    instruction = f"""Given the following traffic data <packet> that contains protocol fields, traffic features, and payloads. Please conduct the ENCRYPTED MALWARE DETECTION TASK to determine which application category the encrypted benign or malicious traffic belongs to. The categories include '{CATEGORIES}'.
<packet>: {packet_data}"""
    
    output = f"This might be a Malware traffic packet. The category is likely to be recognized as {label}."
    
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": instruction},
            {"role": "assistant", "content": output}
        ]
    }

def main():
    print("=" * 70)
    print("         FULL PCAP PROCESSING & TRAINING DATA GENERATION")
    print("=" * 70)
    
    # 1. Process all PCAPs
    print("\n📁 Step 1: Processing PCAPs through Zeek...")
    new_samples = []
    
    for family_dir in sorted(PCAP_DIR.iterdir()):
        if not family_dir.is_dir():
            continue
        label = family_dir.name
        pcaps = list(family_dir.glob("*.pcap"))
        
        if not pcaps:
            continue
            
        print(f"\n  {label}: {len(pcaps)} PCAPs")
        
        for pcap in pcaps:
            print(f"    Processing {pcap.name}...", end=" ", flush=True)
            result = run_zeek_on_pcap(str(pcap))
            
            if result['flow_count'] > 0:
                # Create multiple samples from different flow windows
                flows = result['flows']
                for i in range(0, min(len(flows), 50), 5):
                    window = flows[i:i+10]
                    if len(window) >= 3:
                        sample = create_training_sample(window, label)
                        new_samples.append(sample)
                print(f"✓ {result['flow_count']} flows -> {min(len(flows)//5, 10)} samples")
            else:
                print("✗ no flows")
    
    print(f"\n  Generated {len(new_samples)} new samples from PCAPs")
    
    # 2. Save new PCAP samples
    pcap_samples_file = OUTPUT_DIR / "pcap_training_samples.jsonl"
    with open(pcap_samples_file, 'w') as f:
        for sample in new_samples:
            f.write(json.dumps(sample) + '\n')
    print(f"  Saved to {pcap_samples_file}")
    
    # 3. Merge all training data
    print("\n📊 Step 2: Merging all training data...")
    all_samples = []
    
    # Load existing training data
    existing_file = OUTPUT_DIR / "new_unified_train.jsonl"
    if existing_file.exists():
        with open(existing_file) as f:
            for line in f:
                all_samples.append(json.loads(line))
        print(f"  Loaded {len(all_samples):,} existing samples")
    
    # Load benchmark samples
    benchmark_file = OUTPUT_DIR / "benchmark_training_samples.jsonl"
    benchmark_count = 0
    if benchmark_file.exists():
        with open(benchmark_file) as f:
            for line in f:
                all_samples.append(json.loads(line))
                benchmark_count += 1
        print(f"  Added {benchmark_count:,} benchmark samples")
    
    # Add new PCAP samples
    all_samples.extend(new_samples)
    print(f"  Added {len(new_samples):,} new PCAP samples")
    print(f"  Total: {len(all_samples):,} samples")
    
    # 4. Shuffle and split
    print("\n📈 Step 3: Creating train/valid split...")
    random.seed(42)
    random.shuffle(all_samples)
    
    split_idx = int(len(all_samples) * 0.95)
    train_samples = all_samples[:split_idx]
    valid_samples = all_samples[split_idx:]
    
    # Save
    train_file = OUTPUT_DIR / "final_train.jsonl"
    valid_file = OUTPUT_DIR / "final_valid.jsonl"
    
    with open(train_file, 'w') as f:
        for s in train_samples:
            f.write(json.dumps(s) + '\n')
    
    with open(valid_file, 'w') as f:
        for s in valid_samples:
            f.write(json.dumps(s) + '\n')
    
    print(f"  Train: {len(train_samples):,} samples -> {train_file}")
    print(f"  Valid: {len(valid_samples):,} samples -> {valid_file}")
    
    # 5. Show label distribution
    print("\n📋 Final Label Distribution:")
    import re
    labels = Counter()
    for s in all_samples:
        for msg in s.get('messages', []):
            if msg['role'] == 'assistant':
                match = re.search(r'recognized as (\w+)', msg['content'])
                if match:
                    labels[match.group(1)] += 1
    
    for label, count in sorted(labels.items(), key=lambda x: -x[1])[:20]:
        print(f"    {label}: {count:,}")
    
    print(f"\n✅ DONE! Ready for training with {len(train_samples):,} train + {len(valid_samples):,} valid samples")

if __name__ == "__main__":
    main()

