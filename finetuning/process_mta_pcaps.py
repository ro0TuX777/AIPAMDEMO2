#!/usr/bin/env python3
"""
Process MTA (Malware Traffic Analysis) training exercise PCAPs through Zeek/Suricata
and generate training samples for AIPAM fine-tuning.
"""
import os
import json
import subprocess
import tempfile
import re
import random
from pathlib import Path
from collections import Counter
from typing import Optional, Dict, List, Tuple

# Paths
MTA_DIR = Path("finetuning/data/raw/training_exercises/pages")
MANIFEST_PATH = Path("finetuning/data/raw/training_exercises/manifest.jsonl")
OUTPUT_DIR = Path("finetuning/data/training")
CONTAINER_BACKEND = "aipam-backend"
CONTAINER_WORKER = "aipam-worker"

# Training format
SYSTEM_PROMPT = """You are AIPAM (AI-Powered Advanced Packet Analysis for Malware Detection), a specialized AI for analyzing network traffic and detecting malware.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings."""

CATEGORIES = "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft, Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, IcedID, Qakbot, Emotet, TrickBot, Formbook, CobaltStrike, BazarLoader, DarkGate, Ursnif, Pikabot, BumbleBee, Matanbuchus, Astaroth, AgentTesla, Lumma_Stealer, Danabot, SSLoad, Remcos_RAT, Sliver, Latrodectus, NetSupport_RAT, Redline_Stealer, SocGholish, Raccoon, Meduza_Stealer, GuLoader, AsyncRAT, XWorm, XLoader, StealC, RigEK, AnglerEK, NuclearEK, ExploitKit"

# Malware family patterns to extract from exercise titles/content
MALWARE_PATTERNS = {
    r'\b(emotet)\b': 'Emotet',
    r'\b(trickbot)\b': 'TrickBot',
    r'\b(qakbot|qbot)\b': 'Qakbot',
    r'\b(dridex)\b': 'Dridex',
    r'\b(ursnif|gozi)\b': 'Ursnif',
    r'\b(icedid)\b': 'IcedID',
    r'\b(bazarloader|bazar)\b': 'BazarLoader',
    r'\b(cobalt\s*strike)\b': 'CobaltStrike',
    r'\b(hancitor)\b': 'Hancitor',
    r'\b(lokibot)\b': 'Lokibot',
    r'\b(formbook)\b': 'Formbook',
    r'\b(agent\s*tesla)\b': 'AgentTesla',
    r'\b(remcos)\b': 'Remcos_RAT',
    r'\b(nanocore)\b': 'Nanocore',
    r'\b(njrat)\b': 'NjRAT',
    r'\b(cryptowall)\b': 'CryptoWall',
    r'\b(locky)\b': 'Locky',
    r'\b(cerber)\b': 'Cerber',
    r'\b(gandcrab)\b': 'GandCrab',
    r'\b(ryuk)\b': 'Ryuk',
    r'\b(angler\s*e[xk])\b': 'AnglerEK',
    r'\b(rig\s*e[xk])\b': 'RigEK',
    r'\b(magnitude\s*e[xk])\b': 'MagnitudeEK',
    r'\b(nuclear\s*e[xk])\b': 'NuclearEK',
    r'\b(exploit\s*kit|ek\s+activity|ek\s+traffic)\b': 'ExploitKit',
}


def extract_label_from_title(title: str) -> str:
    """Extract malware family label from exercise title."""
    title_lower = title.lower()
    for pattern, label in MALWARE_PATTERNS.items():
        if re.search(pattern, title_lower, re.IGNORECASE):
            return label
    # Default to generic malware if EK-related
    if 'ek' in title_lower or 'exploit' in title_lower:
        return 'ExploitKit'
    return 'Malware'


def load_manifest() -> Dict[str, dict]:
    """Load manifest and create mapping from directory to exercise info."""
    manifest = {}
    if MANIFEST_PATH.exists():
        with open(MANIFEST_PATH) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    saved_dir = entry.get('saved_dir', '')
                    if saved_dir:
                        # Extract just the directory name
                        dir_name = Path(saved_dir).name
                        manifest[dir_name] = entry
    return manifest


def run_zeek_on_pcap(pcap_path: str) -> dict:
    """Run Zeek on a PCAP file via Docker container."""
    pcap_name = os.path.basename(pcap_path)
    unique_id = random.randint(10000, 99999)
    container_dir = f"/tmp/zeek_{unique_id}"
    
    try:
        # Create temp dir in container
        subprocess.run(["docker", "exec", CONTAINER_BACKEND, "mkdir", "-p", container_dir], 
                      check=True, capture_output=True)
        
        # Copy PCAP to container
        subprocess.run(["docker", "cp", pcap_path, f"{CONTAINER_BACKEND}:{container_dir}/input.pcap"],
                      check=True, capture_output=True)
        
        # Run Zeek with JSON output
        zeek_cmd = f"cd {container_dir} && zeek -r input.pcap LogAscii::use_json=T 2>/dev/null"
        subprocess.run(["docker", "exec", CONTAINER_BACKEND, "bash", "-c", zeek_cmd],
                      check=True, capture_output=True)
        
        # Read conn.log
        result = subprocess.run(
            ["docker", "exec", CONTAINER_BACKEND, "cat", f"{container_dir}/conn.log"],
            capture_output=True, text=True
        )
        
        flows = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip() and not line.startswith('#'):
                    try:
                        flow = json.loads(line)
                        flows.append({
                            'ts': flow.get('ts', ''),
                            'src_ip': flow.get('id.orig_h', ''),
                            'src_port': str(flow.get('id.orig_p', '')),
                            'dst_ip': flow.get('id.resp_h', ''),
                            'dst_port': str(flow.get('id.resp_p', '')),
                            'proto': flow.get('proto', 'tcp').upper(),
                            'service': flow.get('service', '-') or '-',
                            'duration': str(flow.get('duration', 0) or 0),
                            'bytes': str((flow.get('orig_bytes', 0) or 0) + (flow.get('resp_bytes', 0) or 0)),
                        })
                    except json.JSONDecodeError:
                        continue
        
        return {'flows': flows, 'flow_count': len(flows)}
        
    finally:
        # Cleanup
        subprocess.run(["docker", "exec", CONTAINER_BACKEND, "rm", "-rf", container_dir],
                      capture_output=True)


def run_suricata_on_pcap(pcap_path: str) -> List[dict]:
    """Run Suricata on a PCAP file via Docker container."""
    pcap_name = os.path.basename(pcap_path)
    unique_id = random.randint(10000, 99999)
    container_dir = f"/tmp/suricata_{unique_id}"
    
    alerts = []
    try:
        # Create temp dir in container
        subprocess.run(["docker", "exec", CONTAINER_WORKER, "mkdir", "-p", container_dir],
                      check=True, capture_output=True)
        
        # Copy PCAP to container
        subprocess.run(["docker", "cp", pcap_path, f"{CONTAINER_WORKER}:{container_dir}/input.pcap"],
                      check=True, capture_output=True)
        
        # Run Suricata
        suri_cmd = f"cd {container_dir} && suricata -r input.pcap -l . -k none 2>/dev/null"
        subprocess.run(["docker", "exec", CONTAINER_WORKER, "bash", "-c", suri_cmd],
                      capture_output=True, timeout=120)
        
        # Read eve.json
        result = subprocess.run(
            ["docker", "exec", CONTAINER_WORKER, "cat", f"{container_dir}/eve.json"],
            capture_output=True, text=True
        )
        
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            alerts.append({
                                'signature': event.get('alert', {}).get('signature', ''),
                                'category': event.get('alert', {}).get('category', ''),
                                'severity': event.get('alert', {}).get('severity', 0),
                            })
                    except json.JSONDecodeError:
                        continue
    except subprocess.TimeoutExpired:
        print("  [Suricata timeout]", end="")
    except Exception as e:
        print(f"  [Suricata error: {e}]", end="")
    finally:
        subprocess.run(["docker", "exec", CONTAINER_WORKER, "rm", "-rf", container_dir],
                      capture_output=True)
    
    return alerts


def format_flow_for_training(flow: dict) -> str:
    """Format a flow as training input."""
    return f"[{flow.get('proto', 'TCP')}] {flow.get('src_ip', '?')}:{flow.get('src_port', '?')} -> {flow.get('dst_ip', '?')}:{flow.get('dst_port', '?')} | service={flow.get('service', '-')} duration={flow.get('duration', '0')}s bytes={flow.get('bytes', '0')}"


def create_training_sample(flows: list, alerts: list, label: str, exercise_title: str) -> dict:
    """Create a ChatML training sample."""
    # Format packet data
    packet_data = "\n".join(format_flow_for_training(f) for f in flows[:10])

    # Add alert info if available
    alert_info = ""
    if alerts:
        unique_sigs = list(set(a['signature'] for a in alerts[:5]))
        alert_info = f"\nSuricata alerts: {', '.join(unique_sigs[:3])}"

    instruction = f"""Given the following traffic data <packet> that contains protocol fields, traffic features, and payloads. Please conduct the ENCRYPTED MALWARE DETECTION TASK to determine which application category the encrypted benign or malicious traffic belongs to. The categories include '{CATEGORIES}'.
<packet>: {packet_data}{alert_info}"""

    output = f"This might be a Malware traffic packet. The category is likely to be recognized as {label}."

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": instruction},
            {"role": "assistant", "content": output}
        ],
        "metadata": {
            "source": "mta_pcap",
            "exercise": exercise_title,
            "label": label
        }
    }


def find_unique_pcaps() -> List[Tuple[Path, str]]:
    """Find all unique MTA PCAPs (prefer pcaps/ over assets_extracted/)."""
    manifest = load_manifest()
    pcap_map = {}  # exercise_dir -> (pcap_path, label)

    for exercise_dir in sorted(MTA_DIR.iterdir()):
        if not exercise_dir.is_dir():
            continue

        dir_name = exercise_dir.name

        # Get label from manifest title
        label = 'Malware'
        if dir_name in manifest:
            title = manifest[dir_name].get('title', '')
            label = extract_label_from_title(title)

        # Find PCAPs - prefer pcaps/ directory
        pcaps_dir = exercise_dir / "pcaps"
        assets_dir = exercise_dir / "assets_extracted"

        pcap_files = []
        if pcaps_dir.exists():
            pcap_files = list(pcaps_dir.glob("*.pcap")) + list(pcaps_dir.glob("*.pcapng"))
        elif assets_dir.exists():
            pcap_files = list(assets_dir.glob("*.pcap")) + list(assets_dir.glob("*.pcapng"))

        for pcap in pcap_files:
            # Use first PCAP found per exercise
            if dir_name not in pcap_map:
                pcap_map[dir_name] = (pcap, label, manifest.get(dir_name, {}).get('title', dir_name))

    return [(p, l, t) for p, l, t in pcap_map.values()]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Process MTA PCAPs into training data")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of PCAPs to process")
    parser.add_argument("--output", type=str, default="mta_pcap_samples.jsonl", help="Output filename")
    args = parser.parse_args()

    print("=" * 70)
    print("         MTA PCAP PROCESSING FOR AIPAM TRAINING")
    print("=" * 70)

    # Find unique PCAPs
    print("\n📁 Finding unique MTA PCAPs...")
    pcaps = find_unique_pcaps()
    print(f"  Found {len(pcaps)} unique PCAPs")

    if args.limit:
        pcaps = pcaps[:args.limit]
        print(f"  Limiting to {args.limit} PCAPs")

    # Show label distribution
    labels = Counter(label for _, label, _ in pcaps)
    print("\n📊 Label distribution:")
    for label, count in labels.most_common(10):
        print(f"    {label}: {count}")

    # Process PCAPs
    print("\n🔄 Processing PCAPs through Zeek/Suricata...")
    all_samples = []
    success_count = 0
    fail_count = 0

    for i, (pcap_path, label, title) in enumerate(pcaps, 1):
        print(f"  [{i}/{len(pcaps)}] {pcap_path.name} ({label})...", end=" ", flush=True)

        try:
            # Run Zeek
            zeek_result = run_zeek_on_pcap(str(pcap_path))
            flows = zeek_result['flows']

            if not flows:
                print("✗ no flows")
                fail_count += 1
                continue

            # Run Suricata
            alerts = run_suricata_on_pcap(str(pcap_path))

            # Create training samples from flow windows
            samples_created = 0
            for j in range(0, min(len(flows), 50), 5):
                window = flows[j:j+10]
                if len(window) >= 3:
                    sample = create_training_sample(window, alerts, label, title)
                    all_samples.append(sample)
                    samples_created += 1

            print(f"✓ {len(flows)} flows, {len(alerts)} alerts -> {samples_created} samples")
            success_count += 1

        except Exception as e:
            print(f"✗ error: {e}")
            fail_count += 1

    # Save samples
    output_path = OUTPUT_DIR / args.output
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')

    print(f"\n✅ DONE!")
    print(f"  Processed: {success_count} PCAPs successfully, {fail_count} failed")
    print(f"  Generated: {len(all_samples)} training samples")
    print(f"  Saved to: {output_path}")

    # Final label distribution
    print("\n📋 Final sample label distribution:")
    sample_labels = Counter()
    for s in all_samples:
        sample_labels[s.get('metadata', {}).get('label', 'unknown')] += 1
    for label, count in sample_labels.most_common():
        print(f"    {label}: {count}")


if __name__ == "__main__":
    main()

