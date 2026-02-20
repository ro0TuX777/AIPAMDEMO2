#!/usr/bin/env python3
"""
Process benign (normal) network traffic PCAPs through Zeek/Suricata
and generate training samples labeled as 'Benign' for AIPAM fine-tuning.
"""
import os
import json
import subprocess
import tempfile
import re
from pathlib import Path
from typing import List

# Paths
BENIGN_DIR = Path("finetuning/data/raw/benign")
OUTPUT_DIR = Path("finetuning/data/training")
CONTAINER_BACKEND = "aipam-backend"
CONTAINER_WORKER = "aipam-worker"

# Training format
SYSTEM_PROMPT = """You are AIPAM (AI-Powered Advanced Packet Analysis for Malware Detection), a specialized AI for analyzing network traffic and detecting malware.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings."""

CATEGORIES = "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft, Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, IcedID, Qakbot, Emotet, TrickBot, Formbook, CobaltStrike, BazarLoader, DarkGate, Ursnif, Pikabot, BumbleBee, Matanbuchus, Astaroth, AgentTesla, Lumma_Stealer, Danabot, SSLoad, Remcos_RAT, Sliver, Latrodectus, NetSupport_RAT, Redline_Stealer, SocGholish, Raccoon, Meduza_Stealer, GuLoader, AsyncRAT, XWorm, XLoader, StealC, RigEK, AnglerEK, NuclearEK, ExploitKit, Benign"


def process_pcap_with_zeek(pcap_path: Path) -> dict:
    """Process PCAP with Zeek inside Docker container."""
    host_path = pcap_path.resolve()
    filename = pcap_path.name
    
    # Create temp dir inside container and copy pcap
    cmd = f"""docker exec {CONTAINER_BACKEND} bash -c '
        mkdir -p /tmp/benign_pcap &&
        cd /tmp/benign_pcap &&
        rm -rf * 2>/dev/null || true
    '"""
    subprocess.run(cmd, shell=True, capture_output=True)
    
    # Copy pcap to container
    subprocess.run(
        f"docker cp {host_path} {CONTAINER_BACKEND}:/tmp/benign_pcap/{filename}",
        shell=True, capture_output=True
    )
    
    # Run Zeek
    zeek_cmd = f"""docker exec {CONTAINER_BACKEND} bash -c '
        cd /tmp/benign_pcap &&
        /opt/zeek/bin/zeek -r "{filename}" local 2>/dev/null
    '"""
    subprocess.run(zeek_cmd, shell=True, capture_output=True)
    
    # Read conn.log
    read_cmd = f"docker exec {CONTAINER_BACKEND} cat /tmp/benign_pcap/conn.log 2>/dev/null"
    result = subprocess.run(read_cmd, shell=True, capture_output=True, text=True)
    
    return {"conn_log": result.stdout if result.returncode == 0 else ""}


def parse_zeek_conn_log(conn_log: str) -> List[dict]:
    """Parse Zeek conn.log into flow records."""
    flows = []
    if not conn_log:
        return flows
    
    for line in conn_log.split('\n'):
        if line.startswith('#') or not line.strip():
            continue
        fields = line.split('\t')
        if len(fields) >= 15:
            flows.append({
                "ts": fields[0],
                "src_ip": fields[2],
                "src_port": fields[3], 
                "dst_ip": fields[4],
                "dst_port": fields[5],
                "proto": fields[6],
                "service": fields[7] if fields[7] != '-' else '',
                "duration": fields[8],
                "orig_bytes": fields[9],
                "resp_bytes": fields[10],
                "conn_state": fields[11],
            })
    return flows


import random

# Protocol descriptions for more varied responses
PROTOCOL_DESCRIPTIONS = {
    'dns': ('DNS', 'Domain Name System lookups', 'name resolution'),
    'http': ('HTTP', 'web browsing', 'HTTP web traffic'),
    'https': ('HTTPS', 'encrypted web traffic', 'secure web browsing'),
    'smtp': ('SMTP', 'email transmission', 'mail server communication'),
    'imap': ('IMAP', 'email retrieval', 'mailbox synchronization'),
    'ftp': ('FTP', 'file transfer', 'FTP data exchange'),
    'ssh': ('SSH', 'secure shell session', 'encrypted remote access'),
    'telnet': ('Telnet', 'remote terminal access', 'terminal session'),
    'smb': ('SMB', 'file sharing', 'Windows network share access'),
    'ldap': ('LDAP', 'directory service queries', 'directory lookups'),
    'mysql': ('MySQL', 'database queries', 'MySQL database communication'),
    'nfs': ('NFS', 'network file system access', 'remote file operations'),
    'dhcp': ('DHCP', 'IP address assignment', 'network configuration'),
    'ospf': ('OSPF', 'routing protocol exchange', 'router communication'),
    'bgp': ('BGP', 'border gateway protocol', 'inter-AS routing'),
    'snmp': ('SNMP', 'network management', 'device monitoring'),
    'radius': ('RADIUS', 'authentication', 'network access control'),
}

# Response templates for variety
RESPONSE_TEMPLATES = [
    """Classification: Benign

Analysis:
This traffic represents normal {desc} network activity.

Reasoning:
- Traffic patterns are consistent with legitimate network communication
- No indicators of compromise (IOCs) detected
- No suspicious payload or command-and-control patterns
- Flow characteristics match expected behavior for {proto} protocol

MITRE ATT&CK: N/A - No malicious activity detected

Risk Level: Low
Recommendation: No action required - normal network traffic.""",

    """Classification: Benign

Summary: Normal {desc} traffic observed.

Key Observations:
- {proto} protocol communication following standard patterns
- Connection states are appropriate ({conn_states})
- Traffic volume is within normal parameters
- No beaconing or anomalous timing patterns detected

Assessment: This appears to be legitimate {desc2} with no signs of malicious activity.

MITRE ATT&CK Techniques: None identified
Confidence: High""",

    """Classification: Benign

Traffic Type: {proto} ({desc})

Analysis Summary:
The captured traffic shows typical {desc2} behavior:
- Standard protocol handshakes observed
- Normal request/response patterns
- Expected port usage ({ports})
- No encrypted C2 channels or data exfiltration indicators

Conclusion: Legitimate network traffic - no security concerns.

Risk Assessment: Minimal
MITRE ATT&CK: Not applicable""",
]


def format_training_sample(pcap_name: str, flows: List[dict], protocol_hint: str = "", sample_idx: int = 0) -> dict:
    """Format flows into ChatML training sample with variety."""
    # Build flow summary
    flow_lines = []
    conn_states = set()
    ports = set()

    # For variety, skip some flows based on sample_idx
    start_idx = (sample_idx * 5) % max(1, len(flows) - 10)
    selected_flows = flows[start_idx:start_idx + 15 + (sample_idx % 5)]

    for f in selected_flows[:20]:
        line = f"{f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} ({f['proto']}"
        if f['service']:
            line += f"/{f['service']}"
        line += f") state={f['conn_state']} bytes={f['orig_bytes']}/{f['resp_bytes']}"
        flow_lines.append(line)
        conn_states.add(f['conn_state'])
        ports.add(f['dst_port'])

    flows_text = "\n".join(flow_lines)

    user_msg = f"""Analyze this network traffic and classify it.

Categories: {CATEGORIES}

Traffic flows:
{flows_text}

Provide classification and analysis."""

    # Determine protocol from service or filename
    protocol_key = None
    for f in selected_flows:
        if f['service']:
            service_lower = f['service'].lower()
            for key in PROTOCOL_DESCRIPTIONS:
                if key in service_lower:
                    protocol_key = key
                    break
        if protocol_key:
            break

    if not protocol_key:
        fname_lower = pcap_name.lower()
        for key in PROTOCOL_DESCRIPTIONS:
            if key in fname_lower:
                protocol_key = key
                break

    if protocol_key and protocol_key in PROTOCOL_DESCRIPTIONS:
        proto, desc, desc2 = PROTOCOL_DESCRIPTIONS[protocol_key]
    else:
        proto = protocol_hint or pcap_name.replace('.pcap', '').replace('.cap', '').replace('.pcapng', '').replace('_', ' ')
        desc = f"{proto} communication"
        desc2 = f"{proto} activity"

    # Select template based on sample_idx for variety
    template = RESPONSE_TEMPLATES[sample_idx % len(RESPONSE_TEMPLATES)]

    assistant_msg = template.format(
        proto=proto,
        desc=desc,
        desc2=desc2,
        conn_states=', '.join(sorted(conn_states)[:3]),
        ports=', '.join(sorted(ports)[:5])
    )

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg}
        ]
    }


def calculate_samples_per_pcap(num_flows: int) -> int:
    """Calculate how many training samples to generate based on flow count."""
    if num_flows <= 5:
        return 3  # Small PCAPs get 3 variations
    elif num_flows <= 20:
        return 5  # Medium PCAPs get 5 variations
    elif num_flows <= 50:
        return 10  # Larger PCAPs get 10 variations
    elif num_flows <= 100:
        return 20  # Large PCAPs get 20 variations
    else:
        return 50  # Very large PCAPs (like SMB) get 50 variations


def main():
    print("=" * 60)
    print("AIPAM Benign PCAP Processor (Enhanced)")
    print("=" * 60)

    # Find all PCAPs
    pcaps = []
    for ext in ['*.pcap', '*.cap', '*.pcapng']:
        pcaps.extend(BENIGN_DIR.rglob(ext))

    print(f"\nFound {len(pcaps)} benign PCAP files\n")

    samples = []
    total_flows = 0

    for pcap in pcaps:
        print(f"Processing: {pcap.name}...", end=" ", flush=True)

        result = process_pcap_with_zeek(pcap)
        flows = parse_zeek_conn_log(result.get("conn_log", ""))

        if flows:
            total_flows += len(flows)
            num_samples = calculate_samples_per_pcap(len(flows))

            for i in range(num_samples):
                sample = format_training_sample(pcap.name, flows, sample_idx=i)
                samples.append(sample)

            print(f"✓ ({len(flows)} flows → {num_samples} samples)")
        else:
            print("✗ (no flows)")

    # Save samples
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / "benign_samples.jsonl"
    with open(output_file, 'w') as f:
        for s in samples:
            f.write(json.dumps(s) + '\n')

    print(f"\n{'=' * 60}")
    print(f"📊 Total flows processed: {total_flows}")
    print(f"✅ Generated {len(samples)} benign training samples")
    print(f"📁 Output: {output_file}")


if __name__ == "__main__":
    main()

