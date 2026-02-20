#!/usr/bin/env python3
"""
Generate synthetic benign network traffic training samples.
Creates varied examples of normal traffic patterns to balance the malware-heavy training data.
"""
import json
import random
from pathlib import Path

OUTPUT_DIR = Path("finetuning/data/training")

SYSTEM_PROMPT = """You are AIPAM (AI-Powered Advanced Packet Analysis for Malware Detection), a specialized AI for analyzing network traffic and detecting malware.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings."""

CATEGORIES = "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft, Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, IcedID, Qakbot, Emotet, TrickBot, Formbook, CobaltStrike, BazarLoader, DarkGate, Ursnif, Pikabot, BumbleBee, Matanbuchus, Astaroth, AgentTesla, Lumma_Stealer, Danabot, SSLoad, Remcos_RAT, Sliver, Latrodectus, NetSupport_RAT, Redline_Stealer, SocGholish, Raccoon, Meduza_Stealer, GuLoader, AsyncRAT, XWorm, XLoader, StealC, RigEK, AnglerEK, NuclearEK, ExploitKit, Benign"

# Common benign traffic patterns
TRAFFIC_PATTERNS = {
    'dns': {
        'ports': [53], 'proto': 'udp', 'service': 'dns',
        'desc': 'DNS name resolution', 'states': ['SF', 'S0'],
        'bytes_range': (30, 500), 'dest_ips': ['8.8.8.8', '1.1.1.1', '208.67.222.222', '192.168.1.1']
    },
    'http': {
        'ports': [80], 'proto': 'tcp', 'service': 'http',
        'desc': 'HTTP web browsing', 'states': ['SF', 'S1', 'RSTO'],
        'bytes_range': (200, 50000), 'dest_ips': ['93.184.216.34', '142.250.80.4', '151.101.1.140']
    },
    'https': {
        'ports': [443], 'proto': 'tcp', 'service': 'ssl',
        'desc': 'HTTPS encrypted web traffic', 'states': ['SF', 'S1'],
        'bytes_range': (500, 100000), 'dest_ips': ['172.217.14.99', '31.13.71.36', '17.253.144.10']
    },
    'smtp': {
        'ports': [25, 587], 'proto': 'tcp', 'service': 'smtp',
        'desc': 'SMTP email transmission', 'states': ['SF'],
        'bytes_range': (1000, 30000), 'dest_ips': ['74.125.133.108', '64.233.184.26']
    },
    'imap': {
        'ports': [143, 993], 'proto': 'tcp', 'service': 'imap',
        'desc': 'IMAP email retrieval', 'states': ['SF', 'S1'],
        'bytes_range': (500, 20000), 'dest_ips': ['74.125.133.109', '64.233.184.109']
    },
    'smb': {
        'ports': [445], 'proto': 'tcp', 'service': 'smb',
        'desc': 'SMB file sharing', 'states': ['SF', 'S1'],
        'bytes_range': (1000, 500000), 'dest_ips': ['192.168.1.10', '192.168.1.20', '10.0.0.5']
    },
    'ssh': {
        'ports': [22], 'proto': 'tcp', 'service': 'ssh',
        'desc': 'SSH secure shell', 'states': ['SF', 'S1'],
        'bytes_range': (100, 10000), 'dest_ips': ['192.168.1.100', '10.0.0.1']
    },
    'ntp': {
        'ports': [123], 'proto': 'udp', 'service': 'ntp',
        'desc': 'NTP time synchronization', 'states': ['SF'],
        'bytes_range': (48, 90), 'dest_ips': ['129.6.15.28', '132.163.96.5', 'pool.ntp.org']
    },
    'mysql': {
        'ports': [3306], 'proto': 'tcp', 'service': 'mysql',
        'desc': 'MySQL database queries', 'states': ['SF', 'S1'],
        'bytes_range': (100, 5000), 'dest_ips': ['192.168.1.50', '10.0.0.10']
    },
}

RESPONSE_TEMPLATES = [
    """Classification: Benign

Analysis: This traffic represents normal {desc} activity.

Reasoning:
- Traffic patterns are consistent with legitimate {service} communication
- No indicators of compromise (IOCs) detected
- Standard protocol behavior observed
- Connection states ({states}) are appropriate for {service}

MITRE ATT&CK: N/A - No malicious activity
Risk Level: Low
Recommendation: No action required.""",

    """Classification: Benign

Summary: Legitimate {desc} traffic.

Observations:
- Normal {service} protocol communication
- Expected port usage (port {port})
- Standard connection patterns
- No beaconing or C2 indicators

Assessment: Routine network activity.
MITRE ATT&CK: None applicable
Confidence: High""",

    """Classification: Benign

Traffic Type: {service_upper} ({desc})

Analysis:
- Standard {service} request/response patterns
- Normal byte volume for {service} traffic
- Expected destination (common {service} servers)
- No data exfiltration or tunneling indicators

Conclusion: Normal network traffic - no security concerns.
Risk: Minimal""",
]

def gen_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def gen_flows(pattern, num_flows):
    flows = []
    src_ip = f"192.168.{random.randint(1,10)}.{random.randint(10,250)}"
    for _ in range(num_flows):
        dst_ip = random.choice(pattern['dest_ips'])
        dst_port = random.choice(pattern['ports'])
        src_port = random.randint(49152, 65535)
        orig_b, resp_b = random.randint(*pattern['bytes_range']), random.randint(*pattern['bytes_range'])
        state = random.choice(pattern['states'])
        svc = pattern['service'] if random.random() > 0.3 else '-'
        flows.append(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({pattern['proto']}/{svc}) state={state} bytes={orig_b}/{resp_b}")
    return flows

def gen_sample(pattern_name, pattern, idx):
    flows = gen_flows(pattern, random.randint(5, 20))
    user_msg = f"Analyze this network traffic and classify it.\n\nCategories: {CATEGORIES}\n\nTraffic flows:\n" + "\n".join(flows) + "\n\nProvide classification and analysis."
    template = RESPONSE_TEMPLATES[idx % len(RESPONSE_TEMPLATES)]
    assistant_msg = template.format(
        desc=pattern['desc'], service=pattern['service'], service_upper=pattern['service'].upper(),
        states=', '.join(pattern['states']), port=pattern['ports'][0]
    )
    return {"messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_msg}, {"role": "assistant", "content": assistant_msg}]}

def main():
    samples = []
    for pname, pattern in TRAFFIC_PATTERNS.items():
        for i in range(2000):  # 2000 samples per traffic type for better balance
            samples.append(gen_sample(pname, pattern, i))
    random.shuffle(samples)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUTPUT_DIR / "synthetic_benign.jsonl"
    with open(out, 'w') as f:
        for s in samples:
            f.write(json.dumps(s) + '\n')
    print(f"✅ Generated {len(samples)} synthetic benign samples")
    print(f"📁 Output: {out}")

if __name__ == "__main__":
    main()

