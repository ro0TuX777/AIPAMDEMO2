#!/usr/bin/env python3
"""
Create Zero-Day Detection Training Dataset

Generates synthetic training examples with chain-of-thought reasoning for:
1. Anomalous beacon patterns (unknown C2)
2. Novel data exfiltration techniques
3. Unusual protocol behaviors
4. Encrypted traffic anomalies
5. DNS-based threats (tunneling, DGA)
6. Unknown RAT communication patterns

These examples train the model to reason about WHY traffic is suspicious
even when it doesn't match known signatures.
"""

import json
import random
from pathlib import Path
from datetime import datetime

# Training format matching Llama 3.1 Instruct
def format_llama_prompt(system: str, user: str, assistant: str) -> str:
    return f"""<|start_header_id|>system<|end_header_id|>

{system}<|eot_id|><|start_header_id|>user<|end_header_id|>

{user}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

{assistant}<|eot_id|>"""

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specialized in zero-day threat detection and forensic network analysis.
When analyzing traffic that doesn't match known malware signatures, you apply chain-of-thought reasoning to identify behavioral indicators of malicious activity.
Your analysis should be methodical, explaining WHY patterns are suspicious even when they're novel."""


# Zero-day scenario templates with chain-of-thought reasoning
ZERO_DAY_SCENARIOS = [
    {
        "name": "Unknown C2 Beacon",
        "packet_data": "flow: 10.0.1.50:52341 -> 185.220.101.42:8443, proto: TLS, bytes_out: 156, bytes_in: 89, interval: 60.2s (15 occurrences), jitter: 0.08, cipher: TLS_CHACHA20_POLY1305",
        "anomaly_context": """## ZERO-DAY ANOMALY DETECTION REPORT
**Zero-Day Likelihood: HIGH** (score: 0.85)
**Behavioral Anomalies Detected: 2**

### Anomaly #1: [HIGH] Beacon
**Description:** Periodic beacon pattern detected: 10.0.1.50->185.220.101.42:8443
**Evidence:** Connection count: 15, Mean interval: 60.2s, Jitter (CV): 8.00%

**Forensic Analysis:**
OBSERVATION: Host 10.0.1.50 is making regular connections to 185.220.101.42:8443
- 15 connections over the analysis period
- Average interval: 60.2 seconds between connections
- Very low timing variance (jitter): 8.00% - this is unusually consistent

WHY THIS IS SUSPICIOUS:
Normal user traffic has high variance in timing (browsing, clicking, etc.)
This pattern shows machine-like precision typical of C2 beacons.""",
        "classification": "Anomalous/Zero-Day",
        "severity": "high",
        "reasoning": """Let me analyze this traffic methodically:

**STEP 1: Pattern Recognition**
I see 15 connections from 10.0.1.50 to 185.220.101.42:8443 with remarkably consistent timing:
- Interval: 60.2 seconds (almost exactly 1 minute)
- Jitter: only 8% variance

This is NOT human behavior. Humans don't click links every 60 seconds with 8% precision.

**STEP 2: Traffic Characteristics**
- Small payload sizes (156 bytes out, 89 bytes in) - typical for heartbeat/beacon
- Using TLS with modern cipher (CHACHA20_POLY1305) - encryption to hide content
- High ephemeral port on client side

**STEP 3: Known Signature Matching**
Checking against known malware families... NO MATCH FOUND.
- Not Zeus (no characteristic HTTP patterns)
- Not Emotet (no HTTPS C2 with specific certificate patterns)
- Not CobaltStrike (interval doesn't match default profiles)

**STEP 4: Conclusion**
This exhibits classic C2 beacon behavior but doesn't match any known family.
The periodic nature with low jitter is a STRONG indicator of automated malicious activity.

CLASSIFICATION: Anomalous/Zero-Day
This is likely a custom or emerging C2 implant that should be treated as HIGH priority.""",
        "attack_chain": [
            {"stage": "command_and_control", "description": "Unknown implant established periodic C2 beacon to 185.220.101.42:8443 with 60-second intervals", "evidence": ["Beacon interval: 60.2s", "Jitter: 8%", "15 connections observed"], "mitre": [{"id": "T1071", "name": "Application Layer Protocol"}, {"id": "T1573", "name": "Encrypted Channel"}]}
        ],
        "mitre": [{"id": "T1071", "name": "Application Layer Protocol"}, {"id": "T1573", "name": "Encrypted Channel"}, {"id": "T1095", "name": "Non-Application Layer Protocol"}]
    },
    {
        "name": "Novel Data Exfiltration",
        "packet_data": "flow: 192.168.1.100:49521 -> 91.134.222.18:443, proto: HTTPS, bytes_out: 45678912, bytes_in: 2341, duration: 847s, POST requests: 127, avg_post_size: 359KB | DNS: api-sync.cloudservices-cdn.net",
        "anomaly_context": """## ZERO-DAY ANOMALY DETECTION REPORT
**Zero-Day Likelihood: HIGH** (score: 0.78)
**Behavioral Anomalies Detected: 2**

### Anomaly #1: [HIGH] Volume
**Description:** High outbound data volume from 192.168.1.100
**Evidence:** Total outbound: 43.56 MB, Unique destinations: 1, Concentrated to single destination - MORE SUSPICIOUS

**Forensic Analysis:**
OBSERVATION: Host 192.168.1.100 sent 43.56 MB of data to a single destination
This is unusual for normal browsing patterns.""",
        "classification": "Anomalous/Zero-Day",
        "severity": "critical",
        "reasoning": """Analyzing this high-volume transfer:

**STEP 1: Volume Analysis**
- 45.6 MB outbound vs only 2.3 KB inbound
- This is a 19,500:1 ratio - EXTREMELY asymmetric
- Normal HTTPS browsing has much more balanced ratios

**STEP 2: Behavioral Analysis**
- 127 POST requests over 14 minutes
- Average POST size: 359KB
- All to a single domain with CDN-like name

**STEP 3: Domain Analysis**
Domain: api-sync.cloudservices-cdn.net
- Looks like a legitimate cloud service name (social engineering)
- But the traffic pattern doesn't match CDN behavior
- CDNs primarily DELIVER content (inbound), not RECEIVE it (outbound)

**STEP 4: Known Signature Check**
- Not matching known stealer exfil patterns
- Not matching known ransomware data staging
- Novel exfiltration method

**STEP 5: Conclusion**
This is large-scale data exfiltration disguised as cloud sync traffic.
The massive outbound volume, asymmetric ratio, and suspicious domain indicate an advanced threat.""",
        "attack_chain": [
            {"stage": "collection", "description": "Data collected from compromised host 192.168.1.100", "evidence": ["45.6 MB staged for exfiltration"], "mitre": [{"id": "T1005", "name": "Data from Local System"}]},
            {"stage": "exfiltration", "description": "Data exfiltrated via HTTPS POST to fake CDN domain", "evidence": ["127 POST requests", "359KB average size", "api-sync.cloudservices-cdn.net"], "mitre": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"id": "T1567", "name": "Exfiltration Over Web Service"}]}
        ],
        "mitre": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"id": "T1567", "name": "Exfiltration Over Web Service"}, {"id": "T1005", "name": "Data from Local System"}]
    },
    {
        "name": "DNS Tunneling",
        "packet_data": "DNS queries from 10.0.2.15: avg_query_length: 78 chars, entropy: 4.2, unique_subdomains: 847, base_domain: update-check.services-api.net, query_rate: 12/min",
        "anomaly_context": """## ZERO-DAY ANOMALY DETECTION REPORT
**Zero-Day Likelihood: MEDIUM** (score: 0.72)
**Behavioral Anomalies Detected: 1**

### Anomaly #1: [HIGH] DNS
**Description:** DNS tunneling indicators from 10.0.2.15
**Evidence:** High entropy subdomains: 4.2, Unique subdomains: 847, Query rate: 12/min

**Forensic Analysis:**
OBSERVATION: Host 10.0.2.15 is making unusual DNS queries
- Very long subdomain names (78 chars average)
- High entropy in subdomain strings (4.2 bits/char)
- 847 unique subdomains to same base domain

WHY THIS IS SUSPICIOUS:
Normal DNS queries are short (google.com, facebook.com)
These queries look like encoded data being tunneled through DNS.""",
        "classification": "Anomalous/Zero-Day",
        "severity": "high",
        "reasoning": """DNS traffic analysis:

**STEP 1: Query Pattern Analysis**
- Average query length: 78 characters (normal is ~15-25)
- 847 unique subdomains to ONE base domain
- Query rate: 12/minute (sustained)

**STEP 2: Entropy Analysis**
- Subdomain entropy: 4.2 bits/character
- This is HIGH - indicates encoded/encrypted data
- Normal subdomains (www, mail, api) have LOW entropy

**STEP 3: Base Domain Analysis**
Domain: update-check.services-api.net
- Designed to look legitimate
- But no legitimate service generates 847 unique subdomains

**STEP 4: Known Tunnel Detection**
- Not matching Iodine DNS tunnel signatures
- Not matching DNScat2 patterns
- Novel DNS tunneling implementation

**STEP 5: Conclusion**
This is DNS tunneling for data exfiltration or C2 communication.
The high entropy, query volume, and subdomain count are definitive indicators.""",
        "attack_chain": [
            {"stage": "command_and_control", "description": "DNS tunneling established for covert C2 channel", "evidence": ["847 unique subdomains", "High entropy: 4.2", "12 queries/min"], "mitre": [{"id": "T1071.004", "name": "DNS"}, {"id": "T1572", "name": "Protocol Tunneling"}]}
        ],
        "mitre": [{"id": "T1071.004", "name": "DNS"}, {"id": "T1572", "name": "Protocol Tunneling"}, {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"}]
    },
    {
        "name": "Encrypted Payload Anomaly",
        "packet_data": "flow: 172.16.5.20:51234 -> 45.33.32.156:443, TLS_version: 1.3, cipher: TLS_AES_256_GCM_SHA384, cert_issuer: Let's Encrypt, cert_age: 2 days, SNI: cdn-static-assets.com, JA3: 771,4866-4867-4865-49196-49200,29-23-24-25,0, JA3S: 771,4866,0",
        "anomaly_context": """## ZERO-DAY ANOMALY DETECTION REPORT
**Zero-Day Likelihood: MEDIUM** (score: 0.65)
**Behavioral Anomalies Detected: 1**

### Anomaly #1: [MEDIUM] TLS
**Description:** Suspicious TLS characteristics to 45.33.32.156
**Evidence:** Certificate age: 2 days, JA3 fingerprint unusual, SNI mismatch suspected

**Forensic Analysis:**
OBSERVATION: TLS connection with suspicious certificate
- Very new certificate (2 days old)
- JA3 fingerprint doesn't match common browsers
- SNI claims to be CDN but behavior doesn't match""",
        "classification": "Anomalous/Zero-Day",
        "severity": "medium",
        "reasoning": """TLS traffic analysis:

**STEP 1: Certificate Analysis**
- Issuer: Let's Encrypt (free, easy to obtain)
- Age: 2 days (very new - potential indicator)
- Attackers often use fresh certs to avoid reputation blocks

**STEP 2: JA3 Fingerprint Analysis**
JA3: 771,4866-4867-4865-49196-49200,29-23-24-25,0
- This doesn't match Chrome, Firefox, or Edge fingerprints
- Suggests custom TLS client (malware, tool, or script)

**STEP 3: SNI Analysis**
SNI: cdn-static-assets.com
- Generic CDN-like name (social engineering)
- But JA3 doesn't match CDN client libraries

**STEP 4: Known Malware TLS Check**
- Not matching CobaltStrike default JA3
- Not matching Metasploit HTTPS stager
- Novel TLS implementation

**STEP 5: Conclusion**
This is likely a custom C2 channel using TLS for encryption.
The combination of new cert, unusual JA3, and generic SNI is suspicious.""",
        "attack_chain": [
            {"stage": "command_and_control", "description": "Encrypted C2 channel established with suspicious TLS characteristics", "evidence": ["2-day-old certificate", "Non-browser JA3 fingerprint", "Generic CDN SNI"], "mitre": [{"id": "T1573.002", "name": "Asymmetric Cryptography"}, {"id": "T1071.001", "name": "Web Protocols"}]}
        ],
        "mitre": [{"id": "T1573.002", "name": "Asymmetric Cryptography"}, {"id": "T1071.001", "name": "Web Protocols"}]
    },
]


def generate_training_example(scenario: dict) -> dict:
    """Generate a single training example from a scenario."""

    # Build the user prompt with anomaly context
    user_prompt = f"""Conduct a detailed ZERO-DAY FORENSIC ANALYSIS on the following traffic data.
Identify if this traffic is Benign or Malicious.

If malicious:
1. Identify the likely malware family if it matches known signatures.
2. If it doesn't match known signatures but shows malicious behavior, classify as 'Anomalous/Zero-Day'.

<packet>: {scenario['packet_data']}
{scenario['anomaly_context']}

Provide your analysis with chain-of-thought reasoning, then give findings in JSON format."""

    # Build the assistant response with reasoning + JSON
    json_output = {
        "classification": scenario["classification"],
        "overall_severity": scenario["severity"],
        "attack_chain": scenario["attack_chain"],
        "host_findings": [],
        "anomalies": [{
            "description": f"{scenario['name']} detected",
            "related_hosts": [],
            "confidence": 0.85,
            "reason": scenario["reasoning"].split("**STEP 5: Conclusion**")[-1].strip() if "**STEP 5: Conclusion**" in scenario["reasoning"] else "Behavioral analysis indicates novel threat"
        }],
        "mitre_techniques_overall": scenario["mitre"]
    }

    assistant_response = f"""{scenario['reasoning']}

```json
{json.dumps(json_output, indent=2)}
```"""

    return {
        "text": format_llama_prompt(SYSTEM_PROMPT, user_prompt, assistant_response),
        "scenario_name": scenario["name"],
        "classification": scenario["classification"]
    }


def create_dataset(output_dir: str = "zero_day_training_data"):
    """Create the zero-day training dataset."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    examples = []

    # Generate examples from each scenario
    for scenario in ZERO_DAY_SCENARIOS:
        example = generate_training_example(scenario)
        examples.append(example)
        print(f"Generated: {scenario['name']}")

    # Save as JSONL for training
    jsonl_path = output_path / "zero_day_cot_training.jsonl"
    with open(jsonl_path, "w") as f:
        for ex in examples:
            f.write(json.dumps({"text": ex["text"]}) + "\n")

    print(f"\nSaved {len(examples)} training examples to {jsonl_path}")

    # Also save a readable version
    readable_path = output_path / "zero_day_examples_readable.json"
    with open(readable_path, "w") as f:
        json.dump(examples, f, indent=2)

    print(f"Saved readable version to {readable_path}")

    return examples


if __name__ == "__main__":
    create_dataset()

