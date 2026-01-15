#!/usr/bin/env python3
"""
Create Fine-tuning Dataset for Ollama/llama3.1:8b

Converts processed training samples into the JSONL format required for
fine-tuning with Unsloth, Axolotl, or direct Ollama fine-tuning.

Output format (ChatML-compatible):
{
    "messages": [
        {"role": "system", "content": "..."},
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "..."}
    ]
}
"""

import json
import random
from pathlib import Path
from typing import Dict, List

# System prompt matching AIPAM's LLM client
SYSTEM_PROMPT = """You are a senior network security analyst and incident responder.

You are given:
- Aggregated network flow summaries
- Protocol summaries (HTTP, DNS, SMB, RDP, SSH, TLS, etc.)
- Signature alerts (Suricata, YARA, IOC matches)
- Optional baseline vs exploit traffic comparisons

Your goals:
1. Identify evidence of attacks, exploitation, malware activity, C2, lateral movement, or data exfiltration.
2. Highlight anomalies not covered by signatures (potential zero-days or novel techniques).
3. Map observed behavior to MITRE ATT&CK techniques where possible.
4. Clearly distinguish between confirmed malicious behavior and suspicious but unconfirmed behavior.
5. Output a structured JSON object in the exact schema requested.

Do not invent facts. Base your conclusions only on the provided data."""


def create_user_prompt(sample: Dict) -> str:
    """Create user prompt from processed sample."""
    data_json = json.dumps({
        "host_summaries": sample.get("host_summaries", []),
        "hostpair_summaries": sample.get("hostpair_summaries", []),
        "flow_count": sample.get("flow_count", 0),
        "anomaly_report": sample.get("anomaly_report", {}), # NEW: Added heuristics
    }, indent=2)

    # Add raw packets for "packet vision"
    packet_strings = sample.get("raw_packet_samples", [])
    packet_data = "\n".join(packet_strings) if packet_strings else "(No raw packets provided)"

    return f"""Analyze the following network traffic data:

Network Flows:
```json
{data_json}
```

Raw Packet Snippets:
{packet_data}

Classify this traffic and provide your analysis as a JSON object with these fields:
- overall_severity: "low" | "medium" | "high" | "critical"
- classification: "normal" | "malicious" | "suspicious"
- attack_type: specific attack type or null if normal
- confidence: 0.0-1.0
- attack_chain: list of attack stages with evidence
- host_findings: list of findings per host
- anomalies: list of detected anomalies
- mitre_techniques_overall: list of MITRE ATT&CK technique objects"""


def create_assistant_response(sample: Dict) -> str:
    """Create ideal assistant response based on sample label."""
    label = sample.get("normalized_label", "normal")
    dataset_type = sample.get("dataset_type", "unknown")

    # Map labels to structured responses
    if label == "normal":
        response = {
            "overall_severity": "low",
            "classification": "normal",
            "attack_type": None,
            "confidence": 0.95,
            "attack_chain": [],
            "host_findings": [],
            "anomalies": [],
            "mitre_techniques_overall": [],
        }
    else:
        severity_map = {
            "malware": "high",
            "botnet": "high",
            "web_attack": "medium",
            "apt": "critical",
            "vpn": "low",
            "tor": "medium",
        }

        attack_descriptions = {
            "malware": ("Malware traffic detected", "T1071", "Application Layer Protocol"),
            "botnet": ("Botnet C2 communication detected", "T1071.001", "Web Protocols"),
            "web_attack": ("Web application attack detected", "T1190", "Exploit Public-Facing Application"),
            "apt": ("Advanced Persistent Threat activity detected", "T1566", "Phishing"),
            "vpn": ("Encrypted VPN tunnel detected", "T1572", "Protocol Tunneling"),
            "tor": ("Tor anonymization network traffic detected", "T1090.003", "Multi-hop Proxy"),
        }

        desc, tech_id, tech_name = attack_descriptions.get(
            dataset_type,
            ("Malicious activity detected", "T1071", "Application Layer Protocol")
        )

        # Use Anomaly Detector's forensic reasoning if available
        anomaly_findings = sample.get("anomaly_report", {}).get("findings", [])
        forensic_evidence = []
        for f in anomaly_findings:
            if f.get("chain_of_thought"):
                forensic_evidence.append(f["chain_of_thought"])
        
        if not forensic_evidence:
            forensic_evidence = [f"Traffic patterns consistent with {dataset_type} behavior"]

        response = {
            "overall_severity": severity_map.get(dataset_type, "medium"),
            "classification": "malicious",
            "attack_type": dataset_type,
            "confidence": 0.90,
            "attack_chain": [{
                "stage": "initial_access" if dataset_type == "apt" else "command_and_control",
                "description": desc,
                "evidence": forensic_evidence[:3], # Use the top 3 reasoning blocks
                "mitre_techniques": [{"id": tech_id, "name": tech_name}],
            }],
            "host_findings": [],
            "anomalies": [{
                "description": f.get("description", f"Detected {dataset_type} anomaly"),
                "related_hosts": f.get("affected_hosts", []),
                "confidence": f.get("confidence", 0.85),
                "reason": f.get("category", "malware"),
            } for f in anomaly_findings[:5]],
            "mitre_techniques_overall": [{"id": tech_id, "name": tech_name}],
        }

    return json.dumps(response, indent=2)


def create_training_sample(sample: Dict) -> Dict:
    """Create a training sample in ChatML format."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": create_user_prompt(sample)},
            {"role": "assistant", "content": create_assistant_response(sample)},
        ]
    }


def convert_trafficllm_sample(sample: Dict) -> Dict:
    """Convert TrafficLLM sample to ChatML format."""
    # TrafficLLM format: {"instruction": "...", "output": "..."}
    instruction = sample.get("instruction", "")
    output = sample.get("output", "")

    # Create a system prompt for traffic analysis
    system_prompt = """You are a network traffic analysis expert. Analyze the provided packet data and classify the traffic type or detect malicious activity. Provide concise, accurate classifications."""

    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": instruction},
            {"role": "assistant", "content": output},
        ]
    }


def main():
    print("=" * 60)
    print("Create Fine-tuning Dataset for llama3.1:8b")
    print("=" * 60)

    training_dir = Path("data/training")
    training_dir.mkdir(parents=True, exist_ok=True)

    all_samples = []

    # Option 1: Load TrafficLLM samples (primary source)
    trafficllm_file = Path("data/processed/trafficllm_samples.jsonl")
    if trafficllm_file.exists():
        print(f"\nLoading TrafficLLM samples from {trafficllm_file}...")
        with open(trafficllm_file) as f:
            for line in f:
                sample = json.loads(line)
                all_samples.append(convert_trafficllm_sample(sample))
        print(f"  ✓ Loaded {len(all_samples):,} TrafficLLM samples")

    # Option 2: Load AIPAM processed samples (if available)
    processed_file = Path("data/processed/processed_samples_v4.jsonl")
    if not processed_file.exists():
        processed_file = Path("data/processed/processed_samples.jsonl")

    if processed_file.exists():
        print(f"\nLoading AIPAM processed samples from {processed_file}...")
        aipam_count = 0
        with open(processed_file) as f:
            for line in f:
                sample = json.loads(line)
                all_samples.append(create_training_sample(sample))
                aipam_count += 1
        print(f"  ✓ Loaded {aipam_count:,} AIPAM samples")

    if not all_samples:
        print("\nError: No training samples found.")
        print("Run one of the following first:")
        print("  - python download_training_data.py --download")
        print("  - python process_training_data.py")
        return

    print(f"\nTotal samples: {len(all_samples):,}")

    # Shuffle and split into train/validation
    random.shuffle(all_samples)
    split_idx = int(len(all_samples) * 0.9)
    train_samples = all_samples[:split_idx]
    val_samples = all_samples[split_idx:]

    # Save training data
    train_file = training_dir / "train.jsonl"
    val_file = training_dir / "validation.jsonl"

    with open(train_file, "w") as f:
        for sample in train_samples:
            f.write(json.dumps(sample) + "\n")

    with open(val_file, "w") as f:
        for sample in val_samples:
            f.write(json.dumps(sample) + "\n")

    print(f"\n✓ Created training set: {len(train_samples):,} samples -> {train_file}")
    print(f"✓ Created validation set: {len(val_samples):,} samples -> {val_file}")

    # Show sample statistics
    print("\n" + "=" * 60)
    print("Sample Preview")
    print("=" * 60)
    if train_samples:
        sample = train_samples[0]
        print(f"User prompt (first 200 chars):")
        print(f"  {sample['messages'][1]['content'][:200]}...")
        print(f"Assistant response:")
        print(f"  {sample['messages'][2]['content'][:100]}...")


if __name__ == "__main__":
    main()

