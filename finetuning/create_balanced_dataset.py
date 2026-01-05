#!/usr/bin/env python3
"""
Create a balanced dataset with equal samples per class for better training.
This script merges legacy TrafficLLM data (instruction/output) with 
modern AIPAM data (metrics+packets -> instruction/output).
"""

import json
import random
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

SYSTEM_PROMPT = """You are a senior network security analyst and incident responder.

You are given:
- Aggregated network flow summaries
- Protocol summaries (HTTP, DNS, SMB, RDP, SSH, TLS, etc.)
- Signature alerts (Suricata, YARA, IOC matches)
- Optional baseline vs exploit traffic comparisons
- Raw packet snippets for deep verification

Your goals:
1. Identify evidence of attacks, exploitation, malware activity, C2, lateral movement, or data exfiltration.
2. Highlight anomalies not covered by signatures (potential zero-days or novel techniques).
3. Map observed behavior to MITRE ATT&CK techniques where possible.
4. Clearly distinguish between confirmed malicious behavior and suspicious but unconfirmed behavior.
5. Output a structured JSON object in the exact schema requested.

Do not invent facts. Base your conclusions only on the provided data."""

# Dataset configurations
DATASETS = [
    {
        "path": "data/trafficllm_datasets/ustc-tfc-2016/ustc-tfc-2016_detection_packet_train.json",
        "task": "Malware Detection",
        "type": "legacy",
        "samples_per_class": 100,  # Keep legacy low to maintain modern focus
    },
    {
        "path": "data/trafficllm_datasets/iscx-vpn-2016/iscx-vpn-2016_detection_packet_train.json",
        "task": "VPN Detection",
        "type": "legacy",
        "samples_per_class": 100,
    },
    {
        "path": "data/trafficllm_datasets/iscx-tor-2016/iscx-tor-2016_detection_packet_train.json",
        "task": "Tor Detection",
        "type": "legacy",
        "samples_per_class": 100,
    },
    # NEW: Modern Families
    {
        "path": "data/processed/processed_samples.jsonl",
        "task": "Modern Malware Detection",
        "type": "modern",
        "samples_per_class": 2000, 
    },
]


def create_user_prompt(sample: Dict) -> str:
    """Create user prompt from processed sample (Modern Format)."""
    # 1. JSON Context
    data_json = json.dumps({
        "host_summaries": sample.get("host_summaries", []),
        "hostpair_summaries": sample.get("hostpair_summaries", []),
        "flow_count": sample.get("flow_count", 0),
    }, indent=2)

    # 2. Raw Packets
    packet_strings = sample.get("raw_packet_samples", [])
    packet_data = "\n".join(packet_strings) if packet_strings else "(No raw packets provided)"

    return f"""Analyze the following network traffic data:

Network Flows:
```json
{data_json}
```

Raw Packet Snipets:
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
    """Create ideal assistant response based on sample label (Modern Format)."""
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
        # Default templates for types
        severity_map = {"malware": "high", "botnet": "high", "apt": "critical"}
        
        response = {
            "overall_severity": severity_map.get(dataset_type, "high"),
            "classification": "malicious",
            "attack_type": label if label != "malware" else dataset_type,
            "confidence": 0.95,
            "attack_chain": [{
                "stage": "execution",
                "description": f"Traffic consistent with {label} behavior",
                "evidence": [f"Observed characteristic flows for {label}"],
                "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}],
            }],
            "host_findings": [], # Filled in by model ideally, but empty for training template is fine
            "anomalies": [{
                "description": f"Detected {label} traffic signatures",
                "related_hosts": [],
                "confidence": 0.95,
                "reason": f"Matches known {label} patterns",
            }],
            "mitre_techniques_overall": [{"id": "T1071", "name": "Application Layer Protocol"}],
        }

    return json.dumps(response, indent=2)


def load_and_balance_dataset(ds_config):
    """Load dataset, convert if needed, and balance by class."""
    filepath = Path(ds_config["path"])
    samples_per_class = ds_config["samples_per_class"]
    ds_type = ds_config["type"]
    
    samples_by_class = defaultdict(list)
    
    if not filepath.exists():
        print(f"  [Skipped] File not found: {filepath}")
        return []

    print(f"  Loading {filepath.name} ({ds_type})...")
    
    with open(filepath) as f:
        # Check explicit legacy list format (some ISCX files are big JSON lists)
        first_char = f.read(1)
        f.seek(0)
        
        if first_char == '[':
            # Legacy robust JSON list
            try:
                data = json.load(f)
                for sample in data:
                    label = sample.get("output", "unknown")
                    samples_by_class[label].append({
                        "instruction": sample.get("instruction", ""),
                        "output": sample.get("output", "")
                    })
            except Exception as e:
                print(f"    Error loading JSON list: {e}")
        else:
            # JSONL format (Modern or Legacy JSONL)
            for line in f:
                if not line.strip(): continue
                try:
                    raw_sample = json.loads(line)
                    
                    if ds_type == "modern":
                        # Convert Metrics -> Instruction/Output
                        instruction = create_user_prompt(raw_sample)
                        output = create_assistant_response(raw_sample)
                        label = raw_sample.get("normalized_label", "unknown")
                        
                        samples_by_class[label].append({
                            "instruction": instruction,
                            "output": output
                        })
                    else:
                        # Legacy JSONL (Instruction/Output)
                        label = raw_sample.get("output", "unknown")
                        samples_by_class[label].append(raw_sample)
                except Exception as e:
                    continue
    
    # Balance: take equal samples from each class
    balanced = []
    print(f"    Found classes: {list(samples_by_class.keys())}")
    for label, samples in samples_by_class.items():
        count = min(len(samples), samples_per_class)
        selected = random.sample(samples, count)
        balanced.extend(selected)
        print(f"    - {label}: {count} samples")
    
    return balanced


def convert_to_chatml(samples):
    """Convert to MLX training format with chat template."""
    converted = []
    for sample in samples:
        text = (
            f"<|start_header_id|>system<|end_header_id|>\n\n{SYSTEM_PROMPT}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n{sample['instruction']}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n{sample['output']}<|eot_id|>"
        )
        converted.append({"text": text})
    return converted


def main():
    print("=" * 60)
    print("Creating Balanced Training Dataset (Hybrid Legacy + Modern)")
    print("=" * 60)
    
    all_samples = []
    
    for ds in DATASETS:
        print(f"\nProcessing {ds['task']}...")
        samples = load_and_balance_dataset(ds)
        all_samples.extend(samples)
    
    if not all_samples:
        print("\nError: No samples collected!")
        return

    # Shuffle all samples
    random.shuffle(all_samples)
    
    # Split into train/validation (90/10)
    split_idx = int(len(all_samples) * 0.9)
    train_samples = all_samples[:split_idx]
    val_samples = all_samples[split_idx:]
    
    print(f"\n{'=' * 60}")
    print(f"Total Combined Samples: {len(all_samples)}")
    print(f"Training: {len(train_samples)}")
    print(f"Validation: {len(val_samples)}")
    
    # Convert to training format
    train_data = convert_to_chatml(train_samples)
    val_data = convert_to_chatml(val_samples)
    
    # Save to balanced dataset directory
    output_dir = Path("models/aipam-llama-balanced")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "train.jsonl", "w") as f:
        for item in train_data:
            f.write(json.dumps(item) + "\n")
    
    with open(output_dir / "valid.jsonl", "w") as f:
        for item in val_data:
            f.write(json.dumps(item) + "\n")
    
    print(f"\nDataset saved to: {output_dir}")
    print(f"  - train.jsonl: {len(train_data)} samples")
    print(f"  - valid.jsonl: {len(val_data)} samples")

if __name__ == "__main__":
    main()
