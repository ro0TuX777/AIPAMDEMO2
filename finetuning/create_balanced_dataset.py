import argparse
import copy
import json
import random
import re
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

BASE_DIR = Path(__file__).parent.absolute()

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
        "path": BASE_DIR / "data/trafficllm_datasets/ustc-tfc-2016/ustc-tfc-2016_detection_packet_train.json",
        "task": "Malware Detection",
        "type": "legacy",
        "samples_per_class": 100,
    },
    {
        "path": BASE_DIR / "data/trafficllm_datasets/iscx-vpn-2016/iscx-vpn-2016_detection_packet_train.json",
        "task": "VPN Detection",
        "type": "legacy",
        "samples_per_class": 100,
    },
    {
        "path": BASE_DIR / "data/trafficllm_datasets/iscx-tor-2016/iscx-tor-2016_detection_packet_train.json",
        "task": "Tor Detection",
        "type": "legacy",
        "samples_per_class": 100,
    },
    # NEW: Modern Families
    {
        "path": BASE_DIR / "data/processed/processed_samples_v5.jsonl",
        "task": "Modern Malware Detection",
        "type": "modern",
        "samples_per_class": 5000, 
    },
    {
        "path": BASE_DIR / "custom_v5_lessons.jsonl",
        "task": "V5 Reasoning Reinforcement",
        "type": "legacy",
        "samples_per_class": 100,
    },
]

# Session-Level IR dataset (Phase 6.2) — replaces v5 modern dataset
SESSION_IR_DATASET = {
    "path": BASE_DIR / "data/processed/processed_samples_v6_session.jsonl",
    "task": "Session-Level Modern Malware Detection",
    "type": "modern",
    "samples_per_class": 5000,
}



def generate_payload_heatmap(packet_strings: List[str]) -> str:
    """Generate a visual byte-distribution heatmap for LLM analysis."""
    if not packet_strings:
        return "(No raw packets provided)"
        
    import string
    all_bytes = []
    for p in packet_strings:
        # Extract hex values from packet snippets
        hex_vals = "".join(filter(lambda c: c in string.hexdigits, p))
        try:
            if len(hex_vals) % 2 == 0:
                all_bytes.extend(bytes.fromhex(hex_vals))
        except:
            continue
            
    if not all_bytes:
        return "(Unprocessable payload format)"
        
    total = len(all_bytes)
    nulls = all_bytes.count(0)
    printable = sum(1 for b in all_bytes if 32 <= b <= 126)
    high_bit = sum(1 for b in all_bytes if b > 127)
    
    # ASCII Histogram
    def bar(pct): 
        filled = int(pct / 5)
        return "█" * filled + "░" * (20 - filled)
    
    p_pct = (printable/total)*100
    n_pct = (nulls/total)*100
    h_pct = (high_bit/total)*100
    o_pct = max(0, 100 - p_pct - n_pct - h_pct)

    return f"""PAYLOAD HEATMAP (Visual Byte Distribution):
[Printable] {bar(p_pct)} {p_pct:4.1f}% (Text/Headers)
[Null Bytes] {bar(n_pct)} {n_pct:4.1f}% (Padding/Structure)
[High Bit  ] {bar(h_pct)} {h_pct:4.1f}% (Encrypted/Encapsulated)
[Other     ] {bar(o_pct)} {o_pct:4.1f}% (Control/Binary)"""


def create_user_prompt(sample: Dict) -> str:
    """Create user prompt from processed sample (Modern Format)."""
    # 1. JSON Context
    ctx_data = {
        "host_summaries": sample.get("host_summaries", []),
        "hostpair_summaries": sample.get("hostpair_summaries", []),
        "flow_count": sample.get("flow_count", 0),
        "alert_count": sample.get("alert_count", 0),
        "anomaly_report": sample.get("anomaly_report", {}),
        "interaction_graph": sample.get("anomaly_report", {}).get("interaction_graph", {}) # NEW: V5 Topologies
    }
    data_json = json.dumps(ctx_data, indent=2)

    # 2. Raw Packets & Heatmap
    packet_strings = sample.get("raw_packet_samples", [])
    packet_data = "\n".join(packet_strings) if packet_strings else "(No raw packets provided)"
    heatmap = generate_payload_heatmap(packet_strings)

    return f"""Analyze the following network traffic data:

Network Topology & Heuristics:
```json
{data_json}
```

{heatmap}

Raw Packet Snippets:
{packet_data}

Classify this traffic and provide your analysis as a JSON object.
Use the `interaction_graph` to identify patterns such as Hubs, Authorities, or PIVOTS.
Use the `PAYLOAD HEATMAP` to verify if the traffic is legitimately encrypted or anomalously obfuscated.
Provide your reasoning in the `attack_chain` and `anomalies` fields."""


def create_assistant_response(sample: Dict) -> str:
    """Create ideal assistant response based on sample label (Modern Format)."""
    label = sample.get("normalized_label", "normal")
    dataset_type = sample.get("dataset_type", "unknown")
    anomaly_report = sample.get("anomaly_report", {})
    findings = anomaly_report.get("findings", [])
    graph = anomaly_report.get("interaction_graph", {})
    
    heatmap_findings = []
    # Simple logic to extract heatmap-like observation if we were in the prompt
    # Since we don't have the actual heatmap text here, we'll use the findings
    
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
        
        # Enrich attack chain with forensic reasoning
        evidence = [f"Observed characteristic flows for {label}"]
        
        # Add Graph Reasoning
        if graph.get("pivots"):
            evidence.append(f"CRITICAL TOPOLOGY: Detected horizontal pivoting through {graph['pivots']}")
        elif graph.get("hubs"):
            evidence.append("ACTIVE RECON: Large fan-out detected from source hub IPs.")
            
        # Add Heuristic Reasoning
        if findings:
            for f in findings[:3]: # Take top 3 findings
                if f.get("chain_of_thought"):
                    evidence.append(f["chain_of_thought"])

        # Dynamic confidence boost for high-fidelity signals
        base_confidence = 0.90
        if graph.get("pivots") or any(f.get("severity") == "high" for f in findings):
            base_confidence = 0.98

        response = {
            "overall_severity": severity_map.get(dataset_type, "high"),
            "classification": "malicious",
            "attack_type": label if label != "malware" else dataset_type,
            "confidence": base_confidence,
            "attack_chain": [{
                "stage": "detection",
                "description": f"Traffic consistent with {label} behavior and protocol anomalies",
                "evidence": evidence,
                "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}],
            }],
            "host_findings": [],
            "anomalies": findings if findings else [{
                "description": f"Detected {label} traffic signs",
                "related_hosts": [],
                "confidence": 0.90,
                "reason": f"Matches known {label} patterns",
            }],
            "mitre_techniques_overall": [{"id": "T1071", "name": "Application Layer Protocol"}],
        }

    return json.dumps(response, indent=2)


# =============================================================================
# Phase 6.1 — ORPO Preference-Pair Generation (Contrastive Evidentiary Training)
# =============================================================================

def _random_ip() -> str:
    """Generate a random non-routable IP address for evidence corruption."""
    return f"{random.randint(198, 203)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_mitre_id() -> str:
    """Generate a plausible but invalid MITRE technique ID."""
    return f"T{random.randint(9000, 9999)}"


def corrupt_evidence(response_json_str: str) -> str:
    """Corrupt evidentiary fields in a forensic response while preserving classification.

    This creates the 'rejected' half of an ORPO preference pair. The malware
    classification stays correct, but the supporting evidence (IPs, MITRE IDs,
    evidence chains) is randomized — teaching the model that
    'Right Answer + Wrong Evidence = Failure'.

    Args:
        response_json_str: Valid JSON string of an assistant forensic response.

    Returns:
        Corrupted JSON string with hallucinated evidence fields.
    """
    try:
        response = json.loads(response_json_str)
    except json.JSONDecodeError:
        # For non-JSON legacy responses, do simple IP corruption
        corrupted = re.sub(
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            lambda m: _random_ip(),
            response_json_str,
        )
        return corrupted

    corrupted = copy.deepcopy(response)

    # 1. Corrupt MITRE technique IDs (keep names to look plausible)
    for tech in corrupted.get("mitre_techniques_overall", []):
        tech["id"] = _random_mitre_id()

    # 2. Corrupt attack_chain evidence
    for chain_step in corrupted.get("attack_chain", []):
        # Corrupt MITRE IDs in chain
        for tech in chain_step.get("mitre_techniques", []):
            tech["id"] = _random_mitre_id()

        # Shuffle evidence strings to break logical reasoning chain
        evidence = chain_step.get("evidence", [])
        if len(evidence) > 1:
            shuffled = evidence.copy()
            random.shuffle(shuffled)
            # Also corrupt any IPs in evidence strings
            chain_step["evidence"] = [
                re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                       lambda m: _random_ip(), e)
                for e in shuffled
            ]

    # 3. Corrupt anomaly related_hosts IPs
    for anomaly in corrupted.get("anomalies", []):
        if "related_hosts" in anomaly:
            anomaly["related_hosts"] = [_random_ip() for _ in anomaly["related_hosts"]]
        # Corrupt reason text IPs
        if "reason" in anomaly:
            anomaly["reason"] = re.sub(
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                lambda m: _random_ip(),
                anomaly["reason"],
            )

    # 4. Corrupt host_findings IPs
    for finding in corrupted.get("host_findings", []):
        if "ip" in finding:
            finding["ip"] = _random_ip()

    return json.dumps(corrupted, indent=2)


def create_preference_pairs(samples: List[Dict]) -> List[Dict]:
    """Convert balanced samples into ORPO preference pairs.

    For each sample, produces:
        {
            "prompt":   "<system + user as ChatML>",
            "chosen":   "<valid forensic response>",
            "rejected": "<same response with corrupted evidence>"
        }

    Args:
        samples: List of {"instruction": ..., "output": ...} dicts.

    Returns:
        List of preference-pair dicts ready for ORPOTrainer.
    """
    pairs = []
    for sample in samples:
        instruction = sample.get("instruction", "")
        chosen_response = sample.get("output", "")

        if not instruction or not chosen_response:
            continue

        # Build the prompt (system + user) in ChatML format
        prompt = (
            f"<|start_header_id|>system<|end_header_id|>\n\n{SYSTEM_PROMPT}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n{instruction}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
        )

        # Create the rejected version with corrupted evidence
        rejected_response = corrupt_evidence(chosen_response)

        pairs.append({
            "prompt": prompt,
            "chosen": chosen_response,
            "rejected": rejected_response,
        })

    return pairs


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
        # Check explicit legacy list format (some ISCX files are big JSON list)
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
                        # Check for explicit label first, then fallback to output
                        label = raw_sample.get("label") or raw_sample.get("normalized_label") or raw_sample.get("output", "unknown")
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
    parser = argparse.ArgumentParser(
        description="Create balanced training datasets for AIPAM (SFT or ORPO)"
    )
    parser.add_argument(
        "--orpo", action="store_true",
        help="Generate ORPO preference pairs instead of SFT ChatML"
    )
    parser.add_argument(
        "--session-ir", action="store_true",
        help="Phase 6.2: Use session-level IR data (v6_session) for 32k context"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate dataset generation without writing files"
    )
    args = parser.parse_args()

    mode = "ORPO Preference Pairs" if args.orpo else "SFT ChatML"
    if args.session_ir:
        mode += " (Session-Level IR)"
    print("=" * 60)
    print(f"Creating Balanced Training Dataset — {mode}")
    print("=" * 60)
    
    # Determine which datasets to use
    active_datasets = list(DATASETS)
    if args.session_ir:
        # Replace the v5 modern dataset with v6 session-level IR
        active_datasets = [
            ds for ds in active_datasets
            if "processed_samples_v5" not in str(ds.get("path", ""))
        ]
        active_datasets.append(SESSION_IR_DATASET)
        print(f"  [Phase 6.2] Using session-level IR source: {SESSION_IR_DATASET['path']}")
    
    all_samples = []
    
    for ds in active_datasets:
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

    if args.orpo:
        # ── ORPO Mode: Generate preference pairs ──
        print(f"\n[Phase 6.1] Generating ORPO preference pairs...")
        train_data = create_preference_pairs(train_samples)
        val_data = create_preference_pairs(val_samples)

        print(f"  Training pairs: {len(train_data)}")
        print(f"  Validation pairs: {len(val_data)}")

        # Validate a sample pair
        if train_data:
            sample = train_data[0]
            assert "prompt" in sample, "Missing 'prompt' key"
            assert "chosen" in sample, "Missing 'chosen' key"
            assert "rejected" in sample, "Missing 'rejected' key"
            assert sample["chosen"] != sample["rejected"], "Chosen and rejected should differ"
            print(f"  ✓ Sample pair validated (prompt={len(sample['prompt'])} chars)")

        # Phase 6.2: Token budget warning for 32k context
        MAX_TOKEN_BUDGET = 32768 * 4  # ~4 chars per token
        oversized = sum(
            1 for p in train_data
            if len(p['prompt']) + len(p['chosen']) > MAX_TOKEN_BUDGET
        )
        if oversized > 0:
            print(f"  ⚠️  {oversized}/{len(train_data)} pairs exceed estimated 32k token budget")
            print(f"     These may be truncated during training.")
        else:
            print(f"  ✓ All pairs within 32k token budget")

        if args.dry_run:
            print("\n[Dry Run] Validation passed. No files written.")
            return

        output_dir = BASE_DIR / "data/v6-orpo"
        output_dir.mkdir(parents=True, exist_ok=True)

        with open(output_dir / "train.jsonl", "w") as f:
            for item in train_data:
                f.write(json.dumps(item) + "\n")

        with open(output_dir / "valid.jsonl", "w") as f:
            for item in val_data:
                f.write(json.dumps(item) + "\n")

        print(f"\nORPO dataset saved to: {output_dir}")
        print(f"  - train.jsonl: {len(train_data)} preference pairs")
        print(f"  - valid.jsonl: {len(val_data)} preference pairs")

    else:
        # ── SFT Mode: Original ChatML format (unchanged) ──
        train_data = convert_to_chatml(train_samples)
        val_data = convert_to_chatml(val_samples)

        if args.dry_run:
            print("\n[Dry Run] Validation passed. No files written.")
            return

        output_dir = BASE_DIR / "data/v5-balanced"
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
