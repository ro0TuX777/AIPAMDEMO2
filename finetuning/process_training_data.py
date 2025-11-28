#!/usr/bin/env python3
"""
Process raw PCAP data into training samples.

This script processes PCAP files through the same pipeline as AIPAM
to create consistent training data.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Add backend to path for importing AIPAM modules
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

try:
    from app.parsers import parse_zeek_logs, run_zeek
    from app.aggregation import aggregate_host_summary, aggregate_hostpair_summary
except ImportError:
    print("Warning: Could not import AIPAM modules. Run from project root.")
    parse_zeek_logs = None
    run_zeek = None


LABEL_MAPPING = {
    # USTC-TFC-2016 labels
    "Cridex": "malware",
    "Geodo": "malware",
    "Htbot": "malware",
    "Miuref": "malware",
    "Neris": "malware",
    "Nsis-ay": "malware",
    "Shifu": "malware",
    "Tinba": "malware",
    "Virut": "malware",
    "Zeus": "malware",
    "BitTorrent": "normal",
    "Facetime": "normal",
    "FTP": "normal",
    "Gmail": "normal",
    "MySQL": "normal",
    "Outlook": "normal",
    "Skype": "normal",
    "SMB": "normal",
    "Weibo": "normal",
    "WorldOfWarcraft": "normal",

    # Generic labels
    "malicious": "malware",
    "benign": "normal",
    "normal": "normal",
    "attack": "malware",
    "botnet": "botnet",
    "apt": "apt",
    "vpn": "vpn",
    "tor": "tor",
}


def process_pcap_file(pcap_path: str, label: str) -> Optional[Dict]:
    """Process a single PCAP file and return aggregated data."""
    if run_zeek is None:
        return None

    try:
        # Run Zeek on PCAP
        zeek_output_dir = run_zeek(pcap_path)

        # Parse Zeek logs
        flows, events = parse_zeek_logs(zeek_output_dir)

        if not flows:
            return None

        # Aggregate data
        host_summaries = aggregate_host_summary(flows, events)
        hostpair_summaries = aggregate_hostpair_summary(flows, events)

        return {
            "pcap_file": os.path.basename(pcap_path),
            "label": label,
            "normalized_label": LABEL_MAPPING.get(label, label),
            "host_summaries": [hs.model_dump() for hs in host_summaries.values()],
            "hostpair_summaries": [hps.model_dump() for hps in hostpair_summaries.values()],
            "flow_count": len(flows),
            "event_count": len(events),
        }
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        return None


def process_dataset(dataset_dir: str, dataset_type: str) -> List[Dict]:
    """Process all PCAP files in a dataset directory."""
    results = []
    dataset_path = Path(dataset_dir)

    if not dataset_path.exists():
        print(f"Dataset directory not found: {dataset_dir}")
        return results

    # Find all PCAP files
    pcap_files = list(dataset_path.glob("**/*.pcap")) + \
                 list(dataset_path.glob("**/*.pcapng"))

    print(f"Found {len(pcap_files)} PCAP files in {dataset_dir}")

    for pcap_file in pcap_files:
        # Try to extract label from directory structure or filename
        label = pcap_file.parent.name
        if label in ["pcap", "raw", "data"]:
            label = pcap_file.stem.split("_")[0]

        print(f"Processing: {pcap_file.name} (label: {label})")
        result = process_pcap_file(str(pcap_file), label)

        if result:
            result["dataset_type"] = dataset_type
            results.append(result)

    return results


def main():
    print("=" * 60)
    print("PCAP Training Data Processor")
    print("=" * 60)

    raw_data_dir = Path("data/raw")
    processed_dir = Path("data/processed")
    processed_dir.mkdir(parents=True, exist_ok=True)

    dataset_types = {
        "ustc-tfc-2016": "malware",
        "iscx-botnet-2014": "botnet",
        "csic-2010": "web_attack",
        "dapt-2020": "apt",
        "iscx-vpn-2016": "vpn",
        "iscx-tor-2016": "tor",
    }

    all_samples = []

    for dataset_name, dataset_type in dataset_types.items():
        dataset_dir = raw_data_dir / dataset_name
        if dataset_dir.exists():
            print(f"\nProcessing {dataset_name}...")
            samples = process_dataset(str(dataset_dir), dataset_type)
            all_samples.extend(samples)
            print(f"  Processed {len(samples)} samples")

    # Save processed data
    output_file = processed_dir / "processed_samples.jsonl"
    with open(output_file, "w") as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + "\n")

    print(f"\n✓ Saved {len(all_samples)} samples to {output_file}")


if __name__ == "__main__":
    main()

