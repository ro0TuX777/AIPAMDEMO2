#!/usr/bin/env python3
"""
TrafficLLM Training Data Download Script

Downloads pre-processed training datasets from TrafficLLM for fine-tuning llama3.1:8b.

TrafficLLM provides 0.4M+ traffic samples and 9K+ instructions on Google Drive.
This script helps you download and prepare this data for fine-tuning.

Datasets included:
1. USTC-TFC-2016 - Malware traffic detection (50.7K samples)
2. ISCX-Botnet-2014 - Botnet detection (25K samples)
3. CSIC-2010 - Web attack detection (34.5K samples)
4. DAPT-2020 - APT attack detection (10K samples)
5. ISCX-VPN-2016 - Encrypted VPN detection (64.8K samples)
6. ISCX-Tor-2016 - Tor behavior detection (40K samples)
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# TrafficLLM Google Drive links
GOOGLE_DRIVE_DATASETS = "https://drive.google.com/drive/folders/1RZAOPcNKq73-quA8KG_lkAo_EqlwhlQb"
GOOGLE_DRIVE_MODELS = "https://drive.google.com/drive/folders/1YjEhdordqZRpnw_oKczwUztcT52T0oQ0"

# Dataset information
DATASETS = {
    "ustc-tfc-2016": {
        "name": "USTC-TFC-2016",
        "description": "Malware Traffic Detection",
        "samples": "50.7K",
        "task": "MTD",
        "type": "malware",
    },
    "iscx-botnet-2014": {
        "name": "ISCX-Botnet-2014",
        "description": "Botnet Detection",
        "samples": "25K",
        "task": "BND",
        "type": "botnet",
    },
    "csic-2010": {
        "name": "CSIC-2010",
        "description": "Web Attack Detection",
        "samples": "34.5K",
        "task": "WAD",
        "type": "web_attack",
    },
    "dapt-2020": {
        "name": "DAPT-2020",
        "description": "APT Attack Detection",
        "samples": "10K",
        "task": "AAD",
        "type": "apt",
    },
    "iscx-vpn-2016": {
        "name": "ISCX-VPN-2016",
        "description": "Encrypted VPN Detection",
        "samples": "64.8K",
        "task": "EVD",
        "type": "vpn",
    },
    "iscx-tor-2016": {
        "name": "ISCX-Tor-2016",
        "description": "Tor Behavior Detection",
        "samples": "40K",
        "task": "TBD",
        "type": "tor",
    },
}

# TrafficLLM GitHub repo
TRAFFICLLM_REPO = "https://github.com/ZGC-LLM-Safety/TrafficLLM.git"


def create_directories(base_dir: Path):
    """Create necessary directories for data storage."""
    dirs = [
        base_dir / "raw",
        base_dir / "processed",
        base_dir / "training",
        base_dir / "validation",
        base_dir / "trafficllm_datasets",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print(f"✓ Created data directories in {base_dir}")


def clone_trafficllm_repo(base_dir: Path):
    """Clone TrafficLLM repo for reference data and scripts."""
    target_dir = base_dir / "trafficllm"
    if target_dir.exists():
        print("✓ TrafficLLM repo already exists")
        return

    print("Cloning TrafficLLM repository...")
    subprocess.run(
        ["git", "clone", "--depth", "1", TRAFFICLLM_REPO, str(target_dir)],
        check=True,
    )
    print("✓ Cloned TrafficLLM repository")


def check_gdown():
    """Check if gdown is installed for Google Drive downloads."""
    try:
        import gdown
        return True
    except ImportError:
        return False


def install_gdown():
    """Install gdown for Google Drive downloads."""
    print("Installing gdown for Google Drive downloads...")
    subprocess.run([sys.executable, "-m", "pip", "install", "gdown"], check=True)
    print("✓ Installed gdown")


def download_trafficllm_datasets(base_dir: Path):
    """Download pre-processed datasets from TrafficLLM Google Drive."""
    if not check_gdown():
        install_gdown()

    import gdown

    output_dir = base_dir / "trafficllm_datasets"

    print("\nDownloading TrafficLLM datasets from Google Drive...")
    print(f"Source: {GOOGLE_DRIVE_DATASETS}")
    print(f"Output: {output_dir}")
    print("\nThis may take a while (datasets are ~500MB total)...")

    try:
        gdown.download_folder(
            GOOGLE_DRIVE_DATASETS,
            output=str(output_dir),
            quiet=False,
        )
        print("✓ Downloaded TrafficLLM datasets")
        return True
    except Exception as e:
        print(f"⚠ Auto-download failed: {e}")
        print("\nPlease download manually:")
        print(f"  1. Go to: {GOOGLE_DRIVE_DATASETS}")
        print(f"  2. Download all files")
        print(f"  3. Extract to: {output_dir}")
        return False


def convert_trafficllm_to_aipam_format(base_dir: Path):
    """Convert TrafficLLM JSONL format to AIPAM training format."""
    input_dir = base_dir / "trafficllm_datasets"
    output_dir = base_dir / "processed"

    if not input_dir.exists():
        print("⚠ TrafficLLM datasets not found. Run download first.")
        return

    # Find all JSON files (they're actually JSONL format)
    json_files = list(input_dir.rglob("*.json"))
    print(f"\nFound {len(json_files)} JSON files to convert")

    all_samples = []

    for json_file in json_files:
        # Skip label files
        if "_label.json" in str(json_file):
            print(f"  Skipped label file: {json_file.name}")
            continue

        file_samples = 0
        try:
            with open(json_file, encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        if "instruction" in item and "output" in item:
                            all_samples.append({
                                "source_file": str(json_file.name),
                                "instruction": item["instruction"],
                                "output": item["output"],
                                "input": item.get("input", ""),
                            })
                            file_samples += 1
                    except json.JSONDecodeError:
                        continue  # Skip malformed lines
            print(f"  ✓ Processed: {json_file.name} ({file_samples:,} samples)")
        except Exception as e:
            print(f"  ⚠ Error processing {json_file.name}: {e}")

    # Save converted samples
    output_file = output_dir / "trafficllm_samples.jsonl"
    with open(output_file, "w") as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + "\n")

    print(f"\n✓ Converted {len(all_samples):,} total samples to {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Download and prepare TrafficLLM training data.")
    parser.add_argument("--download", action="store_true", help="Download datasets from Google Drive")
    parser.add_argument("--convert", action="store_true", help="Convert datasets to AIPAM format")
    parser.add_argument("--data-dir", type=str, default="data", help="Base directory for data storage (default: ./data)")
    
    args = parser.parse_args()
    
    # Resolve absolute path for data directory
    if args.data_dir == "data":
        # Default behavior: relative to script location if not specified
        # But for backward compatibility with existing "data" folder in cwd, 
        # let's map it to cwd/data like before.
        base_dir = Path("data")
    else:
        base_dir = Path(args.data_dir)
        
    print("=" * 60)
    print("TrafficLLM Training Data Download & Preparation")
    print(f"Data Directory: {base_dir.resolve()}")
    print("=" * 60)

    create_directories(base_dir)
    clone_trafficllm_repo(base_dir)

    print("\n" + "=" * 60)
    print("Available Datasets (from TrafficLLM)")
    print("=" * 60)

    print("\n| Dataset | Task | Samples | Description |")
    print("|---------|------|---------|-------------|")
    for dataset_id, info in DATASETS.items():
        print(f"| {info['name']} | {info['task']} | {info['samples']} | {info['description']} |")

    # If no action arguments provided, show help
    if not (args.download or args.convert):
        print("\n" + "=" * 60)
        print("Download Options")
        print("=" * 60)

        print(f"""
Option 1: Automatic Download (Recommended)
  Run: python download_training_data.py --download --data-dir {base_dir}

Option 2: Manual Download
  1. Go to: {GOOGLE_DRIVE_DATASETS}
  2. Download the datasets you need
  3. Place in: {base_dir}/trafficllm_datasets/
  4. Run: python download_training_data.py --convert --data-dir {base_dir}
""")

    if args.download:
        if download_trafficllm_datasets(base_dir):
            convert_trafficllm_to_aipam_format(base_dir)
    elif args.convert:
        convert_trafficllm_to_aipam_format(base_dir)


if __name__ == "__main__":
    main()

