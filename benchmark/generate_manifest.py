#!/usr/bin/env python3
"""
Generate Training and Benchmark Manifests for AIPAM v2

This script creates:
1. training_manifest.json - Documents what was used to train v2
2. benchmark_manifest.json - Creates a clean benchmark set
3. leakage_check_manifest.json - Known training samples for overfitting detection
"""

import os
import sys
import json
import random
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set

# Paths
PCAPS_DIR = Path(__file__).parent.parent / "finetuning" / "trafficllm_training" / "pcaps"
OUTPUT_DIR = Path(__file__).parent / "manifests"


def scan_training_pcaps() -> Dict[str, List[str]]:
    """Scan the training PCAPs directory and organize by malware family."""
    pcaps_by_family = defaultdict(list)
    
    if not PCAPS_DIR.exists():
        print(f"Warning: PCAPS directory not found: {PCAPS_DIR}")
        return pcaps_by_family
    
    for family_dir in PCAPS_DIR.iterdir():
        if not family_dir.is_dir():
            continue
            
        family_name = family_dir.name
        
        for pcap_file in family_dir.iterdir():
            if pcap_file.suffix == '.pcap':
                pcaps_by_family[family_name].append(str(pcap_file))
                
    return dict(pcaps_by_family)


def extract_date_from_filename(filename: str) -> str:
    """Extract date from PCAP filename (format: YYYY-MM-DD)."""
    import re
    match = re.search(r'(\d{4}-\d{2}-\d{2})', filename)
    return match.group(1) if match else "unknown"


def create_training_manifest(pcaps_by_family: Dict[str, List[str]]) -> Dict:
    """Create manifest documenting what was used for training v2."""
    samples = []
    
    for family, pcap_paths in pcaps_by_family.items():
        for pcap_path in pcap_paths:
            date = extract_date_from_filename(pcap_path)
            samples.append({
                "pcap": pcap_path,
                "label": family,
                "date": date,
                "set": "training"
            })
    
    # Sort by family then date
    samples.sort(key=lambda x: (x["label"], x["date"]))
    
    manifest = {
        "model": "AIPAM-v2",
        "version": "2.0",
        "created": datetime.now().isoformat(),
        "description": "Training set manifest for AIPAM v2 fine-tuned model",
        "source": "malware-traffic-analysis.net",
        "date_range": {
            "start": "2020-01-01",
            "end": "2024-12-31"
        },
        "statistics": {
            "total_pcaps": len(samples),
            "families": len(pcaps_by_family),
            "pcaps_per_family": {k: len(v) for k, v in sorted(pcaps_by_family.items())}
        },
        "samples": samples
    }
    
    return manifest


def create_leakage_check_manifest(pcaps_by_family: Dict[str, List[str]], num_samples: int = 20) -> Dict:
    """Create manifest of known training samples for overfitting detection."""
    samples = []
    
    # Select random samples from training set
    all_pcaps = [(family, pcap) for family, pcaps in pcaps_by_family.items() for pcap in pcaps]
    
    if len(all_pcaps) > num_samples:
        selected = random.sample(all_pcaps, num_samples)
    else:
        selected = all_pcaps
    
    for family, pcap_path in selected:
        samples.append({
            "pcap": pcap_path,
            "label": family,
            "set": "leakage_check",
            "purpose": "Overfitting detection - these samples were used in training"
        })
    
    manifest = {
        "description": "Leakage check set - known training samples for overfitting detection",
        "created": datetime.now().isoformat(),
        "expected_behavior": "Model should perform BETTER on these than benchmark set",
        "warning": "If benchmark accuracy ≈ leakage accuracy, model may be overfitting",
        "samples": samples
    }
    
    return manifest


def create_benchmark_manifest_placeholder() -> Dict:
    """Create a placeholder benchmark manifest with instructions."""
    return {
        "description": "Benchmark set for AIPAM v2 evaluation",
        "created": datetime.now().isoformat(),
        "status": "PLACEHOLDER - requires manual curation",
        "instructions": {
            "step_1": "Download older PCAPs (2013-2019) from malware-traffic-analysis.net",
            "step_2": "Or hold out recent 2024 samples not seen in training",
            "step_3": "Add unseen malware families for generalization testing",
            "step_4": "Add benign traffic samples for false positive testing",
            "step_5": "Update this manifest with the actual samples"
        },
        "recommended_composition": {
            "seen_families_different_samples": "50-100 samples",
            "unseen_families": "20-30 samples",
            "benign_traffic": "50-100 samples"
        },
        "samples": []
    }


def main():
    """Generate all manifests."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Scanning training PCAPs...")
    pcaps_by_family = scan_training_pcaps()
    
    if not pcaps_by_family:
        print("No PCAPs found! Check the PCAPS_DIR path.")
        return
    
    total_pcaps = sum(len(v) for v in pcaps_by_family.values())
    print(f"Found {total_pcaps} PCAPs across {len(pcaps_by_family)} families\n")
    
    # Generate training manifest
    print("Creating training manifest...")
    training_manifest = create_training_manifest(pcaps_by_family)
    training_path = OUTPUT_DIR / "training_manifest.json"
    with open(training_path, 'w') as f:
        json.dump(training_manifest, f, indent=2)
    print(f"  Saved: {training_path}")
    
    # Generate leakage check manifest
    print("Creating leakage check manifest...")
    leakage_manifest = create_leakage_check_manifest(pcaps_by_family)
    leakage_path = OUTPUT_DIR / "leakage_check_manifest.json"
    with open(leakage_path, 'w') as f:
        json.dump(leakage_manifest, f, indent=2)
    print(f"  Saved: {leakage_path}")

    # Generate benchmark placeholder
    print("Creating benchmark manifest placeholder...")
    benchmark_manifest = create_benchmark_manifest_placeholder()
    benchmark_path = OUTPUT_DIR / "benchmark_manifest.json"
    with open(benchmark_path, 'w') as f:
        json.dump(benchmark_manifest, f, indent=2)
    print(f"  Saved: {benchmark_path}")

    # Print summary
    print(f"\n{'='*60}")
    print("MANIFEST GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"\nTraining Set Statistics:")
    print(f"  Total PCAPs: {training_manifest['statistics']['total_pcaps']}")
    print(f"  Malware Families: {training_manifest['statistics']['families']}")
    print(f"\nPCAPs per Family:")
    for family, count in sorted(training_manifest['statistics']['pcaps_per_family'].items(),
                                 key=lambda x: -x[1])[:10]:
        print(f"    {family}: {count}")
    if len(training_manifest['statistics']['pcaps_per_family']) > 10:
        print(f"    ... and {len(training_manifest['statistics']['pcaps_per_family']) - 10} more")

    print(f"\nLeakage Check Set: {len(leakage_manifest['samples'])} samples")
    print(f"\nNext Steps:")
    print(f"  1. Review training_manifest.json to verify training data")
    print(f"  2. Populate benchmark_manifest.json with held-out samples")
    print(f"  3. Run: python evaluate.py manifests/leakage_check_manifest.json")


if __name__ == "__main__":
    main()

