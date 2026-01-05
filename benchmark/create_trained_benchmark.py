#!/usr/bin/env python3
"""
Create a benchmark manifest from the trained malware families.
Takes a sample of pcaps from each family that was used in training.
"""

import os
import json
import random
from pathlib import Path

# Training data directory
TRAINING_PCAPS_DIR = "finetuning/trafficllm_training/pcaps"

# Output manifest
OUTPUT_MANIFEST = "benchmark/manifests/trained_families_benchmark.json"

# Number of samples per family (use all if fewer available)
SAMPLES_PER_FAMILY = 3


def create_benchmark_manifest():
    """Create manifest from training pcaps."""
    
    pcaps_dir = Path(TRAINING_PCAPS_DIR)
    samples = []
    family_counts = {}
    
    for family_dir in sorted(pcaps_dir.iterdir()):
        if not family_dir.is_dir():
            continue
            
        family_name = family_dir.name
        
        # Get all pcap files
        pcap_files = list(family_dir.glob("*.pcap"))
        
        if not pcap_files:
            print(f"⚠️  {family_name}: No pcap files found")
            continue
            
        # Sample files (or use all if fewer than requested)
        num_samples = min(SAMPLES_PER_FAMILY, len(pcap_files))
        selected = random.sample(pcap_files, num_samples)
        
        for pcap in selected:
            samples.append({
                "pcap": str(pcap),
                "label": family_name,
                "set": "trained_benchmark"
            })
        
        family_counts[family_name] = num_samples
        print(f"✓ {family_name}: {num_samples}/{len(pcap_files)} samples")
    
    # Save manifest
    manifest = {
        "description": "Benchmark using samples from trained malware families",
        "total_samples": len(samples),
        "families": list(family_counts.keys()),
        "samples_per_family": family_counts,
        "samples": samples
    }
    
    os.makedirs(os.path.dirname(OUTPUT_MANIFEST), exist_ok=True)
    with open(OUTPUT_MANIFEST, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\n{'='*50}")
    print(f"Created benchmark manifest: {OUTPUT_MANIFEST}")
    print(f"Total families: {len(family_counts)}")
    print(f"Total samples: {len(samples)}")
    print(f"{'='*50}")
    
    return manifest


if __name__ == "__main__":
    random.seed(42)  # For reproducibility
    create_benchmark_manifest()

