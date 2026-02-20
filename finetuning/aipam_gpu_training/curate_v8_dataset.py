#!/usr/bin/env python3
"""Curate V8 training dataset.

Combines:
  1. New Scapy-format malware family data (129K samples, all 50 families)
  2. Subsampled multi-task data from V7 (traffic diversity: VPN, TOR, botnet, HTTP, app, etc.)
  3. Zeek flow/frame behavioral samples from V7

Excludes:
  - Generic labels ("unknown", "malicious", "benign") — noise that overwhelmed V7
  - Old Scapy-format family data (superseded by new comprehensive data)
"""

import json
import random
import os
from collections import Counter
from pathlib import Path

random.seed(42)

# ---------- CONFIG ----------
# Proportion of V7 multi-task data to keep (for traffic understanding diversity)
MULTITASK_SAMPLE_RATIO = 0.08  # ~8% of ~444K = ~35K samples
VALID_SPLIT_RATIO = 0.1        # 10% held out for validation

V7_TRAIN = "data/v7_train.jsonl"
V7_VALID = "data/v7_valid.jsonl"
NEW_SCAPY_TRAIN = "../trafficllm_training/training_data/malware_detection_chat_train.jsonl"
NEW_SCAPY_VALID = "../trafficllm_training/training_data/malware_detection_chat_valid.jsonl"
OUT_TRAIN = "data/v8_train.jsonl"
OUT_VALID = "data/v8_valid.jsonl"


def classify_sample(msg: dict) -> str:
    """Classify a V7 sample into a bucket."""
    assistant = msg["messages"][2]["content"]
    user = msg["messages"][1]["content"]

    # Check if it has a malware family classification response
    if "recognized as " in assistant:
        family = assistant.split("recognized as ")[-1].rstrip(".")
        if family.lower() in ("unknown", "malicious", "benign"):
            return "generic_label"       # EXCLUDE
        return "old_scapy_family"        # EXCLUDE (superseded by new data)

    # Multi-task samples (valuable for traffic understanding)
    task_keywords = [
        "VPN detection", "TOR BEHAVIOR", "Website Fingerprinting",
        "BOTNET DETECTION", "APP CLASSIFICATION", "Concept Drift",
        "ENCRYPTED APP CLASSIFICATION", "HTTP request",
        "Classify the given HTTP", "ENCRYPTED TRAFFIC CLASSIFICATION",
        "MALWARE DETECTION TASK",
    ]
    for kw in task_keywords:
        if kw.lower() in user.lower():
            return "multitask"

    # Behavioral / MTA / Q&A / other valuable samples
    return "multitask"  # Keep all non-family, non-generic as multitask


def load_jsonl(path: str) -> list:
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def main():
    print("=" * 60)
    print("CURATING V8 TRAINING DATASET")
    print("=" * 60)

    # --- Step 1: Load new Scapy family data ---
    print("\n[1/4] Loading new Scapy-format malware family data...")
    new_train = load_jsonl(NEW_SCAPY_TRAIN)
    new_valid = load_jsonl(NEW_SCAPY_VALID)
    print(f"  New train: {len(new_train):,} samples")
    print(f"  New valid: {len(new_valid):,} samples")

    # --- Step 2: Load and classify V7 data ---
    print("\n[2/4] Loading and classifying V7 data...")
    buckets = Counter()
    multitask_pool = []

    for v7_path in [V7_TRAIN, V7_VALID]:
        with open(v7_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                msg = json.loads(line)
                bucket = classify_sample(msg)
                buckets[bucket] += 1
                if bucket == "multitask":
                    multitask_pool.append(msg)

    print(f"  V7 classification:")
    for b, c in buckets.most_common():
        action = "KEEP (subsample)" if b == "multitask" else "EXCLUDE"
        print(f"    {b:25s}: {c:7,}  → {action}")

    # --- Step 3: Subsample multi-task data ---
    print(f"\n[3/4] Subsampling multi-task data...")
    n_multitask = int(len(multitask_pool) * MULTITASK_SAMPLE_RATIO)
    random.shuffle(multitask_pool)
    multitask_selected = multitask_pool[:n_multitask]

    # Split multi-task into train/valid
    n_mt_valid = int(len(multitask_selected) * VALID_SPLIT_RATIO)
    mt_valid = multitask_selected[:n_mt_valid]
    mt_train = multitask_selected[n_mt_valid:]
    print(f"  Multi-task pool: {len(multitask_pool):,}")
    print(f"  Selected: {len(multitask_selected):,} ({MULTITASK_SAMPLE_RATIO:.0%})")
    print(f"    Train: {len(mt_train):,}")
    print(f"    Valid: {len(mt_valid):,}")

    # --- Step 4: Combine and save ---
    print(f"\n[4/4] Combining and saving...")
    v8_train = new_train + mt_train
    v8_valid = new_valid + mt_valid

    random.shuffle(v8_train)
    random.shuffle(v8_valid)

    os.makedirs("data", exist_ok=True)
    with open(OUT_TRAIN, "w") as f:
        for s in v8_train:
            f.write(json.dumps(s) + "\n")
    with open(OUT_VALID, "w") as f:
        for s in v8_valid:
            f.write(json.dumps(s) + "\n")

    train_size = os.path.getsize(OUT_TRAIN) / 1e6
    valid_size = os.path.getsize(OUT_VALID) / 1e6

    print(f"\n{'=' * 60}")
    print(f"V8 DATASET SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Train: {len(v8_train):,} samples ({train_size:.1f} MB)")
    print(f"  Valid: {len(v8_valid):,} samples ({valid_size:.1f} MB)")
    print(f"  Total: {len(v8_train) + len(v8_valid):,} samples")
    print(f"\n  Composition:")
    print(f"    New malware family (train): {len(new_train):,}")
    print(f"    New malware family (valid): {len(new_valid):,}")
    print(f"    Multi-task diversity (train): {len(mt_train):,}")
    print(f"    Multi-task diversity (valid): {len(mt_valid):,}")
    print(f"\n  Files:")
    print(f"    {OUT_TRAIN}")
    print(f"    {OUT_VALID}")


if __name__ == "__main__":
    main()

