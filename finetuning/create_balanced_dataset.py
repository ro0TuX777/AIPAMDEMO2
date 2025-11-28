#!/usr/bin/env python3
"""
Create a balanced dataset with equal samples per class for better training.
"""

import json
import random
from pathlib import Path
from collections import defaultdict

SYSTEM_PROMPT = "You are a network traffic analysis expert. Analyze the provided packet data and classify the traffic type or detect malicious activity. Provide concise, accurate classifications."

# Dataset configurations
DATASETS = [
    {
        "path": "data/trafficllm_datasets/ustc-tfc-2016/ustc-tfc-2016_detection_packet_train.json",
        "task": "Malware Detection",
        "samples_per_class": 100,
    },
    {
        "path": "data/trafficllm_datasets/iscx-vpn-2016/iscx-vpn-2016_detection_packet_train.json",
        "task": "VPN Detection",
        "samples_per_class": 100,
    },
    {
        "path": "data/trafficllm_datasets/iscx-tor-2016/iscx-tor-2016_detection_packet_train.json",
        "task": "Tor Detection",
        "samples_per_class": 100,
    },
]


def load_and_balance_dataset(filepath, samples_per_class=100):
    """Load dataset and balance by class."""
    samples_by_class = defaultdict(list)
    
    with open(filepath) as f:
        for line in f:
            try:
                sample = json.loads(line)
                label = sample["output"]
                samples_by_class[label].append(sample)
            except:
                continue
    
    # Balance: take equal samples from each class
    balanced = []
    for label, samples in samples_by_class.items():
        selected = random.sample(samples, min(len(samples), samples_per_class))
        balanced.extend(selected)
        print(f"  {label}: {len(selected)} samples")
    
    return balanced


def convert_to_training_format(samples, tokenizer_format="llama3"):
    """Convert to MLX training format with chat template."""
    converted = []
    
    for sample in samples:
        if tokenizer_format == "llama3":
            text = (
                f"<|start_header_id|>system<|end_header_id|>\n\n{SYSTEM_PROMPT}<|eot_id|>"
                f"<|start_header_id|>user<|end_header_id|>\n\n{sample['instruction']}<|eot_id|>"
                f"<|start_header_id|>assistant<|end_header_id|>\n\n{sample['output']}<|eot_id|>"
            )
        converted.append({"text": text})
    
    return converted


def main():
    print("=" * 60)
    print("Creating Balanced Training Dataset")
    print("=" * 60)
    
    all_samples = []
    
    for ds in DATASETS:
        path = Path(ds["path"])
        if not path.exists():
            print(f"\nSkipping {ds['task']}: file not found")
            continue
        
        print(f"\n{ds['task']} ({path.name}):")
        samples = load_and_balance_dataset(path, ds["samples_per_class"])
        all_samples.extend(samples)
    
    # Shuffle all samples
    random.shuffle(all_samples)
    
    # Split into train/validation (90/10)
    split_idx = int(len(all_samples) * 0.9)
    train_samples = all_samples[:split_idx]
    val_samples = all_samples[split_idx:]
    
    print(f"\n{'=' * 60}")
    print(f"Total samples: {len(all_samples)}")
    print(f"Training: {len(train_samples)}")
    print(f"Validation: {len(val_samples)}")
    
    # Convert to training format
    train_data = convert_to_training_format(train_samples)
    val_data = convert_to_training_format(val_samples)
    
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
    
    # Print training command
    print(f"\n{'=' * 60}")
    print("To train on this balanced dataset, run:")
    print(f"""
python -m mlx_lm lora \\
  --model mlx-community/Meta-Llama-3.1-8B-Instruct-4bit \\
  --train \\
  --data {output_dir} \\
  --iters 2000 \\
  --batch-size 4 \\
  --learning-rate 2e-05 \\
  --num-layers 16 \\
  --max-seq-length 1024 \\
  --adapter-path {output_dir}/adapters \\
  --grad-checkpoint
""")


if __name__ == "__main__":
    main()

