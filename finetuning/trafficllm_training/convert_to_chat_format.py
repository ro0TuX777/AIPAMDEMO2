#!/usr/bin/env python3
"""
Convert TrafficLLM-style training data to chat message format for continued fine-tuning.
"""

import json
import os
from typing import Dict, List

INPUT_FILE = "training_data/malware_detection_train.json"
OUTPUT_FILE = "training_data/malware_detection_chat_train.jsonl"
OUTPUT_VALID_FILE = "training_data/malware_detection_chat_valid.jsonl"

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in network traffic analysis. 
You analyze packet data to detect malware, identify attack patterns, and provide security insights.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings."""


def convert_sample_to_chat(sample: Dict) -> Dict:
    """Convert instruction/output format to chat messages format."""
    instruction = sample["instruction"]
    output = sample["output"]
    
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": instruction},
            {"role": "assistant", "content": output}
        ]
    }


def main():
    print("Loading training data...")
    with open(INPUT_FILE, 'r') as f:
        data = json.load(f)
    
    print(f"Loaded {len(data)} samples")
    
    # Convert all samples
    converted = [convert_sample_to_chat(sample) for sample in data]
    
    # Split into train/valid (90/10)
    split_idx = int(len(converted) * 0.9)
    train_data = converted[:split_idx]
    valid_data = converted[split_idx:]
    
    print(f"Train samples: {len(train_data)}")
    print(f"Valid samples: {len(valid_data)}")
    
    # Save as JSONL
    print(f"Saving to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w') as f:
        for item in train_data:
            f.write(json.dumps(item) + '\n')
    
    print(f"Saving to {OUTPUT_VALID_FILE}...")
    with open(OUTPUT_VALID_FILE, 'w') as f:
        for item in valid_data:
            f.write(json.dumps(item) + '\n')
    
    # Print size info
    train_size = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    valid_size = os.path.getsize(OUTPUT_VALID_FILE) / (1024 * 1024)
    print(f"\nTrain file size: {train_size:.1f} MB")
    print(f"Valid file size: {valid_size:.1f} MB")
    
    # Print sample
    print("\n=== Sample converted entry ===")
    sample = converted[0]
    print(f"System: {sample['messages'][0]['content'][:100]}...")
    print(f"User: {sample['messages'][1]['content'][:200]}...")
    print(f"Assistant: {sample['messages'][2]['content']}")


if __name__ == "__main__":
    main()

