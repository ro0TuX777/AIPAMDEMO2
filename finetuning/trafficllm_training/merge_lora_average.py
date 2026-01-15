#!/usr/bin/env python3
"""
Merge multiple LoRA adapters by averaging their weights.

This is the correct approach for combining independently trained LoRA adapters.
Each adapter's delta weights are averaged, then applied to the base model once.
"""

import os
import gc
import torch
import subprocess
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel, PeftConfig, get_peft_model
from safetensors.torch import load_file, save_file
import json

# Configuration
BASE_MODEL = "meta-llama/Llama-3.1-8B-Instruct"
BATCHES = [
    "batch1_banking_trojans",
    "batch2_infostealers", 
    "batch3_loaders",
    "batch4_rats_c2",
    "batch5_regional_other",
]
TRAINED_MODELS_DIR = Path("trained_models")
OUTPUT_DIR = Path("merged_model_averaged")
GGUF_OUTPUT = "aipam-trafficllm-v4.gguf"


def average_lora_weights():
    """Average LoRA weights from all adapters."""
    print("\n" + "=" * 60)
    print("Step 1: Averaging LoRA adapter weights")
    print("=" * 60)
    
    # Load all adapter weights
    all_weights = []
    adapter_config = None
    
    for batch in BATCHES:
        adapter_path = TRAINED_MODELS_DIR / batch
        if not adapter_path.exists():
            print(f"⚠️  Skipping {batch} - not found")
            continue
            
        print(f"Loading {batch}...")
        
        # Load adapter weights
        adapter_file = adapter_path / "adapter_model.safetensors"
        if adapter_file.exists():
            weights = load_file(str(adapter_file))
        else:
            # Try bin format
            adapter_file = adapter_path / "adapter_model.bin"
            weights = torch.load(str(adapter_file), map_location="cpu")
        
        all_weights.append(weights)
        
        # Keep first config as reference
        if adapter_config is None:
            config_file = adapter_path / "adapter_config.json"
            with open(config_file) as f:
                adapter_config = json.load(f)
    
    if not all_weights:
        raise ValueError("No adapters found!")
    
    print(f"\nAveraging {len(all_weights)} adapters...")
    
    # Average the weights
    averaged_weights = {}
    for key in all_weights[0].keys():
        stacked = torch.stack([w[key].float() for w in all_weights])
        averaged_weights[key] = stacked.mean(dim=0).half()
    
    # Save averaged adapter
    averaged_adapter_dir = Path("averaged_adapter")
    averaged_adapter_dir.mkdir(exist_ok=True)
    
    save_file(averaged_weights, str(averaged_adapter_dir / "adapter_model.safetensors"))
    with open(averaged_adapter_dir / "adapter_config.json", "w") as f:
        json.dump(adapter_config, f, indent=2)
    
    print(f"✓ Averaged adapter saved to {averaged_adapter_dir}")
    return averaged_adapter_dir


def merge_and_convert(adapter_dir):
    """Merge averaged adapter with base model and convert to GGUF."""
    print("\n" + "=" * 60)
    print("Step 2: Loading base model and merging averaged adapter")
    print("=" * 60)
    
    print(f"Loading {BASE_MODEL}...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map="cpu",
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    
    print("Applying averaged LoRA adapter...")
    model = PeftModel.from_pretrained(model, str(adapter_dir), device_map="cpu")
    model = model.merge_and_unload()
    
    print(f"Saving merged model to {OUTPUT_DIR}...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUTPUT_DIR, safe_serialization=True)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    del model
    gc.collect()
    
    print("\n" + "=" * 60)
    print("Step 3: Converting to GGUF")
    print("=" * 60)
    
    llama_cpp_dir = Path("../aipam_gpu_training/llama.cpp")
    convert_script = llama_cpp_dir / "convert_hf_to_gguf.py"
    
    subprocess.run([
        "python", str(convert_script),
        str(OUTPUT_DIR),
        "--outfile", GGUF_OUTPUT,
        "--outtype", "q8_0",
    ], check=True)
    
    # Create Modelfile
    modelfile = f'''FROM {GGUF_OUTPUT}
PARAMETER temperature 0.1
PARAMETER num_ctx 4096
PARAMETER stop "<|eot_id|>"
SYSTEM """You are a cybersecurity expert specializing in malware traffic analysis."""
'''
    with open("Modelfile", "w") as f:
        f.write(modelfile)
    
    print(f"\n✓ GGUF saved: {GGUF_OUTPUT}")
    print("✓ Modelfile created")


def main():
    print("\n" + "=" * 60)
    print("AIPAM TrafficLLM v4 - LoRA Weight Averaging Merge")
    print("=" * 60)
    
    adapter_dir = average_lora_weights()
    merge_and_convert(adapter_dir)
    
    print("\n" + "=" * 60)
    print("SUCCESS! Deploy with: ollama create aipam-trafficllm-v4 -f Modelfile")
    print("=" * 60)


if __name__ == "__main__":
    main()

