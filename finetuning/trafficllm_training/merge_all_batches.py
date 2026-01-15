#!/usr/bin/env python3
"""
Merge all 5 LoRA batch adapters into a single combined model.

Strategy: Sequential merging - apply each adapter to base model one at a time,
then merge and unload to get final weights.
"""

import os
import gc
import torch
import subprocess
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel, PeftConfig

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
OUTPUT_DIR = Path("merged_model")
GGUF_OUTPUT = "aipam-trafficllm-v4.gguf"


def merge_adapters():
    """Merge all batch LoRA adapters sequentially."""
    print("\n" + "=" * 60)
    print("Step 1: Loading base model on CPU")
    print("=" * 60)

    # Load base model on CPU to avoid GPU memory issues
    print(f"Loading {BASE_MODEL} (this may take a while on CPU)...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map="cpu",  # Use CPU for merging
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    print("\n" + "=" * 60)
    print("Step 2: Applying and merging LoRA adapters sequentially")
    print("=" * 60)

    for i, batch in enumerate(BATCHES, 1):
        adapter_path = TRAINED_MODELS_DIR / batch
        if not adapter_path.exists():
            print(f"⚠️  Skipping {batch} - not found")
            continue

        print(f"\n[{i}/{len(BATCHES)}] Applying {batch}...")

        # Load and merge this adapter on CPU
        model = PeftModel.from_pretrained(model, str(adapter_path), device_map="cpu")
        model = model.merge_and_unload()

        print(f"  ✓ Merged {batch}")

        # Free memory
        gc.collect()
    
    print("\n" + "=" * 60)
    print("Step 3: Saving merged model")
    print("=" * 60)
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Saving to {OUTPUT_DIR}...")
    model.save_pretrained(OUTPUT_DIR, safe_serialization=True)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    print("✓ Merged model saved!")
    
    # Cleanup
    del model
    gc.collect()
    torch.cuda.empty_cache()
    
    return True


def convert_to_gguf():
    """Convert merged model to GGUF format."""
    print("\n" + "=" * 60)
    print("Step 4: Converting to GGUF format")
    print("=" * 60)
    
    llama_cpp_dir = Path("../aipam_gpu_training/llama.cpp")
    if not llama_cpp_dir.exists():
        print("Cloning llama.cpp...")
        subprocess.run(["git", "clone", "https://github.com/ggerganov/llama.cpp", str(llama_cpp_dir)], check=True)
    
    subprocess.run(["pip", "install", "gguf", "-q"], check=True)
    
    convert_script = llama_cpp_dir / "convert_hf_to_gguf.py"
    print(f"Converting {OUTPUT_DIR} to GGUF (Q8_0 quantization)...")
    
    subprocess.run([
        "python", str(convert_script),
        str(OUTPUT_DIR),
        "--outfile", GGUF_OUTPUT,
        "--outtype", "q8_0",
    ], check=True)
    
    print(f"✓ GGUF saved: {GGUF_OUTPUT}")
    return True


def create_modelfile():
    """Create Ollama Modelfile."""
    modelfile = f'''FROM {GGUF_OUTPUT}

PARAMETER temperature 0.1
PARAMETER num_ctx 4096
PARAMETER stop "<|eot_id|>"

SYSTEM """You are a cybersecurity expert analyzing network traffic. Classify the traffic as one of: Benign, Banking_Trojan, Infostealer, Loader, RAT, Botnet, Ransomware, Exploit_Kit, C2_Framework, or the specific malware family name if identifiable."""
'''
    with open("Modelfile", "w") as f:
        f.write(modelfile)
    print("✓ Created Modelfile")


def main():
    print("\n" + "=" * 60)
    print("AIPAM TrafficLLM v4 - Merge All Batch Adapters")
    print("=" * 60)
    
    # Verify adapters exist
    missing = [b for b in BATCHES if not (TRAINED_MODELS_DIR / b).exists()]
    if missing:
        print(f"ERROR: Missing adapters: {missing}")
        return
    
    if not merge_adapters():
        return
        
    if not convert_to_gguf():
        return
        
    create_modelfile()
    
    print("\n" + "=" * 60)
    print("SUCCESS!")
    print(f"  - Merged model: {OUTPUT_DIR}/")
    print(f"  - GGUF: {GGUF_OUTPUT}")
    print(f"  - Modelfile: Modelfile")
    print("=" * 60)
    print("\nTo deploy: ollama create aipam-trafficllm-v4 -f Modelfile")


if __name__ == "__main__":
    main()

