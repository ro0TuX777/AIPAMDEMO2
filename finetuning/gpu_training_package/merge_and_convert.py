#!/usr/bin/env python3
"""
Merge LoRA adapter with base model and convert to GGUF format.

Usage:
    python merge_and_convert.py

This will:
1. Load the base Llama 3.1 8B model
2. Load and merge the LoRA adapter
3. Save the merged model
4. Convert to GGUF format for Ollama
"""

import os
import subprocess
import shutil
from pathlib import Path

MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
LORA_DIR = "./aipam-llama-lora"
MERGED_DIR = "./aipam-llama-merged"
GGUF_OUTPUT = "./aipam-traffic-llm.gguf"


def merge_lora():
    """Merge LoRA adapter with base model."""
    print("=" * 60)
    print("Step 1: Merging LoRA adapter with base model")
    print("=" * 60)
    
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel
    
    print(f"Loading base model: {MODEL_NAME}")
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    
    print(f"Loading LoRA adapter from: {LORA_DIR}")
    model = PeftModel.from_pretrained(base_model, LORA_DIR)
    
    print("Merging weights...")
    model = model.merge_and_unload()
    
    print(f"Saving merged model to: {MERGED_DIR}")
    model.save_pretrained(MERGED_DIR, safe_serialization=True)
    
    # Save tokenizer too
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.save_pretrained(MERGED_DIR)
    
    print("Merge complete!")
    return True


def convert_to_gguf():
    """Convert merged model to GGUF format."""
    print("\n" + "=" * 60)
    print("Step 2: Converting to GGUF format")
    print("=" * 60)
    
    # Check if llama.cpp exists
    llama_cpp_dir = Path("./llama.cpp")
    if not llama_cpp_dir.exists():
        print("Cloning llama.cpp...")
        subprocess.run(["git", "clone", "https://github.com/ggerganov/llama.cpp"], check=True)
    
    # Install gguf if needed
    subprocess.run(["pip", "install", "gguf", "-q"], check=True)
    
    # Convert
    print(f"Converting {MERGED_DIR} to GGUF...")
    convert_script = llama_cpp_dir / "convert_hf_to_gguf.py"
    
    subprocess.run([
        "python", str(convert_script),
        MERGED_DIR,
        "--outfile", GGUF_OUTPUT,
        "--outtype", "q8_0",  # 8-bit quantization for good quality
    ], check=True)
    
    print(f"\nGGUF model saved to: {GGUF_OUTPUT}")
    return True


def create_modelfile():
    """Create Ollama Modelfile."""
    modelfile_content = '''FROM ./aipam-traffic-llm.gguf

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER stop "<|eot_id|>"

SYSTEM """You are a network traffic analysis expert. Analyze the provided packet data and classify the traffic type or detect malicious activity. Provide concise, accurate classifications."""
'''
    
    with open("Modelfile", "w") as f:
        f.write(modelfile_content)
    
    print("\nModelfile created!")
    print("\nTo import into Ollama:")
    print("  ollama create aipam-traffic-llm -f Modelfile")


def main():
    print("\n" + "=" * 60)
    print("AIPAM Model - Merge & Convert to GGUF")
    print("=" * 60 + "\n")
    
    # Check if LoRA exists
    if not Path(LORA_DIR).exists():
        print(f"ERROR: LoRA adapter not found at {LORA_DIR}")
        print("Please run train_cuda.py first!")
        return
    
    # Merge
    if not merge_lora():
        return
    
    # Convert
    if not convert_to_gguf():
        return
    
    # Create Modelfile
    create_modelfile()
    
    print("\n" + "=" * 60)
    print("SUCCESS! Files created:")
    print(f"  - {GGUF_OUTPUT} (transfer this to your Mac)")
    print(f"  - Modelfile")
    print("=" * 60)
    print("\nOn your Mac, run:")
    print("  ollama create aipam-traffic-llm -f Modelfile")
    print("  ollama run aipam-traffic-llm")


if __name__ == "__main__":
    main()

