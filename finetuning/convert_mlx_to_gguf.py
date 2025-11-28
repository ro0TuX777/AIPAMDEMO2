#!/usr/bin/env python3
"""
Convert MLX fine-tuned model to GGUF format for Ollama.

This script:
1. Fuses LoRA adapters with base model
2. Converts to Hugging Face format
3. Converts to GGUF using llama.cpp

Requirements:
    pip install mlx mlx-lm huggingface_hub
    brew install llama.cpp  (or build from source)

Usage:
    python convert_mlx_to_gguf.py --model models/aipam-llama-mlx --output models/aipam-llama.gguf
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_convert_script():
    """Find the llama.cpp convert_hf_to_gguf.py script."""
    # Check common locations
    convert_paths = [
        Path.home() / "llama.cpp" / "convert_hf_to_gguf.py",
        Path("/opt/llama.cpp/convert_hf_to_gguf.py"),
        Path("./llama.cpp/convert_hf_to_gguf.py"),
    ]

    for path in convert_paths:
        if path.exists():
            return str(path)

    # Check if llama-gguf-convert exists (some brew versions)
    if shutil.which("llama-gguf-convert"):
        return "llama-gguf-convert"

    return None


def install_llama_cpp_python():
    """Install llama.cpp via pip for conversion."""
    try:
        import llama_cpp
        return True
    except ImportError:
        print("Installing llama-cpp-python for GGUF conversion...")
        subprocess.run([sys.executable, "-m", "pip", "install", "llama-cpp-python"], check=True)
        return True


def main():
    parser = argparse.ArgumentParser(description="Convert MLX model to GGUF")
    parser.add_argument("--model", default="models/aipam-llama-mlx", help="MLX model path")
    parser.add_argument("--adapter-path", default=None, help="LoRA adapter path (if not fused)")
    parser.add_argument("--base-model", default="mlx-community/Meta-Llama-3.1-8B-Instruct-4bit", help="Base model")
    parser.add_argument("--output", default="models/aipam-llama.gguf", help="Output GGUF path")
    parser.add_argument("--quantize", default="q4_k_m", help="Quantization type")
    args = parser.parse_args()

    print("=" * 60)
    print("Convert MLX Model to GGUF for Ollama")
    print("=" * 60)

    model_path = Path(args.model)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    adapter_path = args.adapter_path or model_path / "adapters"

    # Step 1: Fuse LoRA adapters with base model
    fused_path = model_path / "fused"
    
    if not fused_path.exists():
        print("\n[1/3] Fusing LoRA adapters with base model...")
        cmd = [
            sys.executable, "-m", "mlx_lm.fuse",
            "--model", args.base_model,
            "--adapter-path", str(adapter_path),
            "--save-path", str(fused_path),
        ]
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
    else:
        print(f"\n[1/3] Using existing fused model: {fused_path}")

    # Step 2: Convert to Hugging Face format
    hf_path = model_path / "hf"
    
    if not hf_path.exists():
        print("\n[2/3] Converting to Hugging Face format...")
        # MLX models are already in a HF-compatible format after fusing
        # Just need to ensure config.json and tokenizer are present
        hf_path.mkdir(parents=True, exist_ok=True)
        
        # Copy files from fused model
        for f in fused_path.glob("*"):
            if f.is_file():
                shutil.copy(f, hf_path)
        
        print(f"  HF model saved to: {hf_path}")
    else:
        print(f"\n[2/3] Using existing HF model: {hf_path}")

    # Step 3: Convert to GGUF
    print("\n[3/3] Converting to GGUF format...")

    # Try using the mlx_lm built-in conversion first
    try:
        print("Attempting conversion via mlx_lm...")
        cmd = [
            sys.executable, "-m", "mlx_lm", "convert",
            "--hf-path", str(hf_path),
            "--mlx-path", str(model_path / "mlx_converted"),
            "--quantize",
        ]
        # This may not produce GGUF directly, so we'll use llama.cpp
    except Exception:
        pass

    # Clone llama.cpp if not available and use convert script
    llama_cpp_dir = Path("llama.cpp")
    convert_script = find_convert_script()

    if convert_script is None:
        print("llama.cpp not found. Cloning repository...")
        if not llama_cpp_dir.exists():
            subprocess.run([
                "git", "clone", "--depth", "1",
                "https://github.com/ggerganov/llama.cpp.git"
            ], check=True)
        convert_script = str(llama_cpp_dir / "convert_hf_to_gguf.py")

    if not Path(convert_script).exists() and convert_script != "llama-gguf-convert":
        print(f"\nError: Convert script not found at {convert_script}")
        print("\nManual steps:")
        print("  git clone https://github.com/ggerganov/llama.cpp")
        print(f"  python llama.cpp/convert_hf_to_gguf.py {hf_path} --outfile {output_path}")
        return

    # Install required dependencies for conversion
    print("Installing conversion dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "gguf", "numpy", "sentencepiece", "transformers"], check=True)

    # Run conversion
    if convert_script == "llama-gguf-convert":
        cmd = [convert_script, str(hf_path), str(output_path)]
    else:
        cmd = [sys.executable, convert_script, str(hf_path), "--outfile", str(output_path), "--outtype", "f16"]

    print(f"Running: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f"\n✓ GGUF model saved to: {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"\nConversion failed: {e}")
        print("\nManual conversion steps:")
        print(f"  1. pip install gguf numpy sentencepiece transformers")
        print(f"  2. git clone https://github.com/ggerganov/llama.cpp")
        print(f"  3. python llama.cpp/convert_hf_to_gguf.py {hf_path} --outfile {output_path}")
        return

    print("\n" + "=" * 60)
    print("Conversion complete!")
    print("=" * 60)
    print(f"\nImport to Ollama with:")
    print(f"  ./import_to_ollama.sh {output_path} aipam-traffic-llm")


if __name__ == "__main__":
    main()

