#!/usr/bin/env python3
"""
Fine-tune llama3.1:8b for Network Traffic Analysis on Apple Silicon (M1/M2/M3)

Uses MLX for efficient fine-tuning on Apple Silicon Macs.
Output can be converted to GGUF format for use in Ollama.

Requirements:
    pip install mlx mlx-lm

Usage:
    python finetune_mlx.py --data data/training/train.jsonl --output models/aipam-llama
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def check_dependencies():
    """Check if required dependencies are installed."""
    missing = []
    try:
        import mlx
        import mlx.core as mx
    except ImportError:
        missing.append("mlx")

    try:
        import mlx_lm
    except ImportError:
        missing.append("mlx-lm")

    if missing:
        print("Missing dependencies:", ", ".join(missing))
        print("\nInstall with:")
        print("  pip install mlx mlx-lm")
        return False
    return True


def convert_to_mlx_format(input_file: str, output_file: str):
    """Convert ChatML JSONL to MLX training format."""
    samples = []
    with open(input_file) as f:
        for line in f:
            data = json.loads(line)
            # MLX-LM expects {"text": "..."} format with chat template applied
            messages = data.get("messages", [])
            
            # Build conversation text
            text_parts = []
            for msg in messages:
                role = msg["role"]
                content = msg["content"]
                if role == "system":
                    text_parts.append(f"<|start_header_id|>system<|end_header_id|>\n\n{content}<|eot_id|>")
                elif role == "user":
                    text_parts.append(f"<|start_header_id|>user<|end_header_id|>\n\n{content}<|eot_id|>")
                elif role == "assistant":
                    text_parts.append(f"<|start_header_id|>assistant<|end_header_id|>\n\n{content}<|eot_id|>")
            
            samples.append({"text": "".join(text_parts)})
    
    with open(output_file, "w") as f:
        for sample in samples:
            f.write(json.dumps(sample) + "\n")
    
    return len(samples)


def main():
    parser = argparse.ArgumentParser(description="Fine-tune llama3.1:8b on Apple Silicon")
    parser.add_argument("--data", default="data/training/train.jsonl", help="Training data path")
    parser.add_argument("--val-data", default="data/training/validation.jsonl", help="Validation data")
    parser.add_argument("--output", default="models/aipam-llama-mlx", help="Output model path")
    parser.add_argument("--base-model", default="mlx-community/Meta-Llama-3.1-8B-Instruct-4bit", help="Base model")
    parser.add_argument("--batch-size", type=int, default=2, help="Batch size")
    parser.add_argument("--iters", type=int, default=1000, help="Training iterations")
    parser.add_argument("--learning-rate", type=float, default=1e-5, help="Learning rate")
    parser.add_argument("--lora-rank", type=int, default=8, help="LoRA rank")
    parser.add_argument("--num-layers", type=int, default=16, help="Number of LoRA layers")
    parser.add_argument("--max-seq-length", type=int, default=1024, help="Max sequence length (prevents OOM from long samples)")
    parser.add_argument("--grad-checkpoint", action="store_true", default=True, help="Use gradient checkpointing")
    args = parser.parse_args()

    if not check_dependencies():
        return

    print("=" * 60)
    print("Fine-tuning llama3.1:8b on Apple Silicon (MLX)")
    print("=" * 60)

    # Create output directory
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    # Convert training data to MLX format
    mlx_train = output_path / "train.jsonl"
    mlx_val = output_path / "valid.jsonl"

    print(f"\nConverting training data...")
    train_count = convert_to_mlx_format(args.data, str(mlx_train))
    print(f"  Training samples: {train_count}")

    if Path(args.val_data).exists():
        val_count = convert_to_mlx_format(args.val_data, str(mlx_val))
        print(f"  Validation samples: {val_count}")

    # Use the specified iterations
    iters = args.iters

    print(f"\nStarting fine-tuning with MLX...")
    print(f"  Base model: {args.base_model}")
    print(f"  LoRA rank: {args.lora_rank}")
    print(f"  Num layers: {args.num_layers}")
    print(f"  Iterations: {iters}")
    print(f"  Batch size: {args.batch_size}")
    print(f"  Max seq length: {args.max_seq_length}")
    print(f"  Learning rate: {args.learning_rate}")
    print(f"  Grad checkpoint: {args.grad_checkpoint}")

    # Run MLX-LM fine-tuning (using updated CLI format)
    cmd = [
        sys.executable, "-m", "mlx_lm", "lora",
        "--model", args.base_model,
        "--train",
        "--data", str(output_path),
        "--iters", str(iters),
        "--batch-size", str(args.batch_size),
        "--learning-rate", str(args.learning_rate),
        "--num-layers", str(args.num_layers),
        "--max-seq-length", str(args.max_seq_length),
        "--adapter-path", str(output_path / "adapters"),
    ]

    # Add gradient checkpointing if requested
    if args.grad_checkpoint:
        cmd.append("--grad-checkpoint")

    print(f"\nRunning: {' '.join(cmd)}\n")
    subprocess.run(cmd, check=True)

    print("\n" + "=" * 60)
    print("Fine-tuning complete!")
    print("=" * 60)
    print(f"\nAdapter saved to: {output_path / 'adapters'}")
    print("\nNext steps:")
    print("  1. Fuse adapters: python -m mlx_lm.fuse --model <base> --adapter-path <adapters>")
    print("  2. Convert to GGUF: python convert_mlx_to_gguf.py")
    print("  3. Import to Ollama: ./import_to_ollama.sh")


if __name__ == "__main__":
    main()

