#!/usr/bin/env python3
"""
AIPAM Traffic Analysis Model - CUDA Training Script
Fine-tunes Llama 3.1 8B on network traffic classification data.

Usage:
    python train_cuda.py

Requirements:
    - NVIDIA GPU with 16GB+ VRAM (24GB recommended)
    - CUDA 11.8+ installed
    - See requirements.txt for Python dependencies
"""

import os
import argparse
from pathlib import Path
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

SCRIPT_DIR = Path(__file__).resolve().parent

# Defaults (can be overridden via CLI)
MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"

# Training hyperparameters
DEFAULT_NUM_EPOCHS = 1  # 1 epoch for 500K+ samples is sufficient
DEFAULT_BATCH_SIZE = 1  # Minimal for limited VRAM
DEFAULT_GRADIENT_ACCUMULATION = 16  # Effective batch size = 16
DEFAULT_LEARNING_RATE = 2e-5
DEFAULT_MAX_SEQ_LENGTH = 512  # Reduced for memory


def _resolve_path(p: str) -> str:
    """Resolve a potentially-relative path against this script directory."""
    path = Path(p)
    if not path.is_absolute():
        path = (SCRIPT_DIR / path).resolve()
    return str(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AIPAM Traffic Analysis Model - CUDA Training")
    parser.add_argument(
        "--train-file",
        default="data/unified_train.jsonl",
        help="Training JSONL path (relative to this script dir unless absolute)",
    )
    parser.add_argument(
        "--valid-file",
        default="data/unified_valid.jsonl",
        help="Validation JSONL path (relative to this script dir unless absolute)",
    )
    parser.add_argument(
        "--output-dir",
        default="./aipam-llama-lora",
        help="Output directory for checkpoints/adapters (relative to this script dir unless absolute)",
    )
    parser.add_argument("--model-name", default=MODEL_NAME, help="Base model id")
    parser.add_argument("--epochs", type=int, default=DEFAULT_NUM_EPOCHS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--grad-accum", type=int, default=DEFAULT_GRADIENT_ACCUMULATION)
    parser.add_argument("--learning-rate", type=float, default=DEFAULT_LEARNING_RATE)
    parser.add_argument("--max-seq-length", type=int, default=DEFAULT_MAX_SEQ_LENGTH)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from latest checkpoint in output dir if present",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print("AIPAM Traffic Analysis Model - CUDA Training")
    print("=" * 60)
    
    # Check CUDA
    if not torch.cuda.is_available():
        print("ERROR: CUDA not available! This script requires an NVIDIA GPU.")
        return
    
    print(f"CUDA Device: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    
    # Resolve paths
    train_file = _resolve_path(args.train_file)
    valid_file = _resolve_path(args.valid_file)
    output_dir = _resolve_path(args.output_dir)

    # Load tokenizer
    print(f"\nLoading tokenizer from {args.model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    
    # Quantization config for 4-bit training
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    # Load model with memory optimization
    print(f"Loading model {args.model_name}...")
    # Clear GPU cache before loading
    torch.cuda.empty_cache()

    model = AutoModelForCausalLM.from_pretrained(
        args.model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        low_cpu_mem_usage=True,
        torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    
    # LoRA configuration
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    
    # Load dataset
    print("\nLoading training data...")
    dataset = load_dataset("json", data_files={
        "train": train_file,
        "validation": valid_file,
    })
    print(f"Training samples: {len(dataset['train'])}")
    print(f"Validation samples: {len(dataset['validation'])}")

    # Preprocess dataset to add text column from messages
    def preprocess_messages(example):
        """Convert messages format to text for training."""
        messages = example.get("messages", [])
        if messages:
            text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        else:
            text = ""
        return {"text": text}

    print("Preprocessing training data...")
    dataset = dataset.map(preprocess_messages, num_proc=4, desc="Formatting")

    # SFT Config (combines TrainingArguments + SFT-specific settings)
    sft_config = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        logging_steps=100,
        save_steps=2000,
        eval_steps=2000,
        eval_strategy="steps",
        save_total_limit=3,
        bf16=True,
        gradient_checkpointing=True,
        report_to="none",
        max_length=args.max_seq_length,
        dataset_text_field="text",
    )

    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        processing_class=tokenizer,
        args=sft_config,
    )
    
    # Train (optionally resume from latest checkpoint)
    print("\n" + "=" * 60)
    resume_checkpoint = None
    if args.resume and os.path.isdir(output_dir):
        # pick numerically largest checkpoint-XXXXX if any
        ckpts = []
        for name in os.listdir(output_dir):
            if name.startswith("checkpoint-"):
                suffix = name.split("checkpoint-", 1)[-1]
                if suffix.isdigit():
                    ckpts.append((int(suffix), os.path.join(output_dir, name)))
        if ckpts:
            ckpts.sort(key=lambda x: x[0])
            resume_checkpoint = ckpts[-1][1]
            print(f"Resuming training from {resume_checkpoint}...")
    if resume_checkpoint is None:
        print("Starting training from scratch...")
    print("=" * 60)
    trainer.train(resume_from_checkpoint=resume_checkpoint)
    
    # Save LoRA adapter
    print(f"\nSaving LoRA adapter to {output_dir}...")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print(f"LoRA adapter saved to: {output_dir}")
    print("\nTo merge and convert to GGUF, run:")
    print("  python merge_and_convert.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

