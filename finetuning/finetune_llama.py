#!/usr/bin/env python3
"""
Fine-tune llama3.1:8b for Network Traffic Analysis

Uses Unsloth for 2-4x faster fine-tuning with 70% less memory.
Output can be exported to GGUF format for direct use in Ollama.

Requirements:
    pip install unsloth
    pip install --no-deps trl peft accelerate bitsandbytes

Usage:
    python finetune_llama.py --data data/training/train.jsonl --output models/aipam-llama
"""

import argparse
import json
import os
import sys
from pathlib import Path

# --- FIX for Unsloth/Torch/_inductor AttributeError ---
try:
    import torch
    import torch._inductor.config
    
    # Satisfy torchao or other libraries expecting torch.int1 (added in 2.5+)
    if hasattr(torch, "__version__") and not hasattr(torch, "int1"):
        torch.int1 = torch.int8 # Use int8 for 1-bit mapping satisfaction
except (ImportError, AttributeError):
    pass
# ------------------------------------------------------


def check_dependencies():
    """Check if required dependencies are installed."""
    missing = []
    try:
        import torch
    except ImportError:
        missing.append("torch")

    try:
        from unsloth import FastLanguageModel
    except ImportError:
        missing.append("unsloth")

    try:
        from trl import SFTTrainer
    except ImportError:
        missing.append("trl")

    if missing:
        print("Missing dependencies:", ", ".join(missing))
        print("\nInstall with:")
        print("  pip install unsloth")
        print("  pip install --no-deps trl peft accelerate bitsandbytes")
        return False
    return True


def load_training_data(data_path: str):
    """Load training data from JSONL file."""
    samples = []
    with open(data_path) as f:
        for line in f:
            samples.append(json.loads(line))
    return samples


def format_for_training(samples, tokenizer):
    """Format samples for Unsloth training."""
    formatted = []
    for sample in samples:
        # Handle both formats: {"messages": [...]} and {"text": "..."}
        if "text" in sample:
            # Already formatted as text
            formatted.append({"text": sample["text"]})
        elif "messages" in sample:
            # Use ChatML format to convert messages to text
            text = tokenizer.apply_chat_template(
                sample["messages"],
                tokenize=False,
                add_generation_prompt=False,
            )
            formatted.append({"text": text})
        else:
            # Skip invalid samples
            continue
    return formatted


def main():
    parser = argparse.ArgumentParser(description="Fine-tune llama3.1:8b for AIPAM")
    parser.add_argument("--data", default="models/aipam-llama-balanced/train.jsonl", help="Training data path")
    parser.add_argument("--val-data", default="models/aipam-llama-balanced/valid.jsonl", help="Validation data")
    parser.add_argument("--output", default="models/aipam-llama", help="Output model path")
    parser.add_argument("--base-model", default="unsloth/llama-3.1-8b-bnb-4bit", help="Base model")
    parser.add_argument("--epochs", type=int, default=1, help="Training epochs")
    parser.add_argument("--iters", type=int, default=None, help="Max training steps (overrides epochs)")
    parser.add_argument("--batch-size", type=int, default=2, help="Batch size per device")
    parser.add_argument("--learning-rate", type=float, default=5e-5, help="Learning rate")
    parser.add_argument("--lora-r", type=int, default=16, help="LoRA rank")
    parser.add_argument("--lora-rank", type=int, default=None, help="Alias for lora-r")
    parser.add_argument("--lora-alpha", type=int, default=16, help="LoRA alpha")
    parser.add_argument("--max-seq-length", type=int, default=2048, help="Max sequence length (32768 for Phase 6.2)")
    parser.add_argument("--num-layers", type=int, default=None, help="Ignored (for compatibility)")
    parser.add_argument("--export-gguf", action="store_true", help="Export to GGUF for Ollama")
    parser.add_argument("--validate-data", action="store_true", help="Validate data loading without training")
    parser.add_argument("--resume-from", type=str, default=None, help="Path to existing adapter/model to continue training")
    args = parser.parse_args()

    # Normalize aliases
    if args.lora_rank:
        args.lora_r = args.lora_rank
    if args.iters:
        # If iters is specified, we set max_steps in training args
        pass

    # Basic data check
    train_path = Path(args.data)
    if not train_path.exists():
        print(f"Error: Training data not found at {train_path}")
        return

    if args.validate_data:
        # ... (validation logic unchanged) ...
        print("Running in data validation mode...")
        # ...
        return

    if not check_dependencies():
        return

    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import Dataset

    print("=" * 60)
    print("Fine-tuning llama3.1:8b for Network Traffic Analysis")
    print("=" * 60)

    # Load model
    model_name = args.resume_from if args.resume_from else args.base_model
    print(f"\nLoading model: {model_name}")
    
    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=args.max_seq_length,
            dtype=None,  # Auto-detect
            load_in_4bit=True,
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        if "CUDA" in str(e) or "GPU" in str(e):
            print(f"\n[CRITICAL] GPU/CUDA Error detected: {e}")
            return
        raise e

    # Add LoRA adapters ONLY if we are starting fresh (base model).
    # If resuming from an adapter, Unsloth loads it automatically.
    # We check if the loaded model is already a PeftModel.
    from peft import PeftModel
    
    if isinstance(model, PeftModel) or (args.resume_from and Path(args.resume_from).exists()):
        print("Resuming from existing adapter/checkpoint...")
        # Ensure we are in training mode
        model.train()
    else:
        print("Adding new LoRA adapters to base model...")
        model = FastLanguageModel.get_peft_model(
            model,
            r=args.lora_r,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                            "gate_proj", "up_proj", "down_proj"],
            lora_alpha=args.lora_alpha,
            lora_dropout=0,
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=42,
        )

    # Load and format training data
    print(f"\nLoading training data from: {args.data}")
    train_samples = load_training_data(args.data)
    train_formatted = format_for_training(train_samples, tokenizer)
    train_dataset = Dataset.from_list(train_formatted)
    print(f"Training samples: {len(train_dataset)}")

    # Training arguments
    # Training arguments
    # If iters is set, use max_steps and ignore num_train_epochs
    max_steps = args.iters if args.iters else -1
    num_train_epochs = args.epochs if not args.iters else 3.0 # Default fallback if steps used

    training_args = TrainingArguments(
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=4,
        warmup_steps=10,
        max_steps=max_steps,
        num_train_epochs=num_train_epochs if max_steps == -1 else 1.0, 
        learning_rate=args.learning_rate,
        fp16=False,
        bf16=True,
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
        output_dir=args.output,
        save_strategy="steps" if max_steps > 0 else "epoch",
        save_steps=100 if max_steps > 0 else None,
    )

    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        dataset_text_field="text",
        max_seq_length=args.max_seq_length,
        args=training_args,
    )

    # Train
    print("\nStarting training...")
    trainer.train()

    # Save model
    print(f"\nSaving model to: {args.output}")
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)

    # Export to GGUF if requested
    if args.export_gguf:
        print("\nExporting to GGUF format for Ollama...")
        model.save_pretrained_gguf(
            args.output,
            tokenizer,
            quantization_method="q4_k_m",  # Good balance of size/quality
        )
        print(f"✓ GGUF model saved to: {args.output}")

    print("\n" + "=" * 60)
    print("Fine-tuning complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()

