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
from pathlib import Path


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
        # Use ChatML format
        text = tokenizer.apply_chat_template(
            sample["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
        formatted.append({"text": text})
    return formatted


def main():
    parser = argparse.ArgumentParser(description="Fine-tune llama3.1:8b for AIPAM")
    parser.add_argument("--data", default="data/training/train.jsonl", help="Training data path")
    parser.add_argument("--val-data", default="data/training/validation.jsonl", help="Validation data")
    parser.add_argument("--output", default="models/aipam-llama", help="Output model path")
    parser.add_argument("--base-model", default="unsloth/llama-3.1-8b-bnb-4bit", help="Base model")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Batch size per device")
    parser.add_argument("--learning-rate", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--lora-r", type=int, default=16, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=16, help="LoRA alpha")
    parser.add_argument("--max-seq-length", type=int, default=4096, help="Max sequence length")
    parser.add_argument("--export-gguf", action="store_true", help="Export to GGUF for Ollama")
    args = parser.parse_args()

    if not check_dependencies():
        return

    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import Dataset

    print("=" * 60)
    print("Fine-tuning llama3.1:8b for Network Traffic Analysis")
    print("=" * 60)

    # Load model with 4-bit quantization
    print(f"\nLoading base model: {args.base_model}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_seq_length,
        dtype=None,  # Auto-detect
        load_in_4bit=True,
    )

    # Add LoRA adapters
    print("Adding LoRA adapters...")
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
    training_args = TrainingArguments(
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        fp16=True,
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
        output_dir=args.output,
        save_strategy="epoch",
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

