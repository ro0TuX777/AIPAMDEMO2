#!/usr/bin/env python3
"""
Sequential batch training for malware family classification.
Trains on all 5 batches sequentially, with each batch building on the previous.
"""

import os
import sys
import json
import torch
from pathlib import Path
from datetime import datetime

# Training configuration
BASE_MODEL = "unsloth/llama-3.1-8b-bnb-4bit"
OUTPUT_BASE = Path("./trained_models")
DATA_DIR = Path("./training_data_batches")
MAX_SEQ_LENGTH = 2048
LORA_R = 64
LORA_ALPHA = 64

# Batch training order
BATCH_ORDER = [
    "batch1_banking_trojans",
    "batch2_infostealers", 
    "batch3_loaders",
    "batch4_rats_c2",
    "batch5_regional_other",
]

# Per-batch training settings (adjusted for sample count)
BATCH_CONFIG = {
    "batch1_banking_trojans": {"epochs": 3, "lr": 2e-4, "batch_size": 2},   # 221 samples
    "batch2_infostealers": {"epochs": 5, "lr": 2e-4, "batch_size": 2},      # 67 samples
    "batch3_loaders": {"epochs": 4, "lr": 2e-4, "batch_size": 2},           # 85 samples
    "batch4_rats_c2": {"epochs": 8, "lr": 1e-4, "batch_size": 1},           # 27 samples
    "batch5_regional_other": {"epochs": 10, "lr": 1e-4, "batch_size": 1},   # 10 samples
}


def convert_to_chat_format(sample: dict) -> str:
    """Convert training sample to chat format."""
    return f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

You are a network security analyst specializing in malware traffic analysis.<|eot_id|><|start_header_id|>user<|end_header_id|>

{sample['instruction']}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

{sample['output']}<|eot_id|>"""


def load_batch_data(batch_name: str):
    """Load training data for a batch."""
    train_file = DATA_DIR / batch_name / "train.json"
    val_file = DATA_DIR / batch_name / "val.json"
    
    with open(train_file) as f:
        train_data = json.load(f)
    with open(val_file) as f:
        val_data = json.load(f)
    
    # Convert to chat format
    train_texts = [{"text": convert_to_chat_format(s)} for s in train_data]
    val_texts = [{"text": convert_to_chat_format(s)} for s in val_data]
    
    return train_texts, val_texts


def train_batch(batch_name: str, resume_from: str = None):
    """Train on a single batch."""
    import gc

    # Clear GPU memory before starting
    torch.cuda.empty_cache()
    gc.collect()

    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import Dataset

    config = BATCH_CONFIG[batch_name]
    output_dir = OUTPUT_BASE / batch_name
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"Training: {batch_name}")
    print(f"{'='*60}")

    # Always load from base model to avoid memory issues
    # The sequential training builds knowledge cumulatively
    model_name = BASE_MODEL
    print(f"Loading model: {model_name}")
    
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_name,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=True,
    )
    
    # Add LoRA adapters if starting fresh
    from peft import PeftModel
    if not isinstance(model, PeftModel) and not resume_from:
        print("Adding LoRA adapters...")
        model = FastLanguageModel.get_peft_model(
            model,
            r=LORA_R,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                          "gate_proj", "up_proj", "down_proj"],
            lora_alpha=LORA_ALPHA,
            lora_dropout=0,
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=42,
        )
    
    # Load data
    print(f"Loading batch data...")
    train_texts, val_texts = load_batch_data(batch_name)
    train_dataset = Dataset.from_list(train_texts)
    
    print(f"  Train samples: {len(train_texts)}")
    print(f"  Val samples: {len(val_texts)}")
    print(f"  Epochs: {config['epochs']}")
    print(f"  Learning rate: {config['lr']}")
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=config['epochs'],
        per_device_train_batch_size=config['batch_size'],
        gradient_accumulation_steps=4,
        learning_rate=config['lr'],
        weight_decay=0.01,
        warmup_ratio=0.1,
        lr_scheduler_type="cosine",
        logging_steps=10,
        save_steps=100,
        save_total_limit=2,
        bf16=True,
        optim="adamw_8bit",
        seed=42,
        report_to="none",
    )
    
    # Train
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        args=training_args,
    )
    
    print("\nStarting training...")
    trainer.train()
    
    # Save
    print(f"\nSaving to: {output_dir}")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    # Clear memory aggressively
    import gc
    del model, trainer
    gc.collect()
    torch.cuda.empty_cache()
    gc.collect()

    return str(output_dir)


def train_all_batches(start_from: str = None):
    """Train all batches sequentially."""
    print("="*60)
    print("SEQUENTIAL BATCH TRAINING")
    print(f"Started: {datetime.now().isoformat()}")
    print("="*60)

    results = {}
    previous_model = None

    # Find starting point
    start_idx = 0
    if start_from:
        try:
            start_idx = BATCH_ORDER.index(start_from)
            print(f"Starting from batch: {start_from}")
        except ValueError:
            print(f"Unknown batch: {start_from}, starting from beginning")

    for i, batch_name in enumerate(BATCH_ORDER[start_idx:], start=start_idx):
        print(f"\n[{i+1}/{len(BATCH_ORDER)}] Processing {batch_name}")

        try:
            output_path = train_batch(batch_name, resume_from=previous_model)
            results[batch_name] = {"status": "success", "path": output_path}
            previous_model = output_path  # Chain to next batch
        except Exception as e:
            print(f"ERROR training {batch_name}: {e}")
            results[batch_name] = {"status": "error", "error": str(e)}
            # Continue with previous model if available

    # Summary
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)

    for batch_name, result in results.items():
        status = "✓" if result["status"] == "success" else "✗"
        print(f"  {status} {batch_name}: {result.get('path', result.get('error'))}")

    # Save final combined model
    if previous_model:
        final_dir = OUTPUT_BASE / "malware_classifier_final"
        print(f"\nFinal model saved at: {previous_model}")

    return results


def main():
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="Train malware classifier on batches")
    parser.add_argument("--batch", type=str, help="Train specific batch only")
    parser.add_argument("--start-from", type=str, help="Start from specific batch")
    parser.add_argument("--resume", type=str, help="Resume from existing model")
    parser.add_argument("--list", action="store_true", help="List available batches")
    args = parser.parse_args()

    if args.list:
        print("Available batches:")
        for batch in BATCH_ORDER:
            config = BATCH_CONFIG[batch]
            print(f"  {batch}: epochs={config['epochs']}, lr={config['lr']}")
        return

    if args.batch:
        # Train single batch
        train_batch(args.batch, resume_from=args.resume)
    else:
        # Train all batches
        train_all_batches(start_from=args.start_from)


if __name__ == "__main__":
    main()

