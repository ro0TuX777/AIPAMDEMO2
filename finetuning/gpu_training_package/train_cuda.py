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
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

# Configuration
MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
OUTPUT_DIR = "./aipam-llama-lora"
MERGED_DIR = "./aipam-llama-merged"

# Training hyperparameters
NUM_EPOCHS = 3
BATCH_SIZE = 4
LEARNING_RATE = 2e-5
MAX_SEQ_LENGTH = 1024


def main():
    print("=" * 60)
    print("AIPAM Traffic Analysis Model - CUDA Training")
    print("=" * 60)
    
    # Check CUDA
    if not torch.cuda.is_available():
        print("ERROR: CUDA not available! This script requires an NVIDIA GPU.")
        return
    
    print(f"CUDA Device: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    
    # Load tokenizer
    print(f"\nLoading tokenizer from {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    
    # Quantization config for 4-bit training
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    
    # Load model
    print(f"Loading model {MODEL_NAME}...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
    )
    model = prepare_model_for_kbit_training(model)
    
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
        "train": "data/train.jsonl",
        "validation": "data/valid.jsonl"
    })
    print(f"Training samples: {len(dataset['train'])}")
    print(f"Validation samples: {len(dataset['validation'])}")
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=NUM_EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=2,
        learning_rate=LEARNING_RATE,
        weight_decay=0.01,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        logging_steps=50,
        save_steps=500,
        eval_steps=500,
        evaluation_strategy="steps",
        save_total_limit=3,
        bf16=True,
        gradient_checkpointing=True,
        report_to="none",
    )
    
    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        tokenizer=tokenizer,
        args=training_args,
    )
    
    # Train
    print("\n" + "=" * 60)
    print("Starting training...")
    print("=" * 60)
    trainer.train()
    
    # Save LoRA adapter
    print(f"\nSaving LoRA adapter to {OUTPUT_DIR}...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print(f"LoRA adapter saved to: {OUTPUT_DIR}")
    print("\nTo merge and convert to GGUF, run:")
    print("  python merge_and_convert.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

