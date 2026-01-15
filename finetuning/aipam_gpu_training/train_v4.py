#!/usr/bin/env python3
"""
AIPAM Traffic Analysis Model - V4 Training Script
Fine-tunes from LoRA v3 with improved malware classification focus.

This script continues training from v3 checkpoint with emphasis on:
- Better classification of known malware families
- Reduced bias toward "Anomalous/Zero-Day" for known threats
- Improved forensic reasoning

Usage:
    python train_v4.py
    python train_v4.py --resume  # Resume from latest checkpoint
"""

import os
import sys
import glob
import torch
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, PeftModel
from trl import SFTTrainer, SFTConfig

# Configuration
MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
EXISTING_LORA = "./aipam-llama-lora-v3"  # Continue from v3
OUTPUT_DIR = "./aipam-llama-lora-v4"
MERGED_DIR = "./aipam-llama-merged-v4"

# Training hyperparameters - optimized for small high-quality v4 dataset (35 samples)
NUM_EPOCHS = 5  # More epochs since small dataset
BATCH_SIZE = 1
GRADIENT_ACCUMULATION = 4  # Smaller accumulation for faster feedback on small dataset
LEARNING_RATE = 2e-5  # Slightly higher LR for targeted refinement
MAX_SEQ_LENGTH = 1024  # Increased for CoT reasoning samples

# Check for resume flag
RESUME_FROM_CHECKPOINT = "--resume" in sys.argv


def main():
    print("=" * 60)
    print("AIPAM Traffic Analysis Model - V4 Training")
    print("Resuming from LoRA v3")
    print("=" * 60)
    
    if not torch.cuda.is_available():
        print("ERROR: CUDA not available!")
        return
    
    print(f"CUDA Device: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    
    # Load tokenizer
    print(f"\nLoading tokenizer from {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    
    # Quantization config
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    torch.cuda.empty_cache()

    # Load base model
    print(f"Loading model {MODEL_NAME}...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        low_cpu_mem_usage=True,
        torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    
    # Load existing LoRA from v3
    if os.path.exists(EXISTING_LORA):
        print(f"Loading existing LoRA from {EXISTING_LORA}...")
        model = PeftModel.from_pretrained(model, EXISTING_LORA, is_trainable=True)
    else:
        print(f"ERROR: LoRA v3 not found at {EXISTING_LORA}")
        print("Please ensure v3 training is complete before running v4 training.")
        return
    
    model.print_trainable_parameters()
    
    # Load dataset - v4 balanced dataset with behavioral heuristics and CoT reasoning
    # This curated dataset addresses "Loader" bias and improves malware classification
    print("\nLoading v4 training data...")
    dataset = load_dataset("json", data_files={
        "train": "/home/bc/Documents/AIPAM/finetuning/models/aipam-llama-balanced/train.jsonl",
        "validation": "/home/bc/Documents/AIPAM/finetuning/models/aipam-llama-balanced/valid.jsonl"
    })
    print(f"Training samples: {len(dataset['train'])}")
    print(f"Validation samples: {len(dataset['validation'])}")

    def preprocess_messages(example):
        messages = example.get("messages", [])
        if messages:
            text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        else:
            text = ""
        return {"text": text}

    print("Preprocessing...")
    dataset = dataset.map(preprocess_messages, num_proc=4, desc="Formatting")

    sft_config = SFTConfig(
        output_dir=OUTPUT_DIR,
        num_train_epochs=NUM_EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION,
        learning_rate=LEARNING_RATE,
        weight_decay=0.01,
        warmup_ratio=0.1,  # Longer warmup for small dataset
        lr_scheduler_type="cosine",
        logging_steps=5,   # More frequent logging for small dataset
        save_steps=50,     # Save more often for small dataset
        eval_steps=20,     # Evaluate more frequently
        eval_strategy="steps",
        save_total_limit=3,
        bf16=True,
        gradient_checkpointing=True,
        report_to="none",
        dataset_text_field="text",
        max_length=MAX_SEQ_LENGTH,
    )

    trainer = SFTTrainer(
        model=model, train_dataset=dataset["train"], eval_dataset=dataset["validation"],
        processing_class=tokenizer, args=sft_config,
    )
    
    # Find latest checkpoint if resuming
    checkpoint_path = None
    if RESUME_FROM_CHECKPOINT:
        checkpoints = glob.glob(os.path.join(OUTPUT_DIR, "checkpoint-*"))
        if checkpoints:
            checkpoint_path = max(checkpoints, key=os.path.getctime)
            print(f"\n>>> Resuming from checkpoint: {checkpoint_path}")
        else:
            print("\n>>> No checkpoint found, starting fresh v4 training from v3 base")

    print("\nStarting training...")
    trainer.train(resume_from_checkpoint=checkpoint_path)

    print(f"\nSaving LoRA adapter to {OUTPUT_DIR}...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    print("\n" + "=" * 60)
    print("V4 Training complete!")
    print(f"LoRA adapter saved to: {OUTPUT_DIR}")
    print("To merge and convert: python merge_and_convert.py --version v4")
    print("=" * 60)


if __name__ == "__main__":
    main()

