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
from trl import SFTTrainer, SFTConfig

# Configuration
MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
OUTPUT_DIR = "./aipam-llama-lora"
MERGED_DIR = "./aipam-llama-merged"

# Training hyperparameters
NUM_EPOCHS = 1  # 1 epoch for 500K+ samples is sufficient
BATCH_SIZE = 1  # Minimal for limited VRAM
GRADIENT_ACCUMULATION = 16  # Effective batch size = 16
LEARNING_RATE = 2e-5
MAX_SEQ_LENGTH = 512  # Reduced for memory


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

    # Load model with memory optimization
    print(f"Loading model {MODEL_NAME}...")
    # Clear GPU cache before loading
    torch.cuda.empty_cache()

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
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
    
    # Load dataset - unified: cybersec reasoning + IOCs + malware PCAP traffic data
    print("\nLoading training data...")
    dataset = load_dataset("json", data_files={
        "train": "data/unified_train.jsonl",
        "validation": "data/unified_valid.jsonl"
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
        output_dir=OUTPUT_DIR,
        num_train_epochs=NUM_EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION,
        learning_rate=LEARNING_RATE,
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
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_text_field="text",
    )

    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        tokenizer=tokenizer,
        args=sft_config,
    )
    
    # Train (resume from checkpoint if available)
    print("\n" + "=" * 60)
    resume_checkpoint = os.path.join(OUTPUT_DIR, "checkpoint-18000")
    if os.path.exists(resume_checkpoint):
        print(f"Resuming training from {resume_checkpoint}...")
    else:
        print("Starting training from scratch...")
        resume_checkpoint = None
    print("=" * 60)
    trainer.train(resume_from_checkpoint=resume_checkpoint)
    
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

