#!/usr/bin/env python3
"""
AIPAM Traffic Analysis Model - Continued Training Script
Fine-tunes the existing model with new malware traffic data.

This script continues training from an existing LoRA checkpoint with new data.
Supports resume from checkpoint.

Usage:
    python train_continued.py
    python train_continued.py --resume  # Resume from latest checkpoint
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
EXISTING_LORA = "./aipam-llama-lora"  # Use None to start fresh
OUTPUT_DIR = "./aipam-llama-lora-v2"
MERGED_DIR = "./aipam-llama-merged-v2"

# Training hyperparameters
NUM_EPOCHS = 1
BATCH_SIZE = 1
GRADIENT_ACCUMULATION = 16
LEARNING_RATE = 1e-5  # Lower LR for continued training
MAX_SEQ_LENGTH = 512

# Check for resume flag
RESUME_FROM_CHECKPOINT = "--resume" in sys.argv


def main():
    print("=" * 60)
    print("AIPAM Traffic Analysis Model - Continued Training")
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
    
    # Load existing LoRA or create new
    if EXISTING_LORA and os.path.exists(EXISTING_LORA):
        print(f"Loading existing LoRA from {EXISTING_LORA}...")
        model = PeftModel.from_pretrained(model, EXISTING_LORA, is_trainable=True)
    else:
        print("Creating new LoRA adapter...")
        lora_config = LoraConfig(
            r=16, lora_alpha=32, lora_dropout=0.05,
            target_modules=["q_proj", "v_proj", "k_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)
    
    model.print_trainable_parameters()
    
    # Load dataset
    print("\nLoading training data...")
    dataset = load_dataset("json", data_files={
        "train": "data/new_unified_train.jsonl",
        "validation": "data/new_unified_valid.jsonl"
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
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        logging_steps=100,
        save_steps=3000,
        eval_steps=3000,
        eval_strategy="steps",
        save_total_limit=3,
        bf16=True,
        gradient_checkpointing=True,
        report_to="none",
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_text_field="text",
    )

    trainer = SFTTrainer(
        model=model, train_dataset=dataset["train"], eval_dataset=dataset["validation"],
        tokenizer=tokenizer, args=sft_config,
    )
    
    # Find latest checkpoint if resuming
    checkpoint_path = None
    if RESUME_FROM_CHECKPOINT:
        checkpoints = glob.glob(os.path.join(OUTPUT_DIR, "checkpoint-*"))
        if checkpoints:
            checkpoint_path = max(checkpoints, key=os.path.getctime)
            print(f"\n>>> Resuming from checkpoint: {checkpoint_path}")
        else:
            print("\n>>> No checkpoint found, starting fresh training")

    print("\nStarting training...")
    trainer.train(resume_from_checkpoint=checkpoint_path)

    print(f"\nSaving LoRA adapter to {OUTPUT_DIR}...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    print("\n" + "=" * 60)
    print("Training complete!")
    print(f"LoRA adapter saved to: {OUTPUT_DIR}")
    print("To merge and convert: python merge_and_convert.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

