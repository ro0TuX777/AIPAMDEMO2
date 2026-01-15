#!/bin/bash
set -e

# AIPAM V5: Autonomous Forensic Intelligence Fine-Tuning
# Optimized for high-fidelity reasoning and zero-day detection.

echo "============================================================"
echo "AIPAM V5: TRAINING START"
echo "============================================================"

source venv_unsloth/bin/activate

# 1. Regenerate Balanced Dataset
echo "[1/3] Balancing V5 Dataset (203+ samples)..."
python3 finetuning/create_balanced_dataset.py

# 2. Run Fine-Tuning
echo "============================================================"
echo "[2/3] Executing V5 Fine-Tuning..."
echo "============================================================"

# We resume from v4 to maintain previous learnings
BASE_ADAPTER="finetuning/aipam_gpu_training/aipam-llama-lora-v4"

if [ ! -d "$BASE_ADAPTER" ]; then
    echo "Warning: v4 adapter not found. Starting from base llama-3.1."
    BASE_MODEL="unsloth/llama-3.1-8b-bnb-4bit"
else
    echo "Pivoting from v4 to v5..."
    BASE_MODEL="$BASE_ADAPTER"
fi

# V5: Train fresh from base model (cleaner approach than resuming)
# V4 knowledge will be supplemented by improved dataset
python3 finetuning/finetune_llama.py \
    --data finetuning/data/v5-balanced/train.jsonl \
    --val-data finetuning/data/v5-balanced/valid.jsonl \
    --output finetuning/aipam_gpu_training/aipam-llama-lora-v5 \
    --base-model "unsloth/llama-3.1-8b-bnb-4bit" \
    --lora-r 128 \
    --lora-alpha 128 \
    --batch-size 1 \
    --epochs 3 \
    --max-seq-length 4096 \
    --learning-rate 2e-4

# 3. Verify
echo "============================================================"
echo "[3/3] Verifying V5 Model Accuracy..."
echo "============================================================"
python3 finetuning/verify_model_bias.py \
    --model finetuning/aipam_gpu_training/aipam-llama-lora-v5 \
    --data finetuning/data/v5-balanced/valid.jsonl

echo "============================================================"
echo "V5 SUCCESS!"
echo "Model: finetuning/aipam_gpu_training/aipam-llama-lora-v5"
echo "============================================================"
