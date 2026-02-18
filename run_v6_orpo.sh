#!/bin/bash
set -e

# AIPAM V6: ORPO Fine-Tuning — Contrastive Evidentiary Training
# Phase 6.1: Penalize forensic hallucinations via preference optimization.
#
# This script follows the same 3-step pattern as run_v5_tuning.sh:
#   1. Generate ORPO preference-pair dataset
#   2. Run ORPO fine-tuning with DAWN seed (3407)
#   3. Verify model accuracy + hallucination rate

echo "============================================================"
echo "AIPAM V6: ORPO TRAINING START"
echo "============================================================"

source venv_unsloth/bin/activate

# 0. VRAM Pre-flight Check (Phase 6.2)
echo "[0/3] VRAM Pre-flight Check..."
python3 finetuning/vram_monitor.py || echo "⚠️  No GPU detected (will fail at training step)"

# 1. Generate ORPO Preference-Pair Dataset (Session-Level IR)
echo "[1/3] Generating ORPO Preference Pairs (Session-Level IR)..."
python3 finetuning/create_balanced_dataset.py --orpo --session-ir

# 2. Run ORPO Fine-Tuning (32k Context — Phase 6.2)
echo "============================================================"
echo "[2/3] Executing ORPO Fine-Tuning (Phase 6.1+6.2, 32k Context)..."
echo "============================================================"

python3 finetuning/finetune_llama_orpo.py \
    --data finetuning/data/v6-orpo/train.jsonl \
    --val-data finetuning/data/v6-orpo/valid.jsonl \
    --output finetuning/aipam_gpu_training/aipam-llama-lora-v6 \
    --base-model "unsloth/llama-3.1-8b-bnb-4bit" \
    --lora-r 128 \
    --lora-alpha 128 \
    --batch-size 1 \
    --gradient-accumulation 8 \
    --epochs 3 \
    --max-seq-length 32768 \
    --learning-rate 5e-5 \
    --beta 0.1

# 3. Verify
echo "============================================================"
echo "[3/3] Verifying V6 Model Accuracy + Hallucination Rate..."
echo "============================================================"
python3 finetuning/verify_model_bias.py \
    --model finetuning/aipam_gpu_training/aipam-llama-lora-v6 \
    --data finetuning/data/v6-orpo/valid.jsonl

echo "============================================================"
echo "V6 ORPO SUCCESS!"
echo "Model: finetuning/aipam_gpu_training/aipam-llama-lora-v6"
echo "DAWN Ledger: finetuning/dawn_training_ledger.jsonl"
echo "============================================================"
