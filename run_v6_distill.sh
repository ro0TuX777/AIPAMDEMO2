#!/bin/bash
# ============================================================
# AIPAM Phase 6.3: Specialist Distillation (AIPAM-Edge)
# Teacher: unsloth/llama-3.1-8b-bnb-4bit
# Student: unsloth/Llama-3.2-1B-Instruct-bnb-4bit
# ============================================================
set -e

echo "============================================================"
echo "AIPAM V6.3: SPECIALIST DISTILLATION START"
echo "============================================================"

source venv_unsloth/bin/activate

# 0. VRAM Pre-flight Check
echo "[0/3] VRAM Pre-flight Check..."
python3 finetuning/vram_monitor.py || echo "⚠️  No GPU detected (will fail at inference/training steps)"

# 1. Generate Teacher Labels
echo "============================================================"
echo "[1/3] Running Teacher (8B) Labeling..."
echo "============================================================"

python3 finetuning/distill_generate_labels.py \
    --data finetuning/data/processed/processed_samples_v5.jsonl \
    --teacher-model "unsloth/llama-3.1-8b-bnb-4bit" \
    --output-dir finetuning/data/v6-distill \
    --max-seq-length 32768

# 2. Train Student (1B) with ORPO
echo "============================================================"
echo "[2/3] Training AIPAM-Edge 1B Student..."
echo "============================================================"

python3 finetuning/finetune_llama_distill.py \
    --data finetuning/data/v6-distill/teacher_orpo_train.jsonl \
    --val-data finetuning/data/v6-distill/teacher_orpo_valid.jsonl \
    --output finetuning/aipam_gpu_training/aipam-edge-1b-v6 \
    --student-model "unsloth/Llama-3.2-1B-Instruct-bnb-4bit" \
    --lora-r 64 \
    --lora-alpha 64 \
    --batch-size 2 \
    --gradient-accumulation 4 \
    --epochs 3 \
    --max-seq-length 8192 \
    --learning-rate 5e-5 \
    --beta 0.1 \
    --export-gguf

# 3. Verify Retention (Teacher vs Student)
echo "============================================================"
echo "[3/3] Retention Verification (Teacher vs Student)..."
echo "============================================================"
python3 finetuning/verify_model_bias.py \
    --model finetuning/aipam_gpu_training/aipam-edge-1b-v6 \
    --data finetuning/data/v6-distill/teacher_orpo_valid.jsonl \
    --compare-teacher \
    --teacher-model "unsloth/llama-3.1-8b-bnb-4bit"

echo "============================================================"
echo "AIPAM V6.3: DISTILLATION COMPLETE"
echo "============================================================"
