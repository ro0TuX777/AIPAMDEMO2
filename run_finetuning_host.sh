#!/bin/bash
set -e

# AIPAM Fine-Tuning Execution Script
# Run this on your host machine with NVIDIA GPU access.

echo "============================================================"
echo "AIPAM: Fine-Tuning Llama 3 for Malware Forensics"
echo "============================================================"

# 1. Check for Python/Pip
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 could not be found."
    exit 1
fi

echo "[1/3] Setting up Python environment..."
# Create venv if it doesn't exist
if [ ! -d "venv_unsloth" ]; then
    echo "Creating virtual environment 'venv_unsloth'..."
    python3 -m venv venv_unsloth
fi

source venv_unsloth/bin/activate

# Install dependencies (Unsloth optimized)
echo "Installing Unsloth and dependencies..."
pip install --upgrade pip

# Force specific stable versions in a single pass to avoid resolver conflicts
# We pin EVERYTHING to avoid pip trying to be smart.
pip install --no-cache-dir --force-reinstall \
    "torch==2.4.0+cu121" \
    "torchvision==0.19.0+cu121" \
    "torchaudio==2.4.0+cu121" \
    "unsloth[cu121-torch240] @ git+https://github.com/unslothai/unsloth.git" \
    "trl<0.10.0" "peft" "accelerate" "bitsandbytes" "datasets" \
    --index-url https://download.pytorch.org/whl/cu121

# Fix for common Unsloth/Torchao/Transformers conflict
pip uninstall -y torchao || true

# 2. Run Fine-Tuning
echo "============================================================"
echo "[2/3] Configuring Training..."
echo "============================================================"

# Auto-detect existing model
DETECTED_MODEL=""
if [ -d "finetuning/aipam_gpu_training/aipam-llama-lora-v3" ]; then
    DETECTED_MODEL="finetuning/aipam_gpu_training/aipam-llama-lora-v3"
elif [ -d "finetuning/aipam_gpu_training/aipam-llama-lora-v2" ]; then
    DETECTED_MODEL="finetuning/aipam_gpu_training/aipam-llama-lora-v2"
elif [ -d "finetuning/aipam_gpu_training/aipam-llama-lora" ]; then
    DETECTED_MODEL="finetuning/aipam_gpu_training/aipam-llama-lora"
fi

if [ -n "$DETECTED_MODEL" ]; then
    read -p "Found existing model at '$DETECTED_MODEL'. Resume from here? [Y/n]: " use_detected
    if [[ "$use_detected" =~ ^[Yy]$ || -z "$use_detected" ]]; then
        existing_model="$DETECTED_MODEL"
    else
        read -p "Enter path to different model (leave empty to start fresh): " existing_model
    fi
else
    read -p "Enter path to existing model/adapter to RESUME training (leave empty to start fresh): " existing_model
fi

if [ -n "$existing_model" ]; then
    echo "Resuming training from: $existing_model"
    RESUME_FLAG="--resume-from $existing_model"
else
    echo "Starting fresh with unsloth/llama-3.1-8b-bnb-4bit..."
    RESUME_FLAG=""
fi

echo "Starting training job..."

python3 finetuning/finetune_llama.py \
    --data finetuning/models/aipam-llama-balanced/train.jsonl \
    --val-data finetuning/models/aipam-llama-balanced/valid.jsonl \
    --output finetuning/models/aipam-llama \
    --epochs 3 \
    --export-gguf \
    $RESUME_FLAG

# 3. Verify
echo "============================================================"
echo "[3/3] Verifying Model Bias..."
echo "============================================================"
python3 finetuning/verify_model_bias.py \
    --model finetuning/models/aipam-llama \
    --data finetuning/models/aipam-llama-balanced/valid.jsonl

echo "============================================================"
echo "SUCCESS: Model fine-tuned and verified!"
echo "GGUF model is located at: finetuning/models/aipam-llama"
echo "============================================================"
