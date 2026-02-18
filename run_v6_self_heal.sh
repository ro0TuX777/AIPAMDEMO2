#!/bin/bash
# ============================================================
# AIPAM Phase 6.4+6.5: Self-Healing Forensic Loop (LocFT)
# Closed-loop: Verify → Extract Failures → Augment →
#   Breadth-First Buffer Gate → Surgical Delta Train → Re-verify
#
# Phase 6.5 additions:
#   - Breadth-First Buffer: waits for MIN_FAMILIES (default 3)
#     distinct families in data/raw/synthetic/ before training.
#   - LocFT mode: delta training uses --locft-mode (down_proj only,
#     layers 16-30) to surgically edit knowledge without forgetting.
# ============================================================
set -e

echo "============================================================"
echo "AIPAM V6.4+6.5: SELF-HEALING FORENSIC LOOP (LocFT)"
echo "============================================================"

source venv_unsloth/bin/activate

# ── Configuration ──
MODEL_PATH="${MODEL_PATH:-finetuning/aipam_gpu_training/aipam-llama-lora-v6}"
VALID_DATA="${VALID_DATA:-models/aipam-llama-balanced/valid.jsonl}"
VARIANTS_PER_FAMILY="${VARIANTS_PER_FAMILY:-50}"
DELTA_EPOCHS="${DELTA_EPOCHS:-2}"
MIN_FAMILIES="${MIN_FAMILIES:-3}"
SYNTH_DIR="finetuning/data/raw/synthetic"

# 1. Run Bias Verification — Extract Failing Families
echo "============================================================"
echo "[1/6] Running Bias Verification..."
echo "============================================================"

FAIL_LIST=$(python3 finetuning/verify_model_bias.py \
    --model "$MODEL_PATH" \
    --data "$VALID_DATA" 2>&1 | \
    grep -E "^\s+(❌|⚠️)" | \
    awk -F'[()]' '{print $2}' | \
    sed 's/T[0-9].*//;s/ *$//' | \
    sort -u | \
    paste -sd ',' - )

if [ -z "$FAIL_LIST" ]; then
    echo "  ✅ No failing families detected! Model is healthy."
    echo "  Self-healing loop complete (no action needed)."
    exit 0
fi

echo "  Failing families: $FAIL_LIST"

# 2. Generate Synthetic Augmentation Data
echo "============================================================"
echo "[2/6] Generating Synthetic PCAPs for: $FAIL_LIST"
echo "============================================================"

python3 finetuning/purple_team_augment.py \
    --fail-list "$FAIL_LIST" \
    --count "$VARIANTS_PER_FAMILY"

# 3. Phase 6.5 — Breadth-First Buffer Gate
#    Prevent "Catastrophic Overwriting" by requiring at least
#    MIN_FAMILIES distinct malware families before triggering training.
echo "============================================================"
echo "[3/6] Breadth-First Buffer Gate (min=${MIN_FAMILIES} families)..."
echo "============================================================"

if [ -d "$SYNTH_DIR" ]; then
    FAMILY_COUNT=$(find "$SYNTH_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
else
    FAMILY_COUNT=0
fi

echo "  Families in buffer: $FAMILY_COUNT / $MIN_FAMILIES required"

# List the families currently in the buffer
if [ "$FAMILY_COUNT" -gt 0 ]; then
    echo "  Current families:"
    find "$SYNTH_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | while read -r family; do
        file_count=$(find "$SYNTH_DIR/$family" -type f | wc -l | tr -d ' ')
        echo "    - ${family} (${file_count} files)"
    done
fi

if [ "$FAMILY_COUNT" -lt "$MIN_FAMILIES" ]; then
    echo ""
    echo "  ⏳ BUFFER HOLD: Only $FAMILY_COUNT/$MIN_FAMILIES families available."
    echo "  Training deferred until buffer reaches $MIN_FAMILIES distinct families."
    echo "  This prevents Catastrophic Overwriting from single-family training."
    echo ""
    echo "  Tip: Set MIN_FAMILIES=1 to override (not recommended for production)."
    echo "============================================================"
    echo "AIPAM V6.5: BUFFER HOLD — Waiting for more families"
    echo "============================================================"
    exit 0
fi

echo "  ✅ Buffer threshold met. Proceeding with Breadth-First training."

# 4. Process Synthetic PCAPs into Training Data
echo "============================================================"
echo "[4/6] Processing Synthetic PCAPs into Training Data..."
echo "============================================================"

python3 finetuning/process_training_data.py \
    --dataset synthetic

# 5. Delta LoRA Training (LocFT ORPO on augmented data)
echo "============================================================"
echo "[5/6] Delta LoRA Training (LocFT Surgical Mode)..."
echo "============================================================"

# Create balanced dataset from the augmented data
python3 finetuning/create_balanced_dataset.py --orpo

# Train delta LoRA on top of existing model
# Phase 6.5: --locft-mode targets only down_proj in layers 16-30
python3 finetuning/finetune_llama_orpo.py \
    --data models/aipam-llama-balanced/train.jsonl \
    --val-data models/aipam-llama-balanced/valid.jsonl \
    --output "${MODEL_PATH}-delta" \
    --epochs "$DELTA_EPOCHS" \
    --batch-size 2 \
    --gradient-accumulation 4 \
    --locft-mode

# 6. Re-verify (Confidence Check)
echo "============================================================"
echo "[6/6] Re-Verification (Post-Augmentation + LocFT)..."
echo "============================================================"

python3 finetuning/verify_model_bias.py \
    --model "${MODEL_PATH}-delta" \
    --data "$VALID_DATA"

echo "============================================================"
echo "AIPAM V6.4+6.5: SELF-HEALING LOOP COMPLETE (LocFT)"
echo "  Original failures: $FAIL_LIST"
echo "  Families trained:  $FAMILY_COUNT (Breadth-First)"
echo "  Augmented model:   ${MODEL_PATH}-delta"
echo "  Training mode:     LocFT (down_proj, layers 16-30)"
echo "============================================================"
