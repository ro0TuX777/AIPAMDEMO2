#!/bin/bash
# Train TrafficLLM on new malware traffic data
# This creates a new PEFT prefix-tuning adapter for the new malware families

# Configuration
PRE_SEQ_LEN=128
LR=2e-2
NUM_GPUS=1
export CUDA_VISIBLE_DEVICES=0

# Paths (relative to TrafficLLM/dual-stage-tuning directory)
MODEL_PATH="../../trafficllm/models/chatglm2-6b"
OUTPUT_DIR="../../trafficllm/models/peft/new-malware-detection-packet"
TRAIN_FILE="../../finetuning/trafficllm_training/training_data/malware_detection_train.json"
CACHE_DIR="../../finetuning/trafficllm_training/cache"

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$CACHE_DIR"

echo "=== TrafficLLM New Malware Training ==="
echo "Model: $MODEL_PATH"
echo "Output: $OUTPUT_DIR"
echo "Training data: $TRAIN_FILE"
echo ""

cd ../../TrafficLLM/dual-stage-tuning

# Run training
torchrun --standalone --nnodes=1 --nproc-per-node=$NUM_GPUS main.py \
    --do_train \
    --train_file "$TRAIN_FILE" \
    --validation_file "$TRAIN_FILE" \
    --preprocessing_num_workers 10 \
    --prompt_column instruction \
    --response_column output \
    --overwrite_cache \
    --cache_dir "$CACHE_DIR" \
    --model_name_or_path "$MODEL_PATH" \
    --output_dir "$OUTPUT_DIR" \
    --overwrite_output_dir \
    --max_source_length 1024 \
    --max_target_length 32 \
    --per_device_train_batch_size 1 \
    --per_device_eval_batch_size 1 \
    --gradient_accumulation_steps 16 \
    --predict_with_generate \
    --max_steps 10000 \
    --logging_steps 50 \
    --save_steps 2000 \
    --learning_rate $LR \
    --pre_seq_len $PRE_SEQ_LEN

echo ""
echo "=== Training Complete ==="
echo "New PEFT adapter saved to: $OUTPUT_DIR"

