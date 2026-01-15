#!/bin/bash
cd /home/bc/Documents/AIPAM/finetuning/trafficllm_training
source ../aipam_gpu_training/venv_unsloth/bin/activate
echo "Starting batch4 training..."
python3 train_batches.py --batch batch4_rats_c2 2>&1
echo "Training complete!"

