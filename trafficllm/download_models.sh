#!/bin/bash
# Download TrafficLLM models and PEFT adapters
#
# This script downloads:
# 1. ChatGLM2-6B base model from Hugging Face
# 2. TrafficLLM PEFT adapters from Google Drive
#
# Requirements:
# - gdown (pip install gdown)
# - huggingface-cli (pip install huggingface_hub)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS_DIR="${SCRIPT_DIR}/models"

mkdir -p "${MODELS_DIR}"

echo "=========================================="
echo "TrafficLLM Model Download Script"
echo "=========================================="

# Step 1: Download ChatGLM2-6B base model
echo ""
echo "[1/2] Downloading ChatGLM2-6B base model..."
echo "This may take a while (~12GB)..."

if [ -d "${MODELS_DIR}/chatglm2-6b" ]; then
    echo "ChatGLM2-6B already exists, skipping..."
else
    # Option A: Using huggingface-cli
    if command -v huggingface-cli &> /dev/null; then
        huggingface-cli download THUDM/chatglm2-6b --local-dir "${MODELS_DIR}/chatglm2-6b"
    # Option B: Using git lfs
    elif command -v git-lfs &> /dev/null; then
        git lfs install
        git clone https://huggingface.co/THUDM/chatglm2-6b "${MODELS_DIR}/chatglm2-6b"
    else
        echo "ERROR: Please install huggingface-cli or git-lfs"
        echo "  pip install huggingface_hub"
        echo "  or"
        echo "  brew install git-lfs && git lfs install"
        exit 1
    fi
fi

# Step 2: Download PEFT adapters from Google Drive
echo ""
echo "[2/2] Downloading TrafficLLM PEFT adapters..."

PEFT_DIR="${MODELS_DIR}/peft"
mkdir -p "${PEFT_DIR}"

# TrafficLLM provides PEFT adapters via Google Drive
# These are the direct download links from the TrafficLLM repository
# https://github.com/ZGC-LLM-Safety/TrafficLLM

# Check if gdown is installed
if ! command -v gdown &> /dev/null; then
    echo "Installing gdown for Google Drive downloads..."
    pip install gdown
fi

# TrafficLLM PEFT adapters Google Drive folder ID
# Note: You may need to update this if the TrafficLLM authors change the link
GDRIVE_FOLDER_ID="1Ly0lS6kXprU1AwNxdBgCyxhkXx8_oN3e"

if [ -d "${PEFT_DIR}/instruction" ]; then
    echo "PEFT adapters already exist, skipping..."
else
    echo "Downloading PEFT adapters from Google Drive..."
    echo "Note: If this fails, manually download from:"
    echo "  https://drive.google.com/drive/folders/${GDRIVE_FOLDER_ID}"
    
    # Download using gdown (Google Drive downloader)
    gdown --folder "https://drive.google.com/drive/folders/${GDRIVE_FOLDER_ID}" -O "${PEFT_DIR}" --remaining-ok || {
        echo ""
        echo "Automatic download failed. Please manually download PEFT adapters:"
        echo ""
        echo "1. Visit: https://drive.google.com/drive/folders/${GDRIVE_FOLDER_ID}"
        echo "2. Download all folders"
        echo "3. Extract to: ${PEFT_DIR}"
        echo ""
        echo "Expected structure:"
        echo "  ${PEFT_DIR}/"
        echo "    ├── instruction/"
        echo "    ├── ustc-tfc-2016-detection-packet/"
        echo "    ├── iscx-botnet-2014-detection-packet/"
        echo "    ├── csic-2010-detection-packet/"
        echo "    ├── dapt-2020-detection-packet/"
        echo "    ├── iscx-vpn-2016-detection-packet/"
        echo "    └── iscx-tor-2016-detection-packet/"
    }
fi

echo ""
echo "=========================================="
echo "Download complete!"
echo "=========================================="
echo ""
echo "Models location: ${MODELS_DIR}"
echo ""
echo "To start TrafficLLM service:"
echo "  docker-compose up trafficllm"
echo ""

