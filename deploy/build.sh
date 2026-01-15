#!/bin/bash
# AIPAM Docker Build Script
# Builds all Docker images for production deployment
#
# Usage: ./deploy/build.sh [--push REGISTRY]
#
# Prerequisites:
#   1. Training must be complete
#   2. Run merge_and_convert.py to create the GGUF model
#   3. Place aipam-trafficllm-v4.gguf in deploy/models/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REGISTRY=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            REGISTRY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$PROJECT_ROOT"

echo "============================================"
echo "AIPAM Docker Build"
echo "============================================"

# Check for model file
MODEL_FILE="deploy/models/aipam-trafficllm-v4.gguf"
if [ ! -f "$MODEL_FILE" ]; then
    echo "⚠️  WARNING: Model file not found at $MODEL_FILE"
    echo ""
    echo "To create the model file:"
    echo "  1. Wait for training to complete"
    echo "  2. Run: cd finetuning/trafficllm_training && python merge_lora_average.py  (or your merge step)"
    echo "  3. Copy the GGUF file: cp finetuning/trafficllm_training/aipam-trafficllm-v4.gguf deploy/models/"
    echo ""
    read -p "Continue building app image only? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    BUILD_OLLAMA=false
else
    BUILD_OLLAMA=true
    echo "✅ Model file found: $MODEL_FILE"
fi

# Build app image
echo ""
echo "Building AIPAM App image..."
docker build -t aipam-app:latest -f deploy/Dockerfile.app .
echo "✅ aipam-app:latest built successfully"

# Build Ollama image (if model exists)
if [ "$BUILD_OLLAMA" = true ]; then
    echo ""
    echo "Building AIPAM Ollama image..."
    docker build -t aipam-ollama:latest -f deploy/Dockerfile.ollama .
    echo "✅ aipam-ollama:latest built successfully"
fi

# Push to registry if specified
if [ -n "$REGISTRY" ]; then
    echo ""
    echo "Pushing images to $REGISTRY..."
    
    docker tag aipam-app:latest "$REGISTRY/aipam-app:latest"
    docker push "$REGISTRY/aipam-app:latest"
    echo "✅ Pushed aipam-app to $REGISTRY"
    
    if [ "$BUILD_OLLAMA" = true ]; then
        docker tag aipam-ollama:latest "$REGISTRY/aipam-ollama:latest"
        docker push "$REGISTRY/aipam-ollama:latest"
        echo "✅ Pushed aipam-ollama to $REGISTRY"
    fi
fi

echo ""
echo "============================================"
echo "Build Complete!"
echo "============================================"
echo ""
echo "To deploy:"
echo "  docker-compose -f deploy/docker-compose.yml up -d"
echo ""
echo "Access the application at: http://localhost"

