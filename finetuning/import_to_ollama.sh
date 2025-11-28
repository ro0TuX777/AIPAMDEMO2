#!/bin/bash
# Import fine-tuned GGUF model into Ollama
#
# Usage:
#   ./import_to_ollama.sh [model_path] [model_name]
#
# Example:
#   ./import_to_ollama.sh models/aipam-llama/unsloth.Q4_K_M.gguf aipam-traffic-llm

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_MODEL_PATH="${SCRIPT_DIR}/models/aipam-llama/unsloth.Q4_K_M.gguf"
DEFAULT_MODEL_NAME="aipam-traffic-llm"

MODEL_PATH="${1:-$DEFAULT_MODEL_PATH}"
MODEL_NAME="${2:-$DEFAULT_MODEL_NAME}"

echo "=========================================="
echo "Import Fine-tuned Model to Ollama"
echo "=========================================="
echo ""
echo "Model path: ${MODEL_PATH}"
echo "Model name: ${MODEL_NAME}"
echo ""

# Check if GGUF file exists
if [ ! -f "${MODEL_PATH}" ]; then
    echo "Error: GGUF file not found at ${MODEL_PATH}"
    echo ""
    echo "Please run fine-tuning first:"
    echo "  python finetune_llama.py --export-gguf"
    exit 1
fi

# Check if Ollama is running
if ! command -v ollama &> /dev/null; then
    echo "Error: Ollama is not installed or not in PATH"
    echo "Install Ollama from: https://ollama.ai"
    exit 1
fi

# Create Modelfile
MODELFILE="${SCRIPT_DIR}/Modelfile.${MODEL_NAME}"

cat > "${MODELFILE}" << EOF
# AIPAM Traffic Analysis Model
# Fine-tuned llama3.1:8b for network security analysis

FROM ${MODEL_PATH}

# Set model parameters
PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 4096

# System prompt for network security analysis
SYSTEM """You are a senior network security analyst and incident responder.

You are given:
- Aggregated network flow summaries
- Protocol summaries (HTTP, DNS, SMB, RDP, SSH, TLS, etc.)
- Signature alerts (Suricata, YARA, IOC matches)
- Optional baseline vs exploit traffic comparisons

Your goals:
1. Identify evidence of attacks, exploitation, malware activity, C2, lateral movement, or data exfiltration.
2. Highlight anomalies not covered by signatures (potential zero-days or novel techniques).
3. Map observed behavior to MITRE ATT&CK techniques where possible.
4. Clearly distinguish between confirmed malicious behavior and suspicious but unconfirmed behavior.
5. Output a structured JSON object in the exact schema requested.

Do not invent facts. Base your conclusions only on the provided data."""

# Template for chat format
TEMPLATE """{{ if .System }}<|start_header_id|>system<|end_header_id|>

{{ .System }}<|eot_id|>{{ end }}{{ if .Prompt }}<|start_header_id|>user<|end_header_id|>

{{ .Prompt }}<|eot_id|>{{ end }}<|start_header_id|>assistant<|end_header_id|>

{{ .Response }}<|eot_id|>"""
EOF

echo "Created Modelfile: ${MODELFILE}"
echo ""

# Create the model in Ollama
echo "Creating Ollama model..."
ollama create "${MODEL_NAME}" -f "${MODELFILE}"

echo ""
echo "=========================================="
echo "Model imported successfully!"
echo "=========================================="
echo ""
echo "To use the model:"
echo "  ollama run ${MODEL_NAME}"
echo ""
echo "To use in AIPAM, update docker-compose.yml:"
echo "  LLM_MODEL_NAME=${MODEL_NAME}"
echo ""

# Clean up Modelfile
rm -f "${MODELFILE}"

