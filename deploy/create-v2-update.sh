#!/bin/bash
# ============================================================
# AIPAM v2 Delta Update Package Builder
#
# Creates a lightweight update package to upgrade an offline
# server from AIPAM v1 (v8 model) → AIPAM v2 (v9 model).
#
# Usage:  ./deploy/create-v2-update.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y%m%d)
OUTPUT_DIR="$PROJECT_ROOT/dist/aipam-v2-update-$DATE"
GGUF_PATH="$PROJECT_ROOT/finetuning/data/models/run_20260317_012714/gguf_export/aipam-trafficllm-v9.Q4_K_M.gguf"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cd "$PROJECT_ROOT"

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM v2 Update Package Builder${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── Preflight checks ──
echo -e "${YELLOW}[1/5]${NC} Checking prerequisites..."

if [ ! -f "$GGUF_PATH" ]; then
    echo -e "  ${RED}✗ V9 GGUF model not found at:${NC}"
    echo "    $GGUF_PATH"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} V9 GGUF model found ($(du -h "$GGUF_PATH" | cut -f1))"

for img in aipam-backend aipam-frontend aipam-worker; do
    if ! docker images --format '{{.Repository}}' | grep -q "^${img}$"; then
        echo -e "  ${RED}✗ Docker image '$img' not found. Run 'docker compose build' first.${NC}"
        exit 1
    fi
done
echo -e "  ${GREEN}✓${NC} Docker images found (aipam-backend, aipam-frontend, aipam-worker)"

# ── Create output directory ──
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── 2. Export Docker images ──
echo -e "${YELLOW}[2/5]${NC} Exporting Docker images (this takes a few minutes)..."
docker save aipam-backend:latest aipam-frontend:latest aipam-worker:latest \
    | gzip > "$OUTPUT_DIR/docker-images.tar.gz"
echo -e "  ${GREEN}✓${NC} Images saved ($(du -h "$OUTPUT_DIR/docker-images.tar.gz" | cut -f1))"

# ── 3. Copy V9 GGUF model ──
echo -e "${YELLOW}[3/5]${NC} Copying V9 GGUF model..."
cp "$GGUF_PATH" "$OUTPUT_DIR/aipam-trafficllm-v9.Q4_K_M.gguf"
echo -e "  ${GREEN}✓${NC} Model copied ($(du -h "$OUTPUT_DIR/aipam-trafficllm-v9.Q4_K_M.gguf" | cut -f1))"

# ── 4. Create Modelfile for v9 ──
echo -e "${YELLOW}[4/5]${NC} Generating Modelfile and update script..."
cat > "$OUTPUT_DIR/Modelfile.v9" << 'MODELFILE_EOF'
FROM ./aipam-trafficllm-v9.Q4_K_M.gguf

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 4096
PARAMETER repeat_penalty 1.1

SYSTEM """You are an expert cybersecurity analyst specializing in network traffic analysis.
You analyze packet data to detect malware, identify attack patterns, and provide security insights.
When given traffic data, classify it and explain your reasoning with MITRE ATT&CK mappings.

Your capabilities include:
- Malware traffic detection and classification
- Network protocol analysis
- Threat intelligence correlation
- MITRE ATT&CK technique identification
- Indicators of Compromise (IOC) extraction
- Security recommendations

Always provide clear, actionable analysis with confidence levels and supporting evidence."""

LICENSE """
AIPAM Traffic Analysis Model v9
Copyright (c) 2024 Blue Cloak

This model is fine-tuned for cybersecurity traffic analysis.
Base model: Meta Llama 3.1 8B (subject to Meta's license terms)
"""
MODELFILE_EOF
echo -e "  ${GREEN}✓${NC} Modelfile.v9 created"

# ── 5. Bundle updated source code ──
echo -e "${YELLOW}[5/5]${NC} Bundling updated source code..."
tar -czf "$OUTPUT_DIR/repo.tar.gz" \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='venv*' \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='dist' \
    --exclude='finetuning/data/models' \
    --exclude='finetuning/data/distilled' \
    --exclude='.cache' \
    --exclude='aipam-migrate-*' \
    --exclude='llama.cpp' \
    --exclude='trafficllm' \
    --exclude='TrafficLLM*' \
    --exclude='benchmark' \
    --exclude='unsloth_compiled_cache' \
    --exclude='deploy/models' \
    --exclude='*.gguf' \
    --exclude='*.safetensors' \
    --exclude='*.zip' \
    --exclude='*.tar.gz' \
    --exclude='*.tar' \
    -C "$(dirname "$PROJECT_ROOT")" "$(basename "$PROJECT_ROOT")"
echo -e "  ${GREEN}✓${NC} Source code archived ($(du -h "$OUTPUT_DIR/repo.tar.gz" | cut -f1))"

# ── Generate update.sh for the offline server ──
cat > "$OUTPUT_DIR/update.sh" << 'UPDATE_EOF'
#!/bin/bash
# ============================================================
# AIPAM v1 → v2 Update Script  (Air-Gapped)
#
# Run on the offline server after transferring this package.
#   cd /path/to/aipam-v2-update-YYYYMMDD
#   chmod +x update.sh
#   ./update.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="$HOME/AIPAM"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM v1 → v2 Update  (Offline)${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── 1. Stop current stack ──
echo -e "${YELLOW}[1/5]${NC} Stopping current AIPAM stack..."
if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR"
    docker compose down 2>/dev/null || true
    cd "$SCRIPT_DIR"
    echo -e "  ${GREEN}✓${NC} Stack stopped"
else
    echo -e "  ${YELLOW}⚠${NC}  $INSTALL_DIR not found — will create it"
fi

# ── 2. Update source code ──
echo -e "${YELLOW}[2/5]${NC} Updating source code..."
if [ -d "$INSTALL_DIR" ]; then
    mv "$INSTALL_DIR" "${INSTALL_DIR}.v1-backup.$(date +%s)"
    echo -e "  ${GREEN}✓${NC} Backed up old installation"
fi
tar -xzf "$SCRIPT_DIR/repo.tar.gz" -C "$HOME"
echo -e "  ${GREEN}✓${NC} Source code updated at $INSTALL_DIR"

# ── 3. Load new Docker images ──
echo -e "${YELLOW}[3/5]${NC} Loading updated Docker images..."
docker load < "$SCRIPT_DIR/docker-images.tar.gz"
echo -e "  ${GREEN}✓${NC} Docker images loaded"

# ── 4. Import V9 model into Ollama ──
echo -e "${YELLOW}[4/5]${NC} Importing V9 model into Ollama..."
cd "$SCRIPT_DIR"
ollama create aipam-trafficllm-v9 -f Modelfile.v9
echo -e "  ${GREEN}✓${NC} Model imported:"
ollama list | grep aipam

# ── 5. Start updated stack ──
echo -e "${YELLOW}[5/5]${NC} Starting AIPAM v2 stack..."
cd "$INSTALL_DIR"
docker compose up -d 2>&1 | tail -5

sleep 5
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM v2 Update Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Frontend:  ${GREEN}http://$(hostname -I | awk '{print $1}'):5173${NC}"
echo -e "  API:       ${GREEN}http://$(hostname -I | awk '{print $1}'):8000/docs${NC}"
echo -e "  Model:     aipam-trafficllm-v9 (Q4_K_M)"
echo ""
echo -e "  Old v1 backup: ${INSTALL_DIR}.v1-backup.*"
echo ""
UPDATE_EOF
chmod +x "$OUTPUT_DIR/update.sh"
echo -e "  ${GREEN}✓${NC} update.sh generated"

# ── Summary ──
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Update Package Ready!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Location: $OUTPUT_DIR"
echo "  Total size: $TOTAL_SIZE"
echo ""
echo "  Contents:"
ls -lh "$OUTPUT_DIR" | grep -v "^total" | awk '{print "    "$NF" ("$5")"}'
echo ""
echo -e "  ${YELLOW}Transfer to offline server:${NC}"
echo "    rsync -avP --progress $OUTPUT_DIR/ user@<server-ip>:~/aipam-v2-update/"
echo ""
echo -e "  ${YELLOW}Then on the server:${NC}"
echo "    cd ~/aipam-v2-update && chmod +x update.sh && ./update.sh"

