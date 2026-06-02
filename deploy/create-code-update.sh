#!/bin/bash
# ============================================================
# AIPAM Code-Only Update Package Builder
#
# Creates a lightweight update package with just Docker images
# and source code — no model (v10 is already deployed).
#
# Usage:  ./deploy/create-code-update.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y%m%d)
OUTPUT_DIR="$PROJECT_ROOT/dist/aipam-code-update-$DATE"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cd "$PROJECT_ROOT"

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Code-Only Update Package Builder${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── Preflight checks ──
echo -e "${YELLOW}[1/5]${NC} Checking prerequisites..."

for img in aipam-app aipam-frontend; do
    if ! docker images --format '{{.Repository}}' | grep -q "^${img}$"; then
        echo -e "  ${RED}x Docker image '$img' not found. Run 'docker compose build' first.${NC}"
        exit 1
    fi
done
echo -e "  ${GREEN}ok${NC} Docker images found (aipam-app, aipam-frontend)"

for f in _update_template.sh docker-compose.override.host-ollama.yml env.template; do
    if [ ! -f "$SCRIPT_DIR/$f" ]; then
        echo -e "  ${RED}x Required builder asset '$f' missing in $SCRIPT_DIR${NC}"
        exit 1
    fi
done
echo -e "  ${GREEN}ok${NC} Builder assets present (template, override, env.template)"

# ── Create output directory ──
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── 2. Export Docker images ──
echo -e "${YELLOW}[2/5]${NC} Exporting Docker images (this takes a few minutes)..."
docker save aipam-app:latest aipam-frontend:latest \
    | gzip > "$OUTPUT_DIR/docker-images.tar.gz"
echo -e "  ${GREEN}ok${NC} Images saved ($(du -h "$OUTPUT_DIR/docker-images.tar.gz" | cut -f1))"

# ── 3. Bundle updated source code ──
echo -e "${YELLOW}[3/5]${NC} Bundling updated source code..."
tar -czf "$OUTPUT_DIR/repo.tar.gz" \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='venv*' \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='dist' \
    --exclude='finetuning/data' \
    --exclude='.cache' \
    --exclude='aipam-migrate-*' \
    --exclude='llama.cpp' \
    --exclude='trafficllm' \
    --exclude='trafficllm_training' \
    --exclude='trafficllm_datasets' \
    --exclude='aipam_gpu_training' \
    --exclude='aipam_gpu_training.zip' \
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
echo -e "  ${GREEN}ok${NC} Source code archived ($(du -h "$OUTPUT_DIR/repo.tar.gz" | cut -f1))"

# ── 4. Bundle host-Ollama override + env.template ──
echo -e "${YELLOW}[4/5]${NC} Bundling override + env.template..."
cp "$SCRIPT_DIR/docker-compose.override.host-ollama.yml" \
   "$OUTPUT_DIR/docker-compose.override.yml"
cp "$SCRIPT_DIR/env.template" "$OUTPUT_DIR/env.template"
echo -e "  ${GREEN}ok${NC} docker-compose.override.yml + env.template bundled"

# ── 5. Copy update.sh from the maintained template ──
echo -e "${YELLOW}[5/5]${NC} Copying update.sh template..."
cp "$SCRIPT_DIR/_update_template.sh" "$OUTPUT_DIR/update.sh"
chmod +x "$OUTPUT_DIR/update.sh"
# Verify the copied script is syntactically valid
if ! bash -n "$OUTPUT_DIR/update.sh"; then
    echo -e "  ${RED}x update.sh has a syntax error after copy${NC}"
    exit 1
fi
echo -e "  ${GREEN}ok${NC} update.sh installed (supports --check-only / --skip-validate)"

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
echo "    rsync -avP --progress $OUTPUT_DIR/ user@<server-ip>:~/aipam-code-update/"
echo ""
echo -e "  ${YELLOW}Then on the server (recommended sequence):${NC}"
echo "    cd ~/aipam-code-update && chmod +x update.sh"
echo "    ./update.sh --check-only     # diagnostics only, no changes"
echo "    ./update.sh                  # apply the update (validates then installs)"
echo ""
echo -e "  ${YELLOW}Emergency / force install (skips validation):${NC}"
echo "    ./update.sh --skip-validate"

# ── Refresh hot-patch baseline so future hot-patches are valid against this build ──
if [ -x "$SCRIPT_DIR/create-hotpatch.sh" ]; then
    echo ""
    echo -e "${YELLOW}Refreshing hot-patch baseline (so future hot-patches can verify safety)...${NC}"
    "$SCRIPT_DIR/create-hotpatch.sh" --update-baseline >/dev/null
    echo -e "  ${GREEN}ok${NC} baseline updated at $SCRIPT_DIR/.hotpatch-baseline"
fi

