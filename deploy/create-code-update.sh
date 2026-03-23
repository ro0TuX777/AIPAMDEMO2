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
echo -e "${YELLOW}[1/4]${NC} Checking prerequisites..."

for img in aipam-backend aipam-frontend aipam-worker; do
    if ! docker images --format '{{.Repository}}' | grep -q "^${img}$"; then
        echo -e "  ${RED}x Docker image '$img' not found. Run 'docker compose build' first.${NC}"
        exit 1
    fi
done
echo -e "  ${GREEN}ok${NC} Docker images found (aipam-backend, aipam-frontend, aipam-worker)"

# ── Create output directory ──
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── 2. Export Docker images ──
echo -e "${YELLOW}[2/4]${NC} Exporting Docker images (this takes a few minutes)..."
docker save aipam-backend:latest aipam-frontend:latest aipam-worker:latest \
    | gzip > "$OUTPUT_DIR/docker-images.tar.gz"
echo -e "  ${GREEN}ok${NC} Images saved ($(du -h "$OUTPUT_DIR/docker-images.tar.gz" | cut -f1))"

# ── 3. Bundle updated source code ──
echo -e "${YELLOW}[3/4]${NC} Bundling updated source code..."
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

# ── 4. Generate update.sh for the offline server ──
echo -e "${YELLOW}[4/4]${NC} Generating update script..."
cat > "$OUTPUT_DIR/update.sh" << 'UPDATE_EOF'
#!/bin/bash
# ============================================================
# AIPAM Code-Only Update Script  (Air-Gapped)
#
# Updates source code and Docker images only.
# The v10 model is preserved — no model changes.
#
#   cd /path/to/aipam-code-update-YYYYMMDD
#   chmod +x update.sh
#   ./update.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="$HOME/AIPAM"
BACKUP=""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Code-Only Update  (Offline)${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── 1. Stop current stack ──
echo -e "${YELLOW}[1/4]${NC} Stopping current AIPAM stack..."
if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR"
    docker compose down 2>/dev/null || true
    cd "$SCRIPT_DIR"
    echo -e "  ${GREEN}ok${NC} Stack stopped"
else
    echo -e "  ${YELLOW}!!${NC}  $INSTALL_DIR not found -- will create it"
fi

# ── 2. Update source code ──
echo -e "${YELLOW}[2/4]${NC} Updating source code..."
if [ -d "$INSTALL_DIR" ]; then
    BACKUP="${INSTALL_DIR}.backup.$(date +%s)"
    mv "$INSTALL_DIR" "$BACKUP"
    echo -e "  ${GREEN}ok${NC} Backed up old installation to $BACKUP"
fi
tar -xzf "$SCRIPT_DIR/repo.tar.gz" -C "$HOME"
echo -e "  ${GREEN}ok${NC} Source code updated at $INSTALL_DIR"

# ── 3. Load new Docker images ──
echo -e "${YELLOW}[3/4]${NC} Loading updated Docker images..."
docker load < "$SCRIPT_DIR/docker-images.tar.gz"
echo -e "  ${GREEN}ok${NC} Docker images loaded"

# ── 4. Start updated stack ──
echo -e "${YELLOW}[4/4]${NC} Starting AIPAM stack..."
cd "$INSTALL_DIR"
docker compose up -d 2>&1 | tail -5

sleep 5
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Code Update Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Frontend:  ${GREEN}http://$(hostname -I | awk '{print $1}'):80${NC}"
echo -e "  API:       ${GREEN}http://$(hostname -I | awk '{print $1}'):8000/docs${NC}"
echo -e "  Model:     aipam-trafficllm-v10 (unchanged)"
echo ""
if [ -n "$BACKUP" ]; then
echo -e "  Old backup: $BACKUP"
fi
echo ""
UPDATE_EOF
chmod +x "$OUTPUT_DIR/update.sh"
echo -e "  ${GREEN}ok${NC} update.sh generated"

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
echo -e "  ${YELLOW}Then on the server:${NC}"
echo "    cd ~/aipam-code-update && chmod +x update.sh && ./update.sh"

