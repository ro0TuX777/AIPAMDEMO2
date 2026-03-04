#!/bin/bash
# ============================================================
# AIPAM VM Migration Script
# Packages everything needed to deploy AIPAM on a fresh
# Ubuntu 24.04 VM and generates a turnkey install script.
#
# Usage:
#   ./deploy/migrate_to_vm.sh [output-dir]
#
# What it creates:
#   aipam-migrate-YYYYMMDD/
#     ├── repo.tar.gz            (~150 MB - full git repo, no training data)
#     ├── aipam-cybersec-llm-v8.gguf  (~8 GB - the V8 model)
#     ├── Modelfile              (Ollama model definition)
#     ├── install.sh             (turnkey installer for Ubuntu 24.04)
#     └── README-INSTALL.txt     (quick reference)
#
# Transfer to VM:
#   rsync -avP --progress aipam-migrate-YYYYMMDD/ user@vm:/home/user/aipam-migrate/
#   # OR
#   scp -r aipam-migrate-YYYYMMDD/ user@vm:/home/user/aipam-migrate/
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y%m%d)
OUTPUT_DIR="${1:-$PROJECT_ROOT/aipam-migrate-$DATE}"
GGUF_PATH="$PROJECT_ROOT/finetuning/aipam_gpu_training/aipam-cybersec-llm-v8.gguf"
MODELFILE_PATH="$PROJECT_ROOT/finetuning/aipam_gpu_training/Modelfile"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM VM Migration Packager${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── Preflight checks ──
echo -e "${YELLOW}[1/5]${NC} Preflight checks..."

if [ ! -f "$GGUF_PATH" ]; then
    echo -e "${RED}ERROR: V8 GGUF not found at:${NC}"
    echo "  $GGUF_PATH"
    echo "Cannot proceed without the model file."
    exit 1
fi

if [ ! -f "$MODELFILE_PATH" ]; then
    echo -e "${RED}ERROR: Modelfile not found at:${NC}"
    echo "  $MODELFILE_PATH"
    exit 1
fi

if ! command -v git &>/dev/null; then
    echo -e "${RED}ERROR: git not found${NC}"
    exit 1
fi

echo -e "  ${GREEN}✓${NC} V8 GGUF found ($(du -h "$GGUF_PATH" | cut -f1))"
echo -e "  ${GREEN}✓${NC} Modelfile found"
echo -e "  ${GREEN}✓${NC} Git available"

# ── Create output directory ──
echo ""
echo -e "${YELLOW}[2/5]${NC} Creating package directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── Export git repo (excludes large training data) ──
echo ""
echo -e "${YELLOW}[3/5]${NC} Exporting git repository..."
echo "  This includes all source code but excludes untracked large files."
cd "$PROJECT_ROOT"
git archive --format=tar.gz --prefix=AIPAM/ HEAD > "$OUTPUT_DIR/repo.tar.gz"
REPO_SIZE=$(du -h "$OUTPUT_DIR/repo.tar.gz" | cut -f1)
echo -e "  ${GREEN}✓${NC} repo.tar.gz ($REPO_SIZE)"

# ── Copy model files ──
echo ""
echo -e "${YELLOW}[4/5]${NC} Copying V8 model (this may take a minute)..."
cp "$GGUF_PATH" "$OUTPUT_DIR/aipam-cybersec-llm-v8.gguf"
cp "$MODELFILE_PATH" "$OUTPUT_DIR/Modelfile"

# Fix Modelfile path to reference local GGUF
sed -i 's|^FROM .*|FROM ./aipam-cybersec-llm-v8.gguf|' "$OUTPUT_DIR/Modelfile"

MODEL_SIZE=$(du -h "$OUTPUT_DIR/aipam-cybersec-llm-v8.gguf" | cut -f1)
echo -e "  ${GREEN}✓${NC} aipam-cybersec-llm-v8.gguf ($MODEL_SIZE)"
echo -e "  ${GREEN}✓${NC} Modelfile (patched FROM path)"

# ── Generate install script ──
echo ""
echo -e "${YELLOW}[5/5]${NC} Generating install.sh..."

cat > "$OUTPUT_DIR/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# ============================================================
# AIPAM Turnkey Installer for Ubuntu 24.04
# Run this on the target VM after transferring the package.
#
# Usage:
#   cd /path/to/aipam-migrate-YYYYMMDD
#   chmod +x install.sh
#   ./install.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Installer — Ubuntu 24.04${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── 1. System dependencies ──
echo -e "${YELLOW}[1/6]${NC} Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release

# ── 2. Docker Engine ──
if command -v docker &>/dev/null; then
    echo -e "${YELLOW}[2/6]${NC} Docker already installed — $(docker --version)"
else
    echo -e "${YELLOW}[2/6]${NC} Installing Docker Engine..."
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker "$USER"
    echo -e "  ${GREEN}✓${NC} Docker installed"
fi

# ── 3. Ollama ──
if command -v ollama &>/dev/null; then
    echo -e "${YELLOW}[3/6]${NC} Ollama already installed — $(ollama --version)"
else
    echo -e "${YELLOW}[3/6]${NC} Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo -e "  ${GREEN}✓${NC} Ollama installed"
fi
INSTALL_EOF

chmod +x "$OUTPUT_DIR/install.sh"

# Continue the install script (second half)
cat >> "$OUTPUT_DIR/install.sh" << 'INSTALL_EOF2'

# Make sure Ollama service is running
if ! systemctl is-active --quiet ollama 2>/dev/null; then
    sudo systemctl start ollama 2>/dev/null || ollama serve &>/dev/null &
    sleep 3
fi

# ── 4. Extract repo ──
echo -e "${YELLOW}[4/6]${NC} Extracting AIPAM source code..."
INSTALL_DIR="$HOME/AIPAM"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "  ${YELLOW}⚠${NC}  $INSTALL_DIR already exists — backing up to ${INSTALL_DIR}.bak"
    mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
fi
tar -xzf repo.tar.gz -C "$HOME"
echo -e "  ${GREEN}✓${NC} Source code extracted to $INSTALL_DIR"

# ── 5. Import V8 model into Ollama ──
echo -e "${YELLOW}[5/6]${NC} Importing V8 model into Ollama (this takes a few minutes)..."
cd "$SCRIPT_DIR"
ollama create aipam-trafficllm-v8 -f Modelfile
echo -e "  ${GREEN}✓${NC} Model imported:"
ollama list | grep aipam

# ── 6. Build and start Docker stack ──
echo -e "${YELLOW}[6/6]${NC} Building and starting AIPAM Docker stack..."
cd "$INSTALL_DIR"
docker compose up -d --build 2>&1 | tail -5

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Frontend:  ${GREEN}http://$(hostname -I | awk '{print $1}'):5173${NC}"
echo -e "  API:       ${GREEN}http://$(hostname -I | awk '{print $1}'):8000/docs${NC}"
echo -e "  Ollama:    ${GREEN}http://localhost:11434${NC}"
echo ""
echo -e "  To stop:   cd $INSTALL_DIR && docker compose down"
echo -e "  To start:  cd $INSTALL_DIR && docker compose up -d"
echo ""
echo -e "  ${YELLOW}NOTE:${NC} If this is a fresh Docker install, log out and back in"
echo -e "  (or run 'newgrp docker') for group permissions to take effect."
INSTALL_EOF2

# ── Generate README ──
cat > "$OUTPUT_DIR/README-INSTALL.txt" << EOF
AIPAM VM Migration Package — $(date +%Y-%m-%d)
================================================

Contents:
  repo.tar.gz                   Git repo with all source code
  aipam-cybersec-llm-v8.gguf   Fine-tuned Llama 3.1 8B model (~8 GB)
  Modelfile                     Ollama model definition
  install.sh                    Turnkey installer for Ubuntu 24.04
  README-INSTALL.txt            This file

Quick Start:
  1. Transfer this entire directory to the target VM:
       rsync -avP aipam-migrate-$DATE/ user@vm-ip:~/aipam-migrate/

  2. SSH into the VM and run:
       cd ~/aipam-migrate
       chmod +x install.sh
       ./install.sh

  3. Open http://<vm-ip>:5173 in your browser.

VM Requirements:
  - Ubuntu 24.04 LTS (or 22.04)
  - 16 GB RAM (32 GB recommended)
  - 50 GB free disk
  - Internet access (for Docker/Ollama install only — not needed at runtime)

Ports Used:
  5173  — Web UI (frontend)
  8000  — API (backend)
  11434 — Ollama (localhost only)
EOF

# ── Summary ──
echo -e "  ${GREEN}✓${NC} install.sh generated"
echo ""
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Package Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Location: $OUTPUT_DIR"
echo "  Total size: $TOTAL_SIZE"
echo ""
echo "  Contents:"
ls -lh "$OUTPUT_DIR" | grep -v "^total" | awk '{print "    "$NF" ("$5")"}'
echo ""
echo -e "  ${YELLOW}Transfer to VM:${NC}"
echo "    rsync -avP --progress $OUTPUT_DIR/ user@<vm-ip>:~/aipam-migrate/"
echo ""
echo -e "  ${YELLOW}Then on the VM:${NC}"
echo "    cd ~/aipam-migrate && chmod +x install.sh && ./install.sh"

