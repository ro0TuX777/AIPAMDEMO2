#!/bin/bash
# ============================================================
# AIPAM V10 Full Migration Package Builder (Air-Gapped)
#
# Creates EVERYTHING needed to deploy AIPAM on a brand-new
# Ubuntu 24.04 server with NO internet access.
#
# Includes:
#   - All Docker images (AIPAM + Ollama + Redis + Arkime stack)
#   - V10 fine-tuned LLM model (Q4_K_M quantized)
#   - Ollama binary + CUDA libraries
#   - Docker Engine .deb packages
#   - NVIDIA Container Toolkit .deb packages
#   - Full source code
#   - .env template
#   - Turnkey install.sh
#
# Usage:  ./deploy/create-v10-migration.sh [output-dir]
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y%m%d)
OUTPUT_DIR="${1:-$PROJECT_ROOT/dist/aipam-v10-fullinstall-$DATE}"
GGUF_PATH="$PROJECT_ROOT/finetuning/data/models/run_20260318_011409/gguf_export/0e9e39f249a16976918f6564b8830bc894c89659.Q4_K_M.gguf"

# Versions to bundle
OLLAMA_VERSION="0.6.8"
TARGET_DISTRO="noble"       # Ubuntu 24.04
TARGET_ARCH="amd64"
DOCKER_DEB_BASE="https://download.docker.com/linux/ubuntu/dists/${TARGET_DISTRO}/pool/stable/${TARGET_ARCH}"
NVIDIA_CTK_BASE="https://nvidia.github.io/libnvidia-container/stable/deb/${TARGET_ARCH}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cd "$PROJECT_ROOT"

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  AIPAM V10 Full Migration Package Builder (Air-Gapped)${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""

# ── Step 1: Preflight checks ──
echo -e "${YELLOW}[1/9]${NC} Preflight checks..."

if [ ! -f "$GGUF_PATH" ]; then
    echo -e "  ${RED}✗ V10 GGUF model not found at:${NC}"
    echo "    $GGUF_PATH"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} V10 GGUF model found ($(du -h "$GGUF_PATH" | cut -f1))"

if ! command -v git &>/dev/null; then
    echo -e "  ${RED}✗ git not found${NC}"; exit 1
fi
echo -e "  ${GREEN}✓${NC} Git available"

if ! command -v docker &>/dev/null; then
    echo -e "  ${RED}✗ docker not found${NC}"; exit 1
fi
echo -e "  ${GREEN}✓${NC} Docker available"

# Verify all required images exist
REQUIRED_IMAGES=(
    "aipam-app:latest"
    "aipam-frontend:latest"
    "ollama/ollama:latest"
    "redis:7-alpine"
    "opensearchproject/opensearch:2.18.0"
    "ghcr.io/arkime/arkime/arkime:v6-latest"
)
MISSING=0
for img in "${REQUIRED_IMAGES[@]}"; do
    if docker image inspect "$img" &>/dev/null; then
        SIZE=$(docker images --format '{{.Size}}' "$img" | head -1)
        echo -e "  ${GREEN}✓${NC} $img ($SIZE)"
    else
        echo -e "  ${RED}✗ $img NOT FOUND${NC}"
        MISSING=1
    fi
done
if [ "$MISSING" -eq 1 ]; then
    echo -e "\n  ${RED}Missing images. Run:${NC}"
    echo "    docker compose --profile arkime build"
    echo "    docker compose --profile arkime pull"
    exit 1
fi

# ── Step 2: Create output directory ──
echo ""
echo -e "${YELLOW}[2/9]${NC} Creating package directory: $OUTPUT_DIR"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── Step 3: Export source code ──
echo ""
echo -e "${YELLOW}[3/9]${NC} Exporting source code..."
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
    --exclude='trafficllm/venv' \
    --exclude='trafficllm_training' \
    --exclude='trafficllm_datasets' \
    --exclude='aipam_gpu_training' \
    --exclude='aipam_gpu_training.zip' \
    --exclude='TrafficLLM*' \
    --exclude='benchmark' \
    --exclude='unsloth_compiled_cache' \
    --exclude='venv_unsloth' \
    --exclude='deploy/models' \
    --exclude='*.gguf' \
    --exclude='*.safetensors' \
    --exclude='*.zip' \
    --exclude='*.tar.gz' \
    --exclude='*.tar' \
    --exclude='zero_day_training_data' \
    --exclude='frontend/node_modules' \
    --exclude='frontend/dist' \
    --transform='s|^|AIPAM/|' \
    -C "$PROJECT_ROOT" .
echo -e "  ${GREEN}✓${NC} repo.tar.gz ($(du -h "$OUTPUT_DIR/repo.tar.gz" | cut -f1))"

# ── Step 4: Copy V10 GGUF model ──
echo ""
echo -e "${YELLOW}[4/9]${NC} Copying V10 GGUF model (4.6 GB — this takes a minute)..."
cp "$GGUF_PATH" "$OUTPUT_DIR/aipam-trafficllm-v10.Q4_K_M.gguf"
echo -e "  ${GREEN}✓${NC} Model copied ($(du -h "$OUTPUT_DIR/aipam-trafficllm-v10.Q4_K_M.gguf" | cut -f1))"

# ── Step 5: Create Modelfile ──
echo ""
echo -e "${YELLOW}[5/9]${NC} Generating Modelfile.v10..."
cat > "$OUTPUT_DIR/Modelfile.v10" << 'MODELFILE_EOF'
FROM ./aipam-trafficllm-v10.Q4_K_M.gguf

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
AIPAM Traffic Analysis Model v10
Copyright (c) 2024-2026 Blue Cloak

Fine-tuned for cybersecurity traffic analysis.
Trained on 5,477 frontier-distilled samples (GPT-5.4 teacher).
Base model: Meta Llama 3.1 8B (subject to Meta's license terms)
"""
MODELFILE_EOF
echo -e "  ${GREEN}✓${NC} Modelfile.v10 created"

# ── Step 6: Download Ollama tarball ──
echo ""
echo -e "${YELLOW}[6/9]${NC} Downloading Ollama v${OLLAMA_VERSION} tarball..."
OLLAMA_TGZ="ollama-linux-${TARGET_ARCH}.tgz"
OLLAMA_URL="https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/${OLLAMA_TGZ}"
if [ -f "$OUTPUT_DIR/$OLLAMA_TGZ" ]; then
    echo -e "  ${GREEN}✓${NC} Already downloaded (skipping)"
else
    curl -fSL --progress-bar -o "$OUTPUT_DIR/$OLLAMA_TGZ" "$OLLAMA_URL"
fi
echo -e "  ${GREEN}✓${NC} $OLLAMA_TGZ ($(du -h "$OUTPUT_DIR/$OLLAMA_TGZ" | cut -f1)) — includes CUDA libraries"

# ── Step 7: Download Docker Engine .deb packages ──
echo ""
echo -e "${YELLOW}[7/9]${NC} Downloading Docker Engine .deb packages for Ubuntu ${TARGET_DISTRO}/${TARGET_ARCH}..."
mkdir -p "$OUTPUT_DIR/docker-debs"
DOCKER_PKGS=(containerd.io docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin)
for pkg in "${DOCKER_PKGS[@]}"; do
    LATEST_DEB=$(curl -fsSL "${DOCKER_DEB_BASE}/" | grep -oP "${pkg}_[^\">]+_${TARGET_ARCH}\.deb" | sort -V | tail -1)
    if [ -z "$LATEST_DEB" ]; then
        echo -e "  ${RED}✗ Could not find $pkg in Docker repo${NC}"
        continue
    fi
    if [ -f "$OUTPUT_DIR/docker-debs/$LATEST_DEB" ]; then
        echo -e "  ${GREEN}✓${NC} $LATEST_DEB (cached)"
    else
        echo -e "  Downloading $LATEST_DEB..."
        curl -fSL --progress-bar -o "$OUTPUT_DIR/docker-debs/$LATEST_DEB" "${DOCKER_DEB_BASE}/$LATEST_DEB"
        echo -e "  ${GREEN}✓${NC} $LATEST_DEB"
    fi
done
echo -e "  ${GREEN}✓${NC} Docker .deb packages total: $(du -sh "$OUTPUT_DIR/docker-debs" | cut -f1)"

# ── Step 7b: Download NVIDIA Container Toolkit .deb packages ──
echo ""
echo -e "${YELLOW}[7b/9]${NC} Downloading NVIDIA Container Toolkit packages (for GPU support)..."
mkdir -p "$OUTPUT_DIR/nvidia-ctk-debs"
# Download the key packages needed for nvidia-container-toolkit
NVIDIA_PKGS=(libnvidia-container1 libnvidia-container-tools nvidia-container-toolkit nvidia-container-toolkit-base)
NVIDIA_DL_OK=true
for pkg in "${NVIDIA_PKGS[@]}"; do
    LATEST_DEB=$(curl -fsSL "${NVIDIA_CTK_BASE}/" 2>/dev/null | grep -oP "${pkg}_[^\">]+_${TARGET_ARCH}\.deb" | sort -V | tail -1 || true)
    if [ -z "$LATEST_DEB" ]; then
        echo -e "  ${YELLOW}⚠${NC}  Could not find $pkg — GPU support will need manual install"
        NVIDIA_DL_OK=false
        continue
    fi
    if [ -f "$OUTPUT_DIR/nvidia-ctk-debs/$LATEST_DEB" ]; then
        echo -e "  ${GREEN}✓${NC} $LATEST_DEB (cached)"
    else
        curl -fSL --progress-bar -o "$OUTPUT_DIR/nvidia-ctk-debs/$LATEST_DEB" "${NVIDIA_CTK_BASE}/$LATEST_DEB" 2>/dev/null || {
            echo -e "  ${YELLOW}⚠${NC}  Failed to download $pkg"
            NVIDIA_DL_OK=false
            continue
        }
        echo -e "  ${GREEN}✓${NC} $LATEST_DEB"
    fi
done
if [ "$NVIDIA_DL_OK" = true ]; then
    echo -e "  ${GREEN}✓${NC} NVIDIA CTK packages total: $(du -sh "$OUTPUT_DIR/nvidia-ctk-debs" | cut -f1)"
else
    echo -e "  ${YELLOW}⚠${NC}  Some NVIDIA packages missing — GPU support may need manual setup"
fi


# ── Step 8: Export ALL Docker images ──
echo ""
echo -e "${YELLOW}[8/9]${NC} Exporting Docker images (this takes several minutes)..."
echo "  Saving 6 images: aipam-app, aipam-frontend, ollama, redis, opensearch, arkime"
docker save \
    aipam-app:latest \
    aipam-frontend:latest \
    ollama/ollama:latest \
    redis:7-alpine \
    opensearchproject/opensearch:2.18.0 \
    ghcr.io/arkime/arkime/arkime:v6-latest \
    | gzip > "$OUTPUT_DIR/docker-images.tar.gz"
echo -e "  ${GREEN}✓${NC} docker-images.tar.gz ($(du -h "$OUTPUT_DIR/docker-images.tar.gz" | cut -f1))"

# ── Step 9: Generate .env template ──
echo ""
echo -e "${YELLOW}[9/9]${NC} Generating .env template and install script..."

cat > "$OUTPUT_DIR/env.template" << 'ENVEOF'
# AIPAM V2 — Environment Configuration
# Generated by create-v10-migration.sh
#
# Copy to your AIPAM installation:
#   cp env.template ~/AIPAM/.env

# ============================================
# REQUIRED
# ============================================
AIPAM_API_TOKEN=changeme-generate-a-secure-token

# ============================================
# LLM Model (v10 — do not change unless you
# have imported a different model into Ollama)
# ============================================
LLM_MODEL_NAME=aipam-trafficllm-v10
LLM_ENDPOINT=http://ollama:11434/v1/chat/completions

# ============================================
# OPTIONAL — uncomment to override defaults
# ============================================
# AIPAM_MAX_CONCURRENT_JOBS=1
# AIPAM_SENSOR_PARALLELISM=1
# AIPAM_JOB_RETENTION_DAYS=30

# ============================================
# SECURITY ONION (optional — external SO)
# ============================================
# SECURITY_ONION_ENABLED=false
# SECURITY_ONION_API_URL=https://172.16.0.15
# SECURITY_ONION_USERNAME=analyst@example.com
# SECURITY_ONION_PASSWORD=

# ============================================
# ARKIME (optional — enable with: docker compose --profile arkime up)
# ============================================
# ARKIME_ENABLED=false
# ARKIME_API_URL=http://arkime-viewer:8005
# ARKIME_PUBLIC_URL=http://localhost:8005
# ARKIME_API_USERNAME=admin
# ARKIME_API_PASSWORD=changeme
# ARKIME_OPENSEARCH_URL=http://opensearch:9200
# ARKIME_IMPORT_ENABLED=true
ENVEOF
echo -e "  ${GREEN}✓${NC} env.template created"

# ── Generate install.sh (turnkey offline installer) ──
cat > "$OUTPUT_DIR/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# ============================================================
# AIPAM V10 Turnkey Installer — Ubuntu 24.04 (Air-Gapped)
#
# Installs Docker, Ollama, NVIDIA Container Toolkit, loads
# all Docker images, imports the V10 model, and starts the
# full AIPAM stack. NO internet connection required.
#
# Usage:
#   cd /path/to/aipam-v10-fullinstall-YYYYMMDD
#   chmod +x install.sh
#   ./install.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="$HOME/AIPAM"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  AIPAM V10 Installer — Ubuntu 24.04 (Offline)${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""

# ── 1. Docker Engine ──
if command -v docker &>/dev/null; then
    echo -e "${YELLOW}[1/8]${NC} Docker already installed — $(docker --version)"
else
    echo -e "${YELLOW}[1/8]${NC} Installing Docker Engine from bundled packages..."
    if [ -d "$SCRIPT_DIR/docker-debs" ] && ls "$SCRIPT_DIR"/docker-debs/*.deb &>/dev/null; then
        sudo dpkg -i "$SCRIPT_DIR"/docker-debs/*.deb || true
        sudo apt-get install -f -y -qq 2>/dev/null || true
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo usermod -aG docker "$USER"
        echo -e "  ${GREEN}✓${NC} Docker installed"
    else
        echo -e "  ${RED}✗ docker-debs/ not found — cannot install Docker offline${NC}"
        exit 1
    fi
fi

# ── 2. NVIDIA Container Toolkit (for GPU support) ──
echo -e "${YELLOW}[2/8]${NC} Installing NVIDIA Container Toolkit..."
if command -v nvidia-ctk &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Already installed — $(nvidia-ctk --version 2>/dev/null || echo 'installed')"
elif [ -d "$SCRIPT_DIR/nvidia-ctk-debs" ] && ls "$SCRIPT_DIR"/nvidia-ctk-debs/*.deb &>/dev/null; then
    sudo dpkg -i "$SCRIPT_DIR"/nvidia-ctk-debs/*.deb || true
    sudo apt-get install -f -y -qq 2>/dev/null || true
    # Configure Docker to use nvidia runtime
    sudo nvidia-ctk runtime configure --runtime=docker 2>/dev/null || true
    sudo systemctl restart docker 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} NVIDIA Container Toolkit installed"
else
    echo -e "  ${YELLOW}⚠${NC}  NVIDIA CTK packages not found — GPU acceleration unavailable"
    echo "      Ollama will run in CPU mode (slower but functional)"
fi

# ── 3. Ollama ──
if command -v ollama &>/dev/null; then
    echo -e "${YELLOW}[3/8]${NC} Ollama already installed — $(ollama --version 2>/dev/null || echo 'installed')"
else
    echo -e "${YELLOW}[3/8]${NC} Installing Ollama from bundled tarball..."
    OLLAMA_TGZ=$(ls "$SCRIPT_DIR"/ollama-linux-*.tgz 2>/dev/null | head -1)
    if [ -z "$OLLAMA_TGZ" ]; then
        echo -e "  ${RED}✗ ollama-linux-*.tgz not found${NC}"; exit 1
    fi
    sudo tar -C /usr/local -xzf "$OLLAMA_TGZ"
    echo -e "  ${GREEN}✓${NC} Extracted to /usr/local/bin/ollama"

    # Create ollama system user
    if ! id ollama &>/dev/null; then
        sudo useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
        echo -e "  ${GREEN}✓${NC} Created ollama system user"
    fi
    sudo usermod -aG ollama "$(whoami)" 2>/dev/null || true

    # Create systemd service
    sudo tee /etc/systemd/system/ollama.service > /dev/null << 'SVCEOF'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="OLLAMA_HOST=0.0.0.0"

[Install]
WantedBy=default.target
SVCEOF
    sudo systemctl daemon-reload
    sudo systemctl enable ollama
    sudo systemctl start ollama
    echo -e "  ${GREEN}✓${NC} Ollama service created and started (0.0.0.0:11434)"
fi
INSTALL_EOF
chmod +x "$OUTPUT_DIR/install.sh"

# Append second half of install script
cat >> "$OUTPUT_DIR/install.sh" << 'INSTALL_EOF2'

# Ensure Ollama listens on all interfaces
echo "  Verifying Ollama binds to 0.0.0.0..."
OLLAMA_SERVICE="/etc/systemd/system/ollama.service"
if [ -f "$OLLAMA_SERVICE" ]; then
    if grep -q 'Environment="OLLAMA_HOST=' "$OLLAMA_SERVICE"; then
        sudo sed -i 's|Environment="OLLAMA_HOST=.*"|Environment="OLLAMA_HOST=0.0.0.0"|' "$OLLAMA_SERVICE"
    else
        sudo sed -i '/^\[Service\]/a Environment="OLLAMA_HOST=0.0.0.0"' "$OLLAMA_SERVICE"
    fi
    sudo systemctl daemon-reload
fi
if ! systemctl is-active --quiet ollama 2>/dev/null; then
    sudo systemctl start ollama 2>/dev/null || ollama serve &>/dev/null &
else
    sudo systemctl restart ollama
fi
sleep 3
echo -e "  ${GREEN}✓${NC} Ollama listening on 0.0.0.0:11434"

# ── 4. Extract source code ──
echo -e "${YELLOW}[4/8]${NC} Extracting AIPAM source code..."
if [ -d "$INSTALL_DIR" ]; then
    echo -e "  ${YELLOW}⚠${NC}  $INSTALL_DIR already exists — backing up"
    mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%s)"
fi
tar -xzf "$SCRIPT_DIR/repo.tar.gz" -C "$HOME"
echo -e "  ${GREEN}✓${NC} Source code extracted to $INSTALL_DIR"

# ── 5. Create .env ──
echo -e "${YELLOW}[5/8]${NC} Setting up .env configuration..."
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$SCRIPT_DIR/env.template" "$INSTALL_DIR/.env"
    echo -e "  ${GREEN}✓${NC} .env created from template"
    echo -e "  ${YELLOW}⚠${NC}  IMPORTANT: Edit $INSTALL_DIR/.env to set your API token!"
else
    echo -e "  ${GREEN}✓${NC} .env already exists (preserved)"
fi

# ── 6. Load Docker images ──
echo -e "${YELLOW}[6/8]${NC} Loading Docker images (this takes several minutes)..."
if [ -f "$SCRIPT_DIR/docker-images.tar.gz" ]; then
    docker load < "$SCRIPT_DIR/docker-images.tar.gz"
    echo -e "  ${GREEN}✓${NC} All Docker images loaded"
else
    echo -e "  ${YELLOW}⚠${NC}  docker-images.tar.gz not found — will need to build from source"
fi

# ── 7. Import V10 model into Ollama ──
echo -e "${YELLOW}[7/8]${NC} Importing V10 model into Ollama (this takes a few minutes)..."
cd "$SCRIPT_DIR"
ollama create aipam-trafficllm-v10 -f Modelfile.v10
echo -e "  ${GREEN}✓${NC} Model imported:"
ollama list | grep -i aipam || true

# ── 8. Start Docker stack ──
echo -e "${YELLOW}[8/8]${NC} Starting AIPAM Docker stack..."
cd "$INSTALL_DIR"
docker compose up -d 2>&1 | tail -10

# ── Verify ──
sleep 8
echo ""
docker compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || true

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  AIPAM V10 Installation Complete!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo -e "  Frontend:  ${GREEN}http://${LOCAL_IP}:80${NC}"
echo -e "  API:       ${GREEN}http://${LOCAL_IP}:8000/docs${NC}"
echo -e "  Ollama:    ${GREEN}http://localhost:11434${NC}"
echo -e "  Model:     aipam-trafficllm-v10 (Q4_K_M, 5477 distilled samples)"
echo ""
echo -e "  ${YELLOW}Configuration:${NC}  $INSTALL_DIR/.env"
echo -e "  ${YELLOW}Stop:${NC}           cd $INSTALL_DIR && docker compose down"
echo -e "  ${YELLOW}Start:${NC}          cd $INSTALL_DIR && docker compose up -d"
echo -e "  ${YELLOW}Arkime:${NC}         cd $INSTALL_DIR && docker compose --profile arkime up -d"
echo ""
echo -e "  ${YELLOW}NOTE:${NC} If this is a fresh Docker install, log out and back in"
echo -e "  (or run 'newgrp docker') for group permissions to take effect."
INSTALL_EOF2

# ── Generate README ──
cat > "$OUTPUT_DIR/README-INSTALL.txt" << EOF
AIPAM V10 Full Migration Package — $(date +%Y-%m-%d)  (Air-Gapped)
================================================================

This package contains EVERYTHING needed to deploy AIPAM on a
brand-new air-gapped Ubuntu 24.04 server. No internet required.

Contents:
  repo.tar.gz                              Full source code
  aipam-trafficllm-v10.Q4_K_M.gguf        V10 fine-tuned LLM (~4.6 GB)
  Modelfile.v10                            Ollama model definition
  ollama-linux-amd64.tgz                   Ollama binary + CUDA libs
  docker-debs/                             Docker Engine .deb packages
  nvidia-ctk-debs/                         NVIDIA Container Toolkit packages
  docker-images.tar.gz                     Pre-built Docker images (all 6)
  env.template                             .env configuration template
  install.sh                               Turnkey offline installer
  README-INSTALL.txt                       This file

Docker Images Included:
  aipam-app:latest                         Backend API + Worker (~6.8 GB)
  aipam-frontend:latest                    Nginx frontend (~49 MB)
  ollama/ollama:latest                     LLM inference (~3.8 GB)
  redis:7-alpine                           Celery broker (~41 MB)
  opensearchproject/opensearch:2.18.0      Arkime metadata (~1.4 GB)
  ghcr.io/arkime/arkime/arkime:v6-latest   Packet investigation (~752 MB)

Quick Start:
  1. Transfer this directory to the target server:
       rsync -avP aipam-v10-fullinstall-$DATE/ user@<ip>:~/aipam-install/

  2. SSH into the server and run:
       cd ~/aipam-install
       chmod +x install.sh
       ./install.sh

  3. Edit ~/AIPAM/.env (set your API token, enable integrations)

  4. Open http://<server-ip>:80 in your browser

Server Requirements:
  - Ubuntu 24.04 LTS (fresh or existing)
  - 32 GB RAM recommended (16 GB minimum)
  - 150 GB free disk space
  - NVIDIA GPU with 8+ GB VRAM (optional, for fast inference)
  - NO internet access required

Ports Used:
  80     — Web UI (frontend)
  8000   — API (backend)
  11434  — Ollama (LLM inference, all interfaces)
  8005   — Arkime viewer (optional, if arkime profile enabled)
EOF

# ── Final Summary ──
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  AIPAM V10 Full Migration Package Ready!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Location: $OUTPUT_DIR"
echo "  Total size: $TOTAL_SIZE"
echo ""
echo "  Contents:"
ls -lh "$OUTPUT_DIR" | grep -v "^total" | awk '{print "    "$NF" ("$5")"}'
if [ -d "$OUTPUT_DIR/docker-debs" ]; then
    echo "    docker-debs/ ($(du -sh "$OUTPUT_DIR/docker-debs" | cut -f1))"
fi
if [ -d "$OUTPUT_DIR/nvidia-ctk-debs" ]; then
    echo "    nvidia-ctk-debs/ ($(du -sh "$OUTPUT_DIR/nvidia-ctk-debs" | cut -f1))"
fi
echo ""
echo -e "  ${YELLOW}Transfer to offline server:${NC}"
echo "    rsync -avP --progress $OUTPUT_DIR/ user@<server-ip>:~/aipam-install/"
echo ""
echo -e "  ${YELLOW}Then on the server:${NC}"
echo "    cd ~/aipam-install && chmod +x install.sh && ./install.sh"