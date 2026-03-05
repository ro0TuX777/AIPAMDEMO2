#!/bin/bash
# ============================================================
# AIPAM VM Migration Script  (Air-Gapped Edition)
# Packages everything needed to deploy AIPAM on a fresh
# Ubuntu 24.04 VM **without any internet access**.
#
# Usage:
#   ./deploy/migrate_to_vm.sh [output-dir]
#
# What it creates:
#   aipam-migrate-YYYYMMDD/
#     ├── repo.tar.gz                   (~150 MB  - full git repo)
#     ├── aipam-cybersec-llm-v8.gguf    (~8 GB   - the V8 model)
#     ├── Modelfile                     (Ollama model definition)
#     ├── ollama-linux-amd64.tgz        (~1.6 GB  - Ollama binary + CUDA libs)
#     ├── docker-debs/                  (~120 MB  - Docker Engine .deb packages)
#     ├── docker-images.tar.gz          (~1.5 GB  - pre-built Docker images)
#     ├── install.sh                    (turnkey offline installer)
#     └── README-INSTALL.txt            (quick reference)
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

# Versions to bundle
OLLAMA_VERSION="0.6.8"
TARGET_DISTRO="noble"       # Ubuntu 24.04
TARGET_ARCH="amd64"
DOCKER_DEB_BASE="https://download.docker.com/linux/ubuntu/dists/${TARGET_DISTRO}/pool/stable/${TARGET_ARCH}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM VM Migration Packager (Air-Gapped)${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── Preflight checks ──
echo -e "${YELLOW}[1/8]${NC} Preflight checks..."

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
echo -e "${YELLOW}[2/8]${NC} Creating package directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── Export git repo (excludes large training data) ──
echo ""
echo -e "${YELLOW}[3/8]${NC} Exporting git repository..."
echo "  This includes all source code but excludes untracked large files."
cd "$PROJECT_ROOT"
git archive --format=tar.gz --prefix=AIPAM/ HEAD > "$OUTPUT_DIR/repo.tar.gz"
REPO_SIZE=$(du -h "$OUTPUT_DIR/repo.tar.gz" | cut -f1)
echo -e "  ${GREEN}✓${NC} repo.tar.gz ($REPO_SIZE)"

# ── Copy model files ──
echo ""
echo -e "${YELLOW}[4/8]${NC} Copying V8 model (this may take a minute)..."
cp "$GGUF_PATH" "$OUTPUT_DIR/aipam-cybersec-llm-v8.gguf"
cp "$MODELFILE_PATH" "$OUTPUT_DIR/Modelfile"

# Fix Modelfile path to reference local GGUF
sed -i 's|^FROM .*|FROM ./aipam-cybersec-llm-v8.gguf|' "$OUTPUT_DIR/Modelfile"

MODEL_SIZE=$(du -h "$OUTPUT_DIR/aipam-cybersec-llm-v8.gguf" | cut -f1)
echo -e "  ${GREEN}✓${NC} aipam-cybersec-llm-v8.gguf ($MODEL_SIZE)"
echo -e "  ${GREEN}✓${NC} Modelfile (patched FROM path)"

# ── Download Ollama tarball (for air-gapped install) ──
echo ""
echo -e "${YELLOW}[5/8]${NC} Downloading Ollama v${OLLAMA_VERSION} tarball..."
OLLAMA_TGZ="ollama-linux-${TARGET_ARCH}.tgz"
OLLAMA_URL="https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/${OLLAMA_TGZ}"
if [ -f "$OUTPUT_DIR/$OLLAMA_TGZ" ]; then
    echo -e "  ${GREEN}✓${NC} Already downloaded (skipping)"
else
    curl -fSL --progress-bar -o "$OUTPUT_DIR/$OLLAMA_TGZ" "$OLLAMA_URL"
fi
OLLAMA_SIZE=$(du -h "$OUTPUT_DIR/$OLLAMA_TGZ" | cut -f1)
echo -e "  ${GREEN}✓${NC} $OLLAMA_TGZ ($OLLAMA_SIZE) — includes CUDA libraries"

# ── Download Docker Engine .deb packages (for air-gapped install) ──
echo ""
echo -e "${YELLOW}[6/8]${NC} Downloading Docker Engine .deb packages for Ubuntu ${TARGET_DISTRO}/${TARGET_ARCH}..."
mkdir -p "$OUTPUT_DIR/docker-debs"
DOCKER_PKGS=(containerd.io docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin)
for pkg in "${DOCKER_PKGS[@]}"; do
    # Find the latest version of each package from the Docker repo index
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
DEBS_SIZE=$(du -sh "$OUTPUT_DIR/docker-debs" | cut -f1)
echo -e "  ${GREEN}✓${NC} Docker .deb packages total: $DEBS_SIZE"

# ── Export Docker images (for air-gapped install) ──
echo ""
echo -e "${YELLOW}[7/8]${NC} Exporting Docker images (this may take a few minutes)..."
cd "$PROJECT_ROOT"
# Build the stack first to ensure images are current
echo "  Building AIPAM Docker images..."
docker compose build --quiet 2>&1
# Collect all images needed by the stack
COMPOSE_IMAGES=$(docker compose config --images 2>/dev/null)
echo "  Saving images: $(echo "$COMPOSE_IMAGES" | tr '\n' ' ')"
# shellcheck disable=SC2086
docker save $COMPOSE_IMAGES | gzip > "$OUTPUT_DIR/docker-images.tar.gz"
IMAGES_SIZE=$(du -h "$OUTPUT_DIR/docker-images.tar.gz" | cut -f1)
echo -e "  ${GREEN}✓${NC} docker-images.tar.gz ($IMAGES_SIZE)"

# ── Generate install script ──
echo ""
echo -e "${YELLOW}[8/8]${NC} Generating install.sh..."

cat > "$OUTPUT_DIR/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# ============================================================
# AIPAM Turnkey Installer for Ubuntu 24.04  (Air-Gapped)
# Run this on the target VM after transferring the package.
# NO internet connection required.
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
echo -e "${GREEN}  AIPAM Installer — Ubuntu 24.04 (Offline)${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── 1. Docker Engine (from bundled .deb packages) ──
if command -v docker &>/dev/null; then
    echo -e "${YELLOW}[1/7]${NC} Docker already installed — $(docker --version)"
else
    echo -e "${YELLOW}[1/7]${NC} Installing Docker Engine from bundled packages..."
    if [ -d "$SCRIPT_DIR/docker-debs" ] && ls "$SCRIPT_DIR"/docker-debs/*.deb &>/dev/null; then
        sudo dpkg -i "$SCRIPT_DIR"/docker-debs/*.deb || true
        # Fix any missing dependencies from the local system
        sudo apt-get install -f -y -qq 2>/dev/null || true
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo usermod -aG docker "$USER"
        echo -e "  ${GREEN}✓${NC} Docker installed from local .deb packages"
    else
        echo -e "  ${RED}✗ docker-debs/ directory not found — cannot install Docker offline${NC}"
        exit 1
    fi
fi

# ── 2. Ollama (from bundled tarball) ──
if command -v ollama &>/dev/null; then
    echo -e "${YELLOW}[2/7]${NC} Ollama already installed — $(ollama --version)"
else
    echo -e "${YELLOW}[2/7]${NC} Installing Ollama from bundled tarball..."
    OLLAMA_TGZ=$(ls "$SCRIPT_DIR"/ollama-linux-*.tgz 2>/dev/null | head -1)
    if [ -z "$OLLAMA_TGZ" ]; then
        echo -e "  ${RED}✗ ollama-linux-*.tgz not found in package${NC}"
        exit 1
    fi

    # Extract tarball to /usr (bin/ollama → /usr/local/bin/ollama, lib/ollama → /usr/local/lib/ollama)
    sudo tar -C /usr/local -xzf "$OLLAMA_TGZ"
    echo -e "  ${GREEN}✓${NC} Extracted to /usr/local/bin/ollama + /usr/local/lib/ollama"

    # Create ollama user & group (matches official installer)
    if ! id ollama &>/dev/null; then
        sudo useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
        echo -e "  ${GREEN}✓${NC} Created ollama system user"
    fi
    sudo usermod -aG ollama "$(whoami)" 2>/dev/null || true

    # Create systemd service file
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
    echo -e "  ${GREEN}✓${NC} Ollama service created and started (listening on 0.0.0.0:11434)"
fi
INSTALL_EOF

chmod +x "$OUTPUT_DIR/install.sh"

# Continue the install script (second half)
cat >> "$OUTPUT_DIR/install.sh" << 'INSTALL_EOF2'

# Ensure Ollama is configured to listen on all interfaces
echo -e "  Verifying Ollama listens on 0.0.0.0 (required for Docker containers)..."
OLLAMA_SERVICE=$(systemctl show ollama --property=FragmentPath 2>/dev/null | cut -d= -f2)
if [ -z "$OLLAMA_SERVICE" ]; then
    OLLAMA_SERVICE="/etc/systemd/system/ollama.service"
fi
if [ -f "$OLLAMA_SERVICE" ]; then
    if grep -q 'Environment="OLLAMA_HOST=' "$OLLAMA_SERVICE"; then
        sudo sed -i 's|Environment="OLLAMA_HOST=.*"|Environment="OLLAMA_HOST=0.0.0.0"|' "$OLLAMA_SERVICE"
    else
        sudo sed -i '/^\[Service\]/a Environment="OLLAMA_HOST=0.0.0.0"' "$OLLAMA_SERVICE"
    fi
    echo -e "  ${GREEN}✓${NC} Patched $OLLAMA_SERVICE"
fi
sudo systemctl daemon-reload

# Make sure Ollama service is running
if ! systemctl is-active --quiet ollama 2>/dev/null; then
    sudo systemctl start ollama 2>/dev/null || ollama serve &>/dev/null &
else
    sudo systemctl restart ollama
fi
sleep 3
echo -e "  ${GREEN}✓${NC} Ollama listening on 0.0.0.0:11434"

# ── 3. Extract repo ──
echo -e "${YELLOW}[3/7]${NC} Extracting AIPAM source code..."
INSTALL_DIR="$HOME/AIPAM"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "  ${YELLOW}⚠${NC}  $INSTALL_DIR already exists — backing up to ${INSTALL_DIR}.bak"
    mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
fi
tar -xzf repo.tar.gz -C "$HOME"
echo -e "  ${GREEN}✓${NC} Source code extracted to $INSTALL_DIR"

# ── 4. Load Docker images (pre-built, no internet needed) ──
echo -e "${YELLOW}[4/7]${NC} Loading pre-built Docker images..."
if [ -f "$SCRIPT_DIR/docker-images.tar.gz" ]; then
    docker load < "$SCRIPT_DIR/docker-images.tar.gz"
    echo -e "  ${GREEN}✓${NC} Docker images loaded"
else
    echo -e "  ${YELLOW}⚠${NC}  docker-images.tar.gz not found — docker compose will try to build from source"
fi

# ── 5. Import V8 model into Ollama ──
echo -e "${YELLOW}[5/7]${NC} Importing V8 model into Ollama (this takes a few minutes)..."
cd "$SCRIPT_DIR"
ollama create aipam-trafficllm-v8 -f Modelfile
echo -e "  ${GREEN}✓${NC} Model imported:"
ollama list | grep aipam

# ── 6. Start Docker stack ──
echo -e "${YELLOW}[6/7]${NC} Starting AIPAM Docker stack..."
cd "$INSTALL_DIR"
docker compose up -d 2>&1 | tail -5

# ── 7. Verify ──
echo -e "${YELLOW}[7/7]${NC} Verifying services..."
sleep 5
docker compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || true

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
AIPAM VM Migration Package — $(date +%Y-%m-%d)  (Air-Gapped)
==============================================================

This package contains EVERYTHING needed to deploy AIPAM on an
air-gapped Ubuntu 24.04 VM. No internet connection required.

Contents:
  repo.tar.gz                   Git repo with all source code
  aipam-cybersec-llm-v8.gguf   Fine-tuned Llama 3.1 8B model (~8 GB)
  Modelfile                     Ollama model definition
  ollama-linux-amd64.tgz        Ollama binary + CUDA libs (offline install)
  docker-debs/                  Docker Engine .deb packages (offline install)
  docker-images.tar.gz          Pre-built Docker images (no pull needed)
  install.sh                    Turnkey offline installer
  README-INSTALL.txt            This file

Quick Start:
  1. Transfer this entire directory to the target VM (USB, SCP, etc.):
       rsync -avP aipam-migrate-$DATE/ user@vm-ip:~/aipam-migrate/

  2. SSH into the VM and run:
       cd ~/aipam-migrate
       chmod +x install.sh
       ./install.sh

  3. Open http://<vm-ip>:5173 in your browser.

VM Requirements:
  - Ubuntu 24.04 LTS
  - 16 GB RAM (32 GB recommended)
  - 150 GB free disk
  - NO internet access required

Ports Used:
  5173  — Web UI (frontend)
  8000  — API (backend)
  11434 — Ollama (all interfaces)
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

