#!/usr/bin/env bash
# ============================================================
# AIPAM Unified Startup Script
# Works on macOS, Linux, and Git Bash on Windows (WSL/MSYS)
#
# Starts:
#   1. Docker Compose stack (backend, worker, frontend, redis)
#   2. Host trainer launcher (auto-starts host trainer on demand)
#   3. Host trainer (for native MLX fine-tuning on Apple Silicon)
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM — Starting all services${NC}"
echo -e "${GREEN}============================================${NC}"

# ── 1. Docker Compose ──
echo -e "\n${YELLOW}[1/3]${NC} Starting Docker stack..."
docker compose down 2>/dev/null || true
docker compose up -d --build

# ── 2 & 3. Host Trainer + Launcher (platform-aware) ──
OS="$(uname -s)"

case "$OS" in
    Darwin)
        # macOS — start MLX host trainer + launcher for Apple Silicon
        echo -e "\n${YELLOW}[2/3]${NC} Starting host trainer for Apple Silicon (MLX)..."

        # Kill any existing host trainer and launcher
        lsof -ti:8002 | xargs kill -9 2>/dev/null || true
        lsof -ti:8003 | xargs kill -9 2>/dev/null || true

        # Start host trainer in background
        nohup python3 finetuning/host_trainer.py > /tmp/aipam_host_trainer.log 2>&1 &
        HOST_PID=$!
        echo "$HOST_PID" > /tmp/aipam_host_trainer.pid

        sleep 1
        if kill -0 "$HOST_PID" 2>/dev/null; then
            echo -e "${GREEN}  ✓ Host trainer running (PID $HOST_PID, port 8002)${NC}"
        else
            echo -e "${RED}  ✗ Host trainer failed to start${NC}"
            cat /tmp/aipam_host_trainer.log 2>/dev/null
        fi

        # Start launcher daemon (allows web UI to auto-start/restart trainer)
        echo -e "\n${YELLOW}[3/3]${NC} Starting host trainer launcher daemon..."
        nohup python3 finetuning/host_trainer_launcher.py > /tmp/aipam_launcher.log 2>&1 &
        LAUNCHER_PID=$!
        echo "$LAUNCHER_PID" > /tmp/aipam_launcher.pid

        sleep 1
        if kill -0 "$LAUNCHER_PID" 2>/dev/null; then
            echo -e "${GREEN}  ✓ Launcher daemon running (PID $LAUNCHER_PID, port 8003)${NC}"
            echo -e "  ${GREEN}Web UI can now auto-start/restart the host trainer${NC}"
        else
            echo -e "${YELLOW}  ⚠ Launcher daemon failed — trainer must be managed manually${NC}"
        fi
        ;;
    Linux)
        # Linux — check for NVIDIA GPU; if present, start host trainer for CUDA training
        if command -v nvidia-smi &>/dev/null; then
            echo -e "\n${YELLOW}[2/3]${NC} NVIDIA GPU detected — starting host trainer for CUDA training..."

            # Kill any existing host trainer and launcher
            fuser -k 8002/tcp 2>/dev/null || true
            fuser -k 8003/tcp 2>/dev/null || true

            # Start host trainer in background
            nohup python3 finetuning/host_trainer.py > /tmp/aipam_host_trainer.log 2>&1 &
            HOST_PID=$!
            echo "$HOST_PID" > /tmp/aipam_host_trainer.pid

            sleep 1
            if kill -0 "$HOST_PID" 2>/dev/null; then
                echo -e "${GREEN}  ✓ Host trainer running (PID $HOST_PID, port 8002)${NC}"
            else
                echo -e "${RED}  ✗ Host trainer failed to start${NC}"
                cat /tmp/aipam_host_trainer.log 2>/dev/null
            fi

            # Start launcher daemon (allows web UI to auto-start/restart trainer)
            echo -e "\n${YELLOW}[3/3]${NC} Starting host trainer launcher daemon..."
            nohup python3 finetuning/host_trainer_launcher.py > /tmp/aipam_launcher.log 2>&1 &
            LAUNCHER_PID=$!
            echo "$LAUNCHER_PID" > /tmp/aipam_launcher.pid

            sleep 1
            if kill -0 "$LAUNCHER_PID" 2>/dev/null; then
                echo -e "${GREEN}  ✓ Launcher daemon running (PID $LAUNCHER_PID, port 8003)${NC}"
                echo -e "  ${GREEN}Web UI can now auto-start/restart the host trainer${NC}"
            else
                echo -e "${YELLOW}  ⚠ Launcher daemon failed — trainer must be managed manually${NC}"
            fi
        else
            echo -e "\n${YELLOW}[2/3]${NC} No GPU detected — training will use CPU in Docker"
            echo -e "${YELLOW}[3/3]${NC} Launcher not needed without GPU — skipped"
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        # Windows (Git Bash / WSL)
        if command -v nvidia-smi.exe &>/dev/null 2>&1; then
            echo -e "\n${YELLOW}[2/3]${NC} NVIDIA GPU detected — CUDA training runs in Docker"
            echo -e "  Set Training Backend to 'CUDA' in Settings"
        else
            echo -e "\n${YELLOW}[2/3]${NC} No GPU detected — training will use CPU in Docker"
        fi
        echo -e "${YELLOW}[3/3]${NC} Launcher not needed on Windows — skipped"
        ;;
    *)
        echo -e "\n${YELLOW}[2/3]${NC} Unknown OS ($OS) — skipping host trainer"
        echo -e "${YELLOW}[3/3]${NC} Skipped"
        ;;
esac

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM is ready!${NC}"
echo -e "${GREEN}  Frontend: http://localhost:5173${NC}"
echo -e "${GREEN}  API:      http://localhost:8000/docs${NC}"
echo -e "${GREEN}============================================${NC}"
