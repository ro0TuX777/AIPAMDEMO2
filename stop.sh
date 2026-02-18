#!/usr/bin/env bash
# ============================================================
# AIPAM Unified Stop Script
# Stops Docker Compose, host trainer, and launcher
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
NC='\033[0m'

echo "Stopping AIPAM services..."

# Stop launcher daemon
if [ -f /tmp/aipam_launcher.pid ]; then
    PID=$(cat /tmp/aipam_launcher.pid)
    kill "$PID" 2>/dev/null && echo "  ✓ Launcher daemon stopped (PID $PID)"
    rm -f /tmp/aipam_launcher.pid
fi
lsof -ti:8003 | xargs kill -9 2>/dev/null || true

# Stop host trainer
if [ -f /tmp/aipam_host_trainer.pid ]; then
    PID=$(cat /tmp/aipam_host_trainer.pid)
    kill "$PID" 2>/dev/null && echo "  ✓ Host trainer stopped (PID $PID)"
    rm -f /tmp/aipam_host_trainer.pid
fi
lsof -ti:8002 | xargs kill -9 2>/dev/null || true

# Stop Docker
docker compose down

echo -e "${GREEN}AIPAM stopped.${NC}"
