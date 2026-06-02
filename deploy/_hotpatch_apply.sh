#!/bin/bash
# ============================================================
# AIPAM Hot-Patch Apply Script (Air-Gapped)
#
# Copies updated source files into the running containers via
# `docker cp` and restarts them. No internet, no image rebuild,
# no `docker load`. Applies in ~10 seconds.
#
#   ./apply.sh              # apply this hot-patch
#   ./apply.sh --rollback   # restore the previous backup
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

API_CTR="aipam-api"
WORKER_CTR="aipam-worker"
FRONTEND_CTR="aipam-frontend"

API_PATH="/app/backend/app"
WORKER_PATH="/app/backend/app"
FRONTEND_PATH="/usr/share/nginx/html"

# Smoke-test endpoints (host-side ports exposed by docker-compose)
API_BASE="http://localhost:8000/api/v1"
FRONTEND_BASE="http://localhost:80"

# Look for the AIPAM .env to extract the Bearer token for authenticated probes.
ENV_CANDIDATES=(
    "${HOME}/AIPAM/.env"
    "/opt/aipam/.env"
    "${SCRIPT_DIR}/.env"
)

BACKUP_ROOT="${HOME}/aipam-hotpatch-backups"
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_ROOT/$TS"

cmd="${1:-apply}"

require_container() {
    local name="$1"
    if ! docker inspect "$name" >/dev/null 2>&1; then
        echo -e "${RED}x Container '$name' not found.${NC} Is the AIPAM stack running?"
        echo "    docker ps --format '{{.Names}}'"
        exit 1
    fi
}

backup_dir_in_container() {
    # $1 container, $2 in-container path, $3 host backup target
    local ctr="$1" path="$2" dst="$3"
    mkdir -p "$dst"
    docker cp "$ctr:$path/." "$dst/"
}

apply_tarball_to_container() {
    # $1 host tarball, $2 inside-tarball top-dir name, $3 container, $4 in-container path
    local tarball="$1" topdir="$2" ctr="$3" dst="$4"
    local tmp
    tmp="$(mktemp -d)"
    tar -xzf "$tarball" -C "$tmp"
    # Wipe destination first so deletes propagate, then copy contents.
    docker exec "$ctr" sh -c "rm -rf $dst/* $dst/.[!.]* 2>/dev/null || true"
    docker cp "$tmp/$topdir/." "$ctr:$dst/"
    rm -rf "$tmp"
}

if [ "$cmd" = "--rollback" ]; then
    LATEST="$(ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -1 || true)"
    if [ -z "$LATEST" ]; then
        echo -e "${RED}x No backups found in $BACKUP_ROOT${NC}"
        exit 1
    fi
    LATEST="${LATEST%/}"
    echo -e "${YELLOW}Rolling back from:${NC} $LATEST"
    require_container "$API_CTR"
    require_container "$WORKER_CTR"
    require_container "$FRONTEND_CTR"

    docker exec "$API_CTR"      sh -c "rm -rf $API_PATH/* $API_PATH/.[!.]* 2>/dev/null || true"
    docker cp "$LATEST/api/."      "$API_CTR:$API_PATH/"
    docker exec "$WORKER_CTR"   sh -c "rm -rf $WORKER_PATH/* $WORKER_PATH/.[!.]* 2>/dev/null || true"
    docker cp "$LATEST/worker/."   "$WORKER_CTR:$WORKER_PATH/"
    docker exec "$FRONTEND_CTR" sh -c "rm -rf $FRONTEND_PATH/* $FRONTEND_PATH/.[!.]* 2>/dev/null || true"
    docker cp "$LATEST/frontend/." "$FRONTEND_CTR:$FRONTEND_PATH/"

    docker restart "$API_CTR" "$WORKER_CTR" "$FRONTEND_CTR" >/dev/null
    echo -e "${GREEN}ok${NC} Rollback complete. Containers restarted."
    exit 0
fi

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Hot-Patch Apply${NC}"
echo -e "${GREEN}============================================${NC}"
[ -f MANIFEST.txt ] && cat MANIFEST.txt
echo ""

# ── Preflight ──
require_container "$API_CTR"
require_container "$WORKER_CTR"
require_container "$FRONTEND_CTR"
[ -f "$SCRIPT_DIR/backend-app.tar.gz"   ] || { echo -e "${RED}x backend-app.tar.gz missing${NC}";   exit 1; }
[ -f "$SCRIPT_DIR/frontend-dist.tar.gz" ] || { echo -e "${RED}x frontend-dist.tar.gz missing${NC}"; exit 1; }

# ── 1. Backup current state ──
echo -e "${YELLOW}[1/3]${NC} Backing up current container state to $BACKUP_DIR..."
mkdir -p "$BACKUP_DIR"
backup_dir_in_container "$API_CTR"      "$API_PATH"      "$BACKUP_DIR/api"
backup_dir_in_container "$WORKER_CTR"   "$WORKER_PATH"   "$BACKUP_DIR/worker"
backup_dir_in_container "$FRONTEND_CTR" "$FRONTEND_PATH" "$BACKUP_DIR/frontend"
echo -e "  ${GREEN}ok${NC} Backup saved ($(du -sh "$BACKUP_DIR" | cut -f1))"

# ── 2. Apply new files ──
echo -e "${YELLOW}[2/3]${NC} Copying new files into containers..."
apply_tarball_to_container "$SCRIPT_DIR/backend-app.tar.gz"   "app"  "$API_CTR"      "$API_PATH"
apply_tarball_to_container "$SCRIPT_DIR/backend-app.tar.gz"   "app"  "$WORKER_CTR"   "$WORKER_PATH"
apply_tarball_to_container "$SCRIPT_DIR/frontend-dist.tar.gz" "dist" "$FRONTEND_CTR" "$FRONTEND_PATH"
echo -e "  ${GREEN}ok${NC} Files copied"

# ── 3. Restart ──
echo -e "${YELLOW}[3/4]${NC} Restarting containers..."
docker restart "$API_CTR" "$WORKER_CTR" "$FRONTEND_CTR" >/dev/null
echo -e "  ${GREEN}ok${NC} Restarted"

# ── 4. Smoke test ──
echo -e "${YELLOW}[4/4]${NC} Running smoke test (informational; won't abort on failure)..."

# Resolve API token from the first .env found
TOKEN=""
for f in "${ENV_CANDIDATES[@]}"; do
    if [ -f "$f" ]; then
        TOKEN="$(grep -E '^AIPAM_API_TOKEN=' "$f" | head -1 | cut -d= -f2- | tr -d '\r\n"' )"
        [ -n "$TOKEN" ] && { echo "  Token sourced from: $f"; break; }
    fi
done
[ -z "$TOKEN" ] && echo -e "  ${YELLOW}!!${NC} No AIPAM_API_TOKEN found in .env — auth-protected probes will be skipped"

# Wait for backend to come up (docs is unauthenticated)
echo -n "  Waiting for backend"
for i in $(seq 1 30); do
    if curl -fsS -o /dev/null "$API_BASE/docs" 2>/dev/null; then
        echo " — up after ${i}s"; break
    fi
    echo -n "."; sleep 1
    if [ "$i" = "30" ]; then echo " — TIMEOUT (backend did not start in 30s)"; fi
done

probe() {
    # $1 label   $2 url   $3 expected_status   [$4 use_token]
    local label="$1" url="$2" want="$3" use_tok="${4:-}"
    local hdr=()
    [ "$use_tok" = "auth" ] && [ -n "$TOKEN" ] && hdr=(-H "Authorization: Bearer $TOKEN")
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' "${hdr[@]}" "$url" 2>/dev/null || echo 000)"
    if [ "$code" = "$want" ]; then
        echo -e "    ${GREEN}PASS${NC}  $label ($code) — $url"
    else
        echo -e "    ${RED}FAIL${NC}  $label (got $code, want $want) — $url"
    fi
}

probe "Backend docs"             "$API_BASE/docs"                   200
probe "Frontend index"           "$FRONTEND_BASE/"                  200
if [ -n "$TOKEN" ]; then
    probe "GET /settings"            "$API_BASE/settings"               200 auth
    probe "GET /settings/setup_status" "$API_BASE/settings/setup_status" 200 auth
    probe "GET /integrations/settings" "$API_BASE/integrations/settings" 200 auth
    probe "GET /jobs"                "$API_BASE/jobs"                   200 auth
fi

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Hot-Patch Applied!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Backup of previous state: $BACKUP_DIR"
echo "  To roll back:             $SCRIPT_DIR/apply.sh --rollback"
echo ""
echo "  Tail backend logs:        docker logs -f $API_CTR --tail 50"
echo "  Hard-refresh the browser (Ctrl+Shift+R) to load the new frontend bundle."
