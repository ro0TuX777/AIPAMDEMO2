#!/bin/bash
# ============================================================
# AIPAM Hot-Patch Package Builder
#
# Produces a small (~5 MB) update package containing only the
# changed source files — no Docker images. The package is
# applied on the offline server via `docker cp` + container
# restart, so no internet, no `docker load`, no image rebuild.
#
# Use this for routine code changes (Python bugfixes, frontend
# tweaks, new endpoints). For dependency changes (requirements
# .txt, package.json, base image), use create-code-update.sh.
#
# Usage:
#   AIPAM_API_TOKEN=<server-token> ./deploy/create-hotpatch.sh
#   ./deploy/create-hotpatch.sh --init-baseline    (one-time, after first full build)
#   ./deploy/create-hotpatch.sh --update-baseline  (after every full image rebuild)
#
# Pre-flight: the script aborts with a clear error if any
# dependency-sensitive file (requirements.txt, package.json,
# Dockerfiles, docker-compose.yml) has changed since the recorded
# baseline — those changes require a full image rebuild via
# create-code-update.sh, not a hot-patch.
#
# The AIPAM_API_TOKEN must match the offline server's .env so
# the frontend bundle ships with a valid Bearer token. If the
# token differs from the local .env, set it explicitly here.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y%m%d)
LABEL="${HOTPATCH_LABEL:-$DATE}"
OUTPUT_DIR="$PROJECT_ROOT/dist/aipam-hotpatch-$LABEL"
BASELINE_FILE="$SCRIPT_DIR/.hotpatch-baseline"

# Files whose change would invalidate a hot-patch (require full image rebuild).
DEP_FILES=(
    "backend/requirements.txt"
    "backend/Dockerfile"
    "deploy/Dockerfile.app"
    "deploy/Dockerfile.ollama"
    "frontend/package.json"
    "frontend/package-lock.json"
    "frontend/Dockerfile"
    "docker-compose.yml"
    "deploy/docker-compose.yml"
)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cd "$PROJECT_ROOT"

# ── Handle --update-baseline / --init-baseline (run after a full image build) ──
if [ "${1:-}" = "--update-baseline" ] || [ "${1:-}" = "--init-baseline" ]; then
    echo -e "${YELLOW}Recording new dependency baseline at $BASELINE_FILE${NC}"
    : > "$BASELINE_FILE"
    for f in "${DEP_FILES[@]}"; do
        if [ -f "$PROJECT_ROOT/$f" ]; then
            sha256sum "$PROJECT_ROOT/$f" | awk -v p="$f" '{print $1"  "p}' >> "$BASELINE_FILE"
        fi
    done
    echo -e "${GREEN}ok${NC} baseline updated ($(wc -l < "$BASELINE_FILE") files tracked):"
    sed 's/^/    /' "$BASELINE_FILE"
    exit 0
fi

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  AIPAM Hot-Patch Package Builder${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ── Pre-flight: dependency-drift guard ──
echo -e "${YELLOW}[0/5]${NC} Checking for dependency drift since last full image build..."
if [ ! -f "$BASELINE_FILE" ]; then
    echo -e "  ${RED}x No baseline file at $BASELINE_FILE${NC}"
    echo "    A baseline records the sha256 of dependency files at the time of the"
    echo "    last full image build (create-code-update.sh). Without it we cannot"
    echo "    verify that a hot-patch is safe."
    echo ""
    echo "    To create one now (only safe if the offline server's images were built"
    echo "    from this commit's dependency files):"
    echo "        ./deploy/create-hotpatch.sh --init-baseline"
    echo ""
    echo "    Or bypass the check (NOT recommended):"
    echo "        HOTPATCH_FORCE=1 ./deploy/create-hotpatch.sh"
    [ "${HOTPATCH_FORCE:-0}" = "1" ] || exit 1
    echo -e "  ${YELLOW}!! HOTPATCH_FORCE=1 set — continuing without baseline${NC}"
else
    DRIFT=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        expected_sha="${line%% *}"
        path="${line##* }"
        if [ ! -f "$PROJECT_ROOT/$path" ]; then
            DRIFT+=("$path (deleted)")
            continue
        fi
        actual_sha="$(sha256sum "$PROJECT_ROOT/$path" | awk '{print $1}')"
        if [ "$actual_sha" != "$expected_sha" ]; then
            DRIFT+=("$path (modified)")
        fi
    done < "$BASELINE_FILE"

    # Check for new dep files not in baseline
    while IFS= read -r path; do
        if [ -f "$PROJECT_ROOT/$path" ] && ! grep -q "  $path$" "$BASELINE_FILE"; then
            DRIFT+=("$path (new file)")
        fi
    done < <(printf '%s\n' "${DEP_FILES[@]}")

    if [ "${#DRIFT[@]}" -gt 0 ]; then
        echo -e "  ${RED}x Dependency drift detected — hot-patch NOT safe:${NC}"
        for d in "${DRIFT[@]}"; do echo "      • $d"; done
        echo ""
        echo "    These files changed since the last full image build, which means"
        echo "    pip/npm dependencies, base image, or container topology may differ"
        echo "    from what's currently running on the offline server."
        echo ""
        echo "    Required action:"
        echo "        ./deploy/create-code-update.sh        # build full 3.2 GB package"
        echo ""
        echo "    After applying the full package on the offline server, refresh the"
        echo "    baseline so future hot-patches work again:"
        echo "        ./deploy/create-hotpatch.sh --update-baseline"
        echo ""
        echo "    To bypass this check (NOT recommended — will likely produce a"
        echo "    broken hot-patch):"
        echo "        HOTPATCH_FORCE=1 ./deploy/create-hotpatch.sh"
        [ "${HOTPATCH_FORCE:-0}" = "1" ] || exit 1
        echo -e "  ${YELLOW}!! HOTPATCH_FORCE=1 set — continuing despite drift${NC}"
    else
        echo -e "  ${GREEN}ok${NC} no dependency drift — hot-patch is safe ($(wc -l < "$BASELINE_FILE") files verified)"
    fi
fi

# ── Resolve the API token used to build the frontend bundle ──
TOKEN="${AIPAM_API_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$PROJECT_ROOT/.env" ]; then
    TOKEN="$(grep -E '^AIPAM_API_TOKEN=' "$PROJECT_ROOT/.env" | head -1 | cut -d= -f2-)"
fi
if [ -z "$TOKEN" ]; then
    echo -e "${RED}x AIPAM_API_TOKEN is empty.${NC} Set it before running:"
    echo "    AIPAM_API_TOKEN=<server-token> ./deploy/create-hotpatch.sh"
    exit 1
fi
echo -e "${YELLOW}[1/5]${NC} Frontend will be built with API token: ${TOKEN:0:6}…(${#TOKEN} chars)"

# ── Build the frontend dist with the token baked in ──
echo -e "${YELLOW}[2/5]${NC} Building frontend (npm run build)..."
cd "$PROJECT_ROOT/frontend"
if [ ! -d node_modules ]; then
    echo -e "  ${YELLOW}!!${NC} node_modules missing — running npm install (needs internet)"
    npm install --no-audit --no-fund
fi
VITE_API_BASE_URL=/api/v1 VITE_API_TOKEN="$TOKEN" npm run build >/dev/null
[ -d dist ] || { echo -e "${RED}x npm run build did not produce dist/${NC}"; exit 1; }
echo -e "  ${GREEN}ok${NC} frontend/dist built ($(du -sh dist | cut -f1))"
cd "$PROJECT_ROOT"

# ── Create output directory ──
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── 3. Tar up backend Python source ──
echo -e "${YELLOW}[3/5]${NC} Bundling backend/app source..."
tar -czf "$OUTPUT_DIR/backend-app.tar.gz" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    -C "$PROJECT_ROOT/backend" app
echo -e "  ${GREEN}ok${NC} backend-app.tar.gz ($(du -h "$OUTPUT_DIR/backend-app.tar.gz" | cut -f1))"

# ── 4. Tar up the freshly-built frontend dist ──
echo -e "${YELLOW}[4/5]${NC} Bundling frontend/dist..."
tar -czf "$OUTPUT_DIR/frontend-dist.tar.gz" -C "$PROJECT_ROOT/frontend" dist
echo -e "  ${GREEN}ok${NC} frontend-dist.tar.gz ($(du -h "$OUTPUT_DIR/frontend-dist.tar.gz" | cut -f1))"

# ── 5. Manifest + apply.sh ──
echo -e "${YELLOW}[5/5]${NC} Generating apply.sh and MANIFEST..."
GIT_SHA="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

cat > "$OUTPUT_DIR/MANIFEST.txt" <<EOF
AIPAM Hot-Patch
  label:       $LABEL
  built:       $(date -u +"%Y-%m-%d %H:%M:%S UTC")
  git branch:  $GIT_BRANCH
  git sha:     $GIT_SHA
  token hint:  ${TOKEN:0:6}…(${#TOKEN} chars)

Contents:
  backend-app.tar.gz   → /app/backend/app/   in aipam-api + aipam-worker
  frontend-dist.tar.gz → /usr/share/nginx/html/   in aipam-frontend

Affects only Python source + frontend static files.
Container images and dependencies are NOT changed.
EOF

# apply.sh is generated below; keep < 150 lines if possible.
cp "$SCRIPT_DIR/_hotpatch_apply.sh" "$OUTPUT_DIR/apply.sh" 2>/dev/null || true
if [ ! -f "$OUTPUT_DIR/apply.sh" ]; then
    echo -e "${RED}x deploy/_hotpatch_apply.sh template missing${NC}"
    exit 1
fi
chmod +x "$OUTPUT_DIR/apply.sh"
echo -e "  ${GREEN}ok${NC} apply.sh + MANIFEST.txt"

# ── Summary ──
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Hot-Patch Package Ready!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Location:   $OUTPUT_DIR"
echo "  Total size: $TOTAL_SIZE"
echo ""
ls -lh "$OUTPUT_DIR" | grep -v "^total" | awk '{print "    "$NF" ("$5")"}'
echo ""
echo -e "  ${YELLOW}Transfer to offline server:${NC}"
echo "    rsync -avP $OUTPUT_DIR/ maint@<server-ip>:~/aipam-hotpatch/"
echo ""
echo -e "  ${YELLOW}Then on the server:${NC}"
echo "    cd ~/aipam-hotpatch && ./apply.sh"
echo ""
echo -e "  ${YELLOW}To rollback the last hot-patch:${NC}"
echo "    cd ~/aipam-hotpatch && ./apply.sh --rollback"
