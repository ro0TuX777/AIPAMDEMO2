#!/bin/bash
# ============================================================
# AIPAM Code-Only Update Script  (Air-Gapped)
#
# Usage:
#   ./update.sh                 Validate, apply update, validate, report.
#   ./update.sh --check-only    Run Phase A + a read-only Phase B against the
#                               currently-running stack.  Does NOT stop or
#                               modify anything.
#   ./update.sh --skip-validate Apply update without any validation
#                               (emergency reinstall).
#
# Bundled files:
#   repo.tar.gz                  Full source code
#   docker-images.tar.gz         aipam-app + aipam-frontend images
#   docker-compose.override.yml  Host-Ollama routing override
#   env.template                 Fresh .env template (used only if missing)
#   update.sh                    This script
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="$HOME/AIPAM"
BACKUP=""
MODE="apply"

for arg in "$@"; do
    case "$arg" in
        --check-only)    MODE="check" ;;
        --skip-validate) MODE="skip-validate" ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Result tracking ─────────────────────────────────────────
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
CORRECTIVE_ACTIONS=()

record_pass() { PASS_COUNT=$((PASS_COUNT+1)); printf "    ${GREEN}[PASS]${NC} %-50s — %s\n" "$1" "$2"; }
record_warn() {
    WARN_COUNT=$((WARN_COUNT+1))
    printf "    ${YELLOW}[WARN]${NC} %-50s — %s\n" "$1" "$2"
    [ -n "${3:-}" ] && CORRECTIVE_ACTIONS+=("WARN: $1"$'\n'"      Fix: $3")
}
record_fail() {
    FAIL_COUNT=$((FAIL_COUNT+1))
    printf "    ${RED}[FAIL]${NC} %-50s — %s\n" "$1" "$2"
    [ -n "${3:-}" ] && CORRECTIVE_ACTIONS+=("FAIL: $1"$'\n'"      Fix: $3")
}

print_actions() {
    if [ ${#CORRECTIVE_ACTIONS[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}── Corrective actions ──────────────────────────${NC}"
        for a in "${CORRECTIVE_ACTIONS[@]}"; do echo -e "  $a"; done
    fi
}

# ── .env helpers ────────────────────────────────────────────
env_get() {
    # $1 var name; $2 path. Returns 1 if file missing OR key absent.
    [ -f "$2" ] || return 1
    local line; line="$(grep -E "^${1}=" "$2" | tail -1)"
    [ -z "$line" ] && return 1
    local val="${line#*=}"; val="${val%$'\r'}"
    val="${val%\"}"; val="${val#\"}"
    val="${val%\'}"; val="${val#\'}"
    printf '%s' "$val"
}
env_set() {
    # $1 var name; $2 value; $3 path  (idempotent: replace or append)
    local key="$1" val="$2" file="$3"
    if grep -qE "^${key}=" "$file" 2>/dev/null; then
        # in-place replace (handle special chars via awk)
        awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{$0=k"="v} {print}' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        printf '\n%s=%s\n' "$key" "$val" >> "$file"
    fi
}

# ── Banner ──────────────────────────────────────────────────
echo -e "${GREEN}============================================${NC}"
case "$MODE" in
    apply)          echo -e "${GREEN}  AIPAM Code-Only Update  (Offline)${NC}" ;;
    check)          echo -e "${GREEN}  AIPAM Update Pre-flight Check${NC}" ;;
    skip-validate)  echo -e "${GREEN}  AIPAM Code-Only Update  (no validation)${NC}" ;;
esac
echo -e "${GREEN}============================================${NC}"
echo ""

# ════════════════════════════════════════════════════════════
# PHASE A — Pre-flight (auto-fix .env / override, probe host)
# ════════════════════════════════════════════════════════════
phase_a() {
    echo -e "${BLUE}── Phase A: pre-flight ─────────────────────────${NC}"

    # docker present + daemon up + user in group
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            record_pass "Docker daemon" "$(docker --version | cut -d, -f1)"
        else
            record_fail "Docker daemon" "cannot connect" \
                "sudo systemctl start docker && sudo usermod -aG docker \$USER && newgrp docker"
            return 1
        fi
    else
        record_fail "Docker installed" "not found" \
            "Run the V10 full installer first to bootstrap Docker on this host."
        return 1
    fi

    # Free disk
    if command -v df >/dev/null 2>&1; then
        local free_gb
        free_gb=$(df -BG --output=avail "$HOME" 2>/dev/null | tail -1 | tr -d 'G ')
        if [ -n "$free_gb" ] && [ "$free_gb" -lt 20 ]; then
            record_warn "Free disk space" "${free_gb} GB (<20 GB recommended)" \
                "Free at least 20 GB on $HOME before applying the update."
        else
            record_pass "Free disk space" "${free_gb:-?} GB"
        fi
    fi
}


phase_a_env() {
    # .env present / autofill required keys
    local env_path="$INSTALL_DIR/.env"
    if [ ! -f "$env_path" ]; then
        if [ "$MODE" = "check" ]; then
            record_fail ".env exists at $env_path" "missing" \
                "Run ./update.sh (apply mode) to install from bundled env.template, then edit AIPAM_API_TOKEN."
        else
            mkdir -p "$INSTALL_DIR"
            cp "$SCRIPT_DIR/env.template" "$env_path"
            record_warn ".env created from bundled env.template" "edit AIPAM_API_TOKEN before continuing" \
                "vi $env_path  # set AIPAM_API_TOKEN to a long random string"
        fi
    else
        record_pass ".env exists" "$env_path"
    fi

    # Token sanity
    local token
    token="$(env_get AIPAM_API_TOKEN "$env_path" 2>/dev/null || true)"
    if [ -z "$token" ]; then
        record_fail "AIPAM_API_TOKEN" "empty" \
            "vi $env_path  # AIPAM_API_TOKEN=<long-random-string>"
    elif [ "$token" = "changeme-generate-a-secure-token" ]; then
        record_warn "AIPAM_API_TOKEN" "still the default 'changeme-generate-a-secure-token'" \
            "vi $env_path  # set a long random token, then: docker compose up -d --force-recreate backend worker frontend"
    else
        record_pass "AIPAM_API_TOKEN" "set (length=${#token})"
    fi

    # Autofill missing LLM keys (only in apply mode)
    autofill_kv() {
        local key="$1" default="$2" current
        current="$(env_get "$key" "$env_path" 2>/dev/null || true)"
        if [ -z "$current" ]; then
            if [ "$MODE" = "check" ]; then
                record_warn "$key" "missing from .env (would auto-fill to '$default' in apply mode)" \
                    "echo '$key=$default' >> $env_path"
            else
                env_set "$key" "$default" "$env_path"
                record_warn "$key" "missing — auto-filled to '$default'" ""
            fi
        else
            record_pass "$key" "$current"
        fi
    }
    autofill_kv LLM_MODEL_NAME    "aipam-trafficllm-v10"
    autofill_kv AIPAM_OLLAMA_URL  "http://host.docker.internal:11434"
    autofill_kv LLM_ENDPOINT      "http://host.docker.internal:11434/v1/chat/completions"
}

phase_a_override() {
    # docker-compose.override.yml present and routes to host Ollama
    local ov="$INSTALL_DIR/docker-compose.override.yml"
    local bundled="$SCRIPT_DIR/docker-compose.override.yml"
    local needs_install=0 why=""
    if [ ! -f "$ov" ]; then
        needs_install=1; why="missing"
    elif ! grep -q "host.docker.internal:11434" "$ov" 2>/dev/null; then
        needs_install=1; why="present but does not route LLM traffic to host Ollama"
    elif ! grep -qE "^[[:space:]]+-[[:space:]]+container-llm" "$ov" 2>/dev/null; then
        needs_install=1; why="present but does not disable the in-compose ollama service"
    fi
    if [ "$needs_install" = "1" ]; then
        if [ "$MODE" = "check" ]; then
            record_fail "docker-compose.override.yml" "$why" \
                "cp $bundled $ov  # then re-run update"
        else
            mkdir -p "$INSTALL_DIR"
            cp "$bundled" "$ov"
            record_warn "docker-compose.override.yml" "$why — installed bundled version" ""
        fi
    else
        record_pass "docker-compose.override.yml" "present and disables container Ollama"
    fi
}

phase_a_host_ollama() {
    # Host Ollama service + reachability + model presence
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet ollama 2>/dev/null; then
            record_pass "Host ollama systemd service" "active"
        else
            record_warn "Host ollama systemd service" "not active" \
                "sudo systemctl start ollama && sudo systemctl enable ollama"
        fi
    fi
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS --max-time 4 http://localhost:11434/api/tags >/dev/null 2>&1; then
            record_pass "Host Ollama HTTP" "http://localhost:11434 reachable"
            local want
            want="$(env_get LLM_MODEL_NAME "$INSTALL_DIR/.env" 2>/dev/null || echo aipam-trafficllm-v10)"
            if curl -fsS --max-time 4 http://localhost:11434/api/tags 2>/dev/null \
                | grep -q "\"name\":\"${want}"; then
                record_pass "Ollama model present" "$want"
            else
                record_fail "Ollama model present" "$want not registered in host Ollama" \
                    "Import the model from the V10 full-install package: ollama create $want -f /path/to/aipam-v10-fullinstall-*/Modelfile.v10"
            fi
        else
            record_fail "Host Ollama HTTP" "http://localhost:11434 not reachable" \
                "sudo systemctl restart ollama  (or check OLLAMA_HOST=0.0.0.0 in /etc/systemd/system/ollama.service)"
        fi
    fi
}

phase_a_gpu() {
    if command -v nvidia-smi >/dev/null 2>&1; then
        local gpu_name vram_mb
        gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | sed 's/^ *//;s/ *$//')
        vram_mb=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
        if [ -n "$gpu_name" ] && [ -n "$vram_mb" ]; then
            if [ "$vram_mb" -lt 6144 ]; then
                record_warn "NVIDIA GPU" "$gpu_name ${vram_mb} MiB — too small for V10 (4.6 GB on disk, needs ~6 GB VRAM)" \
                    "Increase vGPU profile to L4-8B (8 GB) or larger; otherwise Ollama will run on CPU (functional but slower)."
            else
                record_pass "NVIDIA GPU" "$gpu_name ${vram_mb} MiB"
            fi
        else
            record_warn "NVIDIA GPU" "nvidia-smi available but no GPU info parsed" ""
        fi
    else
        record_warn "NVIDIA GPU" "nvidia-smi not found — Ollama will run on CPU" ""
    fi
}


# ════════════════════════════════════════════════════════════
# PHASE B — Post-install (or read-only against running stack)
# ════════════════════════════════════════════════════════════
phase_b() {
    echo ""
    echo -e "${BLUE}── Phase B: post-install ───────────────────────${NC}"

    # Wait for backend to come up before probing
    local backend_up=0
    for i in $(seq 1 30); do
        if curl -fsS -o /dev/null --max-time 2 http://localhost:8000/api/v1/docs 2>/dev/null; then
            backend_up=1; break
        fi
        sleep 1
    done

    # Container status
    local expected=(aipam-api aipam-worker aipam-frontend aipam-redis)
    for ctr in "${expected[@]}"; do
        local state
        state="$(docker inspect -f '{{.State.Status}}' "$ctr" 2>/dev/null || echo missing)"
        if [ "$state" = "running" ]; then
            local health
            health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$ctr" 2>/dev/null || echo n/a)"
            if [ "$health" = "unhealthy" ]; then
                record_warn "Container $ctr" "running but unhealthy" \
                    "docker logs --tail 50 $ctr"
            else
                record_pass "Container $ctr" "running (health=$health)"
            fi
        else
            record_fail "Container $ctr" "$state" \
                "docker compose -f $INSTALL_DIR/docker-compose.yml logs --tail 50 ${ctr#aipam-}"
        fi
    done

    # In-compose ollama should NOT be running (override puts it behind a profile)
    if docker inspect aipam-ollama >/dev/null 2>&1; then
        local oll_state
        oll_state="$(docker inspect -f '{{.State.Status}}' aipam-ollama 2>/dev/null)"
        if [ "$oll_state" = "running" ]; then
            record_warn "aipam-ollama container" "running (override should have disabled it)" \
                "cd $INSTALL_DIR && docker compose stop ollama && docker compose rm -f ollama"
        else
            record_pass "aipam-ollama container" "$oll_state (override active)"
        fi
    else
        record_pass "aipam-ollama container" "absent (override active)"
    fi

    # Backend /docs
    if [ "$backend_up" = "1" ]; then
        record_pass "Backend /api/v1/docs" "200"
    else
        record_fail "Backend /api/v1/docs" "did not come up within 30 s" \
            "docker logs --tail 100 aipam-api"
        return
    fi

    # Token + authenticated probes
    local token
    token="$(env_get AIPAM_API_TOKEN "$INSTALL_DIR/.env" 2>/dev/null || true)"
    if [ -z "$token" ]; then
        record_warn "Authenticated probes" "no AIPAM_API_TOKEN in .env — skipping" ""
        return
    fi

    # /health
    local health_body
    health_body="$(curl -fsS --max-time 4 -H "Authorization: Bearer $token" \
        http://localhost:8000/api/v1/health 2>/dev/null || true)"
    if [ -z "$health_body" ]; then
        record_fail "GET /api/v1/health" "no response (token wrong, or backend not ready)" \
            "Verify AIPAM_API_TOKEN in $INSTALL_DIR/.env matches what the backend loaded."
    else
        if echo "$health_body" | grep -q '"ollama_ok":true'; then
            record_pass "GET /api/v1/health" "ollama_ok=true"
        else
            record_warn "GET /api/v1/health" "ollama_ok=false (backend reached, LLM unreachable)" \
                "Confirm host Ollama is running and override is in effect — see Phase A output."
        fi
    fi

    # /settings (covers the "settings page won't save" symptom)
    local set_code
    set_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 \
        -H "Authorization: Bearer $token" \
        http://localhost:8000/api/v1/settings 2>/dev/null || echo 000)"
    case "$set_code" in
        200) record_pass "GET /api/v1/settings" "200" ;;
        401) record_fail "GET /api/v1/settings" "401 — backend rejected the token" \
                "Token mismatch. Set AIPAM_API_TOKEN in .env to match what the backend loaded, then: docker compose up -d --force-recreate backend worker frontend" ;;
        *)   record_warn "GET /api/v1/settings" "HTTP $set_code" "docker logs --tail 50 aipam-api" ;;
    esac

    # Frontend index + runtime-config.js
    local fe_code
    fe_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://localhost/ 2>/dev/null || echo 000)"
    if [ "$fe_code" = "200" ]; then
        record_pass "Frontend /" "200"
    else
        record_fail "Frontend /" "HTTP $fe_code" "docker logs --tail 50 aipam-frontend"
    fi

    local rc_body
    rc_body="$(curl -fsS --max-time 4 http://localhost/runtime-config.js 2>/dev/null || true)"
    if [ -z "$rc_body" ]; then
        record_fail "Frontend /runtime-config.js" "missing — frontend image predates runtime-token injection" \
            "Confirm this update package was built with the V20260521+ aipam-frontend image."
    elif echo "$rc_body" | grep -q "apiToken: \"$token\""; then
        record_pass "Frontend runtime-config.js token" "matches .env"
    else
        record_fail "Frontend runtime-config.js token" "does not match .env" \
            "docker compose up -d --force-recreate frontend  (entrypoint re-renders runtime-config.js from .env)"
    fi

    # Backend env reflects override
    local backend_url
    backend_url="$(docker exec aipam-api sh -c 'printf %s "$AIPAM_OLLAMA_URL"' 2>/dev/null || true)"
    if [ "$backend_url" = "http://host.docker.internal:11434" ]; then
        record_pass "backend AIPAM_OLLAMA_URL env" "$backend_url"
    elif [ -z "$backend_url" ]; then
        record_warn "backend AIPAM_OLLAMA_URL env" "could not read from aipam-api" ""
    else
        record_warn "backend AIPAM_OLLAMA_URL env" "$backend_url (override not in effect?)" \
            "cd $INSTALL_DIR && docker compose up -d --force-recreate backend worker"
    fi
}


# ════════════════════════════════════════════════════════════
# APPLY — Stop / backup / extract / load / up
# ════════════════════════════════════════════════════════════
apply_update() {
    echo ""
    echo -e "${BLUE}── Apply: stop / backup / extract / load / up ──${NC}"

    # 1. Stop current stack
    if [ -d "$INSTALL_DIR" ]; then
        ( cd "$INSTALL_DIR" && docker compose down 2>/dev/null || true )
        echo -e "    ${GREEN}ok${NC}   Stack stopped"
    else
        echo -e "    ${YELLOW}!!${NC}   $INSTALL_DIR not found — will create it"
    fi

    # 2. Backup + extract source
    if [ -d "$INSTALL_DIR" ]; then
        BACKUP="${INSTALL_DIR}.backup.$(date +%s)"
        mv "$INSTALL_DIR" "$BACKUP"
        echo -e "    ${GREEN}ok${NC}   Backed up old installation to $BACKUP"
    fi
    tar -xzf "$SCRIPT_DIR/repo.tar.gz" -C "$HOME"
    echo -e "    ${GREEN}ok${NC}   Source code updated at $INSTALL_DIR"

    # Restore server-specific .env from backup (the SQLite DB containing SO/Arkime
    # UI-configured integration settings is in a named Docker volume and is preserved
    # automatically across docker compose down/up cycles).
    if [ -n "$BACKUP" ] && [ -f "$BACKUP/.env" ]; then
        cp "$BACKUP/.env" "$INSTALL_DIR/.env"
        echo -e "    ${GREEN}ok${NC}   Restored .env from backup"
    fi
    # Restore docker-compose.override.yml from backup ONLY if it already routes
    # to host Ollama; otherwise Phase A will install the bundled override.
    if [ -n "$BACKUP" ] && [ -f "$BACKUP/docker-compose.override.yml" ] \
        && grep -q "host.docker.internal:11434" "$BACKUP/docker-compose.override.yml" 2>/dev/null; then
        cp "$BACKUP/docker-compose.override.yml" "$INSTALL_DIR/docker-compose.override.yml"
        echo -e "    ${GREEN}ok${NC}   Restored docker-compose.override.yml from backup"
    fi

    # 3. Load images
    docker load < "$SCRIPT_DIR/docker-images.tar.gz" >/dev/null
    echo -e "    ${GREEN}ok${NC}   Docker images loaded"

    # 4. Run Phase A again — this time auto-fixes apply (.env autofill, override install)
    echo ""
    phase_a
    phase_a_env
    phase_a_override
    phase_a_host_ollama
    phase_a_gpu

    # 5. Bring stack up
    echo ""
    echo -e "    ${YELLOW}..${NC}   docker compose up -d"
    ( cd "$INSTALL_DIR" && docker compose up -d 2>&1 | tail -5 )
    echo -e "    ${GREEN}ok${NC}   Stack started"
}

# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════
case "$MODE" in
    check)
        phase_a
        phase_a_env
        phase_a_override
        phase_a_host_ollama
        phase_a_gpu
        phase_b
        ;;

    skip-validate)
        apply_update >/dev/null 2>&1 || true
        # Re-run without silencing so failures surface
        echo -e "${YELLOW}Skipping validation as requested. Stack restarted.${NC}"
        ;;

    apply)
        # Phase A first; abort apply if any FAIL surfaces (unless user passed --skip-validate)
        phase_a
        phase_a_env
        phase_a_override
        phase_a_host_ollama
        phase_a_gpu
        if [ "$FAIL_COUNT" -gt 0 ]; then
            echo ""
            echo -e "${RED}Phase A reported ${FAIL_COUNT} blocking failure(s). Aborting apply.${NC}"
            echo -e "${YELLOW}Re-run with --skip-validate to force, or fix the issues above and retry.${NC}"
            print_actions
            exit 1
        fi
        apply_update
        phase_b
        ;;
esac

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Summary${NC}"
echo -e "${GREEN}============================================${NC}"
printf "  ${GREEN}PASS${NC}: %d   ${YELLOW}WARN${NC}: %d   ${RED}FAIL${NC}: %d\n" \
    "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
print_actions

if [ "$MODE" = "apply" ] && [ "$FAIL_COUNT" -eq 0 ]; then
    echo ""
    HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo -e "  Frontend:  ${GREEN}http://${HOST_IP:-<host>}/${NC}"
    echo -e "  API docs:  ${GREEN}http://${HOST_IP:-<host>}:8000/api/v1/docs${NC}"
    echo -e "  Model:     $(env_get LLM_MODEL_NAME "$INSTALL_DIR/.env" 2>/dev/null || echo aipam-trafficllm-v10) (host Ollama)"
    [ -n "$BACKUP" ] && echo -e "  Backup:    $BACKUP"
    echo ""
    echo -e "  ${BLUE}Operator helpers:${NC}"
    echo  "    cd $INSTALL_DIR && ./bin/switch-llm-backend.sh status      # show LLM routing"
    echo  "    cd $INSTALL_DIR && ./bin/switch-llm-backend.sh host        # route to host Ollama"
    echo  "    cd $INSTALL_DIR && ./bin/switch-llm-backend.sh container   # route to in-compose Ollama"
fi

# Exit code: 0 if no failures, 1 otherwise (so CI / scripts can detect issues)
[ "$FAIL_COUNT" -eq 0 ] || exit 1
exit 0
