#!/bin/bash
# switch-llm-backend.sh — flip AIPAM between host-Ollama and container-Ollama
#
# Usage (run from the AIPAM install directory, normally $HOME/AIPAM):
#   ./bin/switch-llm-backend.sh host        Route backend/worker to Ollama on the VM host
#   ./bin/switch-llm-backend.sh container   Route to the in-compose aipam-ollama container
#   ./bin/switch-llm-backend.sh status      Show current routing + reachability of both
#
# Idempotent: edits .env, installs/removes docker-compose.override.yml, and
# does a targeted `docker compose up -d --force-recreate backend worker`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$(dirname "$SCRIPT_DIR")"
cd "$INSTALL_DIR"

ENV_FILE="$INSTALL_DIR/.env"
OVERRIDE="$INSTALL_DIR/docker-compose.override.yml"
BUNDLED_OVERRIDE="$INSTALL_DIR/deploy/docker-compose.override.host-ollama.yml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

env_get() {
    [ -f "$ENV_FILE" ] || return 1
    local line; line="$(grep -E "^${1}=" "$ENV_FILE" | tail -1)"
    [ -z "$line" ] && return 1
    local val="${line#*=}"; val="${val%$'\r'}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    printf '%s' "$val"
}
env_set() {
    local key="$1" val="$2"
    if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
        awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{$0=k"="v} {print}' \
            "$ENV_FILE" > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "$ENV_FILE"
    else
        printf '\n%s=%s\n' "$key" "$val" >> "$ENV_FILE"
    fi
}
require_env() {
    [ -f "$ENV_FILE" ] || { echo -e "${RED}error:${NC} $ENV_FILE not found — run update.sh first." >&2; exit 1; }
}

cmd_status() {
    require_env
    echo -e "${GREEN}── AIPAM LLM backend status ──${NC}"
    printf "  %-22s %s\n" "AIPAM_OLLAMA_URL:" "$(env_get AIPAM_OLLAMA_URL || echo '<unset>')"
    printf "  %-22s %s\n" "LLM_ENDPOINT:"     "$(env_get LLM_ENDPOINT     || echo '<unset>')"
    printf "  %-22s %s\n" "LLM_MODEL_NAME:"   "$(env_get LLM_MODEL_NAME   || echo '<unset>')"
    if [ -f "$OVERRIDE" ]; then
        if grep -q "host.docker.internal:11434" "$OVERRIDE" \
           && grep -qE "^[[:space:]]+-[[:space:]]+container-llm" "$OVERRIDE"; then
            echo -e "  override.yml:          ${GREEN}host-Ollama mode${NC} (in-compose ollama disabled)"
        else
            echo -e "  override.yml:          ${YELLOW}present but not a canonical mode${NC}"
        fi
    else
        echo -e "  override.yml:          ${YELLOW}absent → container-Ollama mode (compose defaults)${NC}"
    fi
    command -v curl >/dev/null 2>&1 && {
        if curl -fsS --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
            echo -e "  host Ollama (:11434):  ${GREEN}reachable${NC}"
        else
            echo -e "  host Ollama (:11434):  ${RED}not reachable${NC}"
        fi
    }
    if docker inspect aipam-ollama >/dev/null 2>&1; then
        echo "  container Ollama:      $(docker inspect -f '{{.State.Status}}' aipam-ollama)"
    else
        echo "  container Ollama:      absent"
    fi
}

cmd_host() {
    require_env
    echo -e "${YELLOW}── Switching to host-Ollama mode ──${NC}"
    env_set AIPAM_OLLAMA_URL "http://host.docker.internal:11434"
    env_set LLM_ENDPOINT     "http://host.docker.internal:11434/v1/chat/completions"
    echo "  ✓ .env updated"
    if [ -f "$OVERRIDE" ] && ! grep -q "host.docker.internal:11434" "$OVERRIDE"; then
        cp "$OVERRIDE" "${OVERRIDE}.backup.$(date +%s)"
        echo "  ✓ previous override.yml backed up"
    fi
    if [ -f "$BUNDLED_OVERRIDE" ]; then
        cp "$BUNDLED_OVERRIDE" "$OVERRIDE"
    else
        cat > "$OVERRIDE" <<'YAML'
services:
  ollama:
    profiles: [container-llm]
  backend:
    environment:
      AIPAM_OLLAMA_URL: ${AIPAM_OLLAMA_URL:-http://host.docker.internal:11434}
      LLM_ENDPOINT:     ${LLM_ENDPOINT:-http://host.docker.internal:11434/v1/chat/completions}
  worker:
    environment:
      AIPAM_OLLAMA_URL: ${AIPAM_OLLAMA_URL:-http://host.docker.internal:11434}
      LLM_ENDPOINT:     ${LLM_ENDPOINT:-http://host.docker.internal:11434/v1/chat/completions}
YAML
    fi
    echo "  ✓ docker-compose.override.yml installed (host-Ollama variant)"
    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
        local want; want="$(env_get LLM_MODEL_NAME || echo aipam-trafficllm-v10)"
        if ! curl -fsS http://localhost:11434/api/tags 2>/dev/null | grep -q "\"name\":\"${want}"; then
            echo -e "  ${YELLOW}WARN${NC} host Ollama up but model '$want' not registered. Re-run the V10 full-install Modelfile step."
        fi
    else
        echo -e "  ${YELLOW}WARN${NC} host Ollama not reachable. sudo systemctl start ollama && sudo systemctl enable ollama"
    fi
    docker compose stop ollama 2>/dev/null || true
    docker compose rm -f ollama 2>/dev/null || true
    docker compose up -d --force-recreate backend worker frontend
    echo -e "${GREEN}✓ Switched to host-Ollama mode${NC}"
}

cmd_container() {
    require_env
    echo -e "${YELLOW}── Switching to container-Ollama mode ──${NC}"
    env_set AIPAM_OLLAMA_URL "http://ollama:11434"
    env_set LLM_ENDPOINT     "http://ollama:11434/v1/chat/completions"
    echo "  ✓ .env updated"
    if [ -f "$OVERRIDE" ] && grep -q "host.docker.internal:11434" "$OVERRIDE"; then
        mv "$OVERRIDE" "${OVERRIDE}.host-ollama.disabled"
        echo "  ✓ host-Ollama override moved to docker-compose.override.yml.host-ollama.disabled"
    elif [ -f "$OVERRIDE" ]; then
        echo -e "  ${YELLOW}WARN${NC} $OVERRIDE exists but is not the host-Ollama variant — left in place."
    fi
    docker compose up -d ollama
    for i in $(seq 1 30); do
        docker exec aipam-ollama ollama list >/dev/null 2>&1 && break
        sleep 1
    done
    local want; want="$(env_get LLM_MODEL_NAME || echo aipam-trafficllm-v10)"
    if ! docker exec aipam-ollama ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$want"; then
        echo -e "  ${YELLOW}WARN${NC} container Ollama is up but model '$want' is not present in it."
        echo  "        Either (a) ollama create $want -f Modelfile.v10  inside the container, or"
        echo  "               (b) sudo cp -a /usr/share/ollama/.ollama/models/* \\"
        echo  "                       /var/lib/docker/volumes/aipam_ollama-models/_data/  &&  docker compose restart ollama"
    fi
    docker compose up -d --force-recreate backend worker frontend
    echo -e "${GREEN}✓ Switched to container-Ollama mode${NC}"
}

case "${1:-}" in
    host)              cmd_host ;;
    container)         cmd_container ;;
    status)            cmd_status ;;
    -h|--help|help|"") usage 0 ;;
    *) echo "unknown subcommand: $1" >&2; usage 1 ;;
esac
