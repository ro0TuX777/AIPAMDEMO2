#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Arkime MVP — End-to-End Validation Script
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   1. Start base AIPAM:  docker compose up -d
#   2. Run disabled-mode checks:  bash tests/validate_arkime_e2e.sh --disabled
#   3. Start Arkime profile:  docker compose --profile arkime up -d
#   4. Run enabled-mode checks:  bash tests/validate_arkime_e2e.sh --enabled
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

API_BASE="${AIPAM_API_BASE:-http://localhost:8000/api/v1}"
ARKIME_URL="${ARKIME_URL:-http://localhost:8005}"
API_TOKEN="${AIPAM_API_TOKEN:-test-token-v2}"
AUTH_HEADER="Authorization: Bearer $API_TOKEN"
PASS=0
FAIL=0

green()  { printf "\033[32m✓ %s\033[0m\n" "$1"; PASS=$((PASS+1)); }
red()    { printf "\033[31m✗ %s\033[0m\n" "$1"; FAIL=$((FAIL+1)); }
header() { printf "\n\033[1;36m── %s ──\033[0m\n" "$1"; }

check_http() {
  local desc="$1" url="$2" expect_code="$3"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH_HEADER" "$url" 2>/dev/null) || code="000"
  if [ "$code" = "$expect_code" ]; then
    green "$desc (HTTP $code)"
  else
    red "$desc (expected HTTP $expect_code, got $code)"
  fi
}

check_http_noauth() {
  local desc="$1" url="$2" expect_code="$3"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 "$url" 2>/dev/null) || code="000"
  if [ "$code" = "$expect_code" ]; then
    green "$desc (HTTP $code)"
  else
    red "$desc (expected HTTP $expect_code, got $code)"
  fi
}

check_json_field() {
  local desc="$1" url="$2" field="$3" expected="$4"
  local body val
  body=$(curl -s -H "$AUTH_HEADER" "$url" 2>/dev/null) || body="{}"
  val=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$field',''))" 2>/dev/null || echo "")
  if [ "$val" = "$expected" ]; then
    green "$desc ($field=$val)"
  else
    red "$desc (expected $field=$expected, got '$val')"
  fi
}

# ─── Disabled-mode validation ───────────────────────────────────────────────
validate_disabled() {
  header "Validation: AIPAM without Arkime profile"

  echo "Checking AIPAM API is reachable..."
  check_http "AIPAM health endpoint" "$API_BASE/health" "200"

  echo "Checking Arkime endpoints return disabled gracefully..."
  # Use a fake job ID — should get disabled response, not 404
  local fake_job="00000000-0000-0000-0000-000000000000"
  check_json_field "Status endpoint (disabled)" \
    "$API_BASE/jobs/$fake_job/arkime/status" "enabled" "False"

  echo ""
  echo "Checking Arkime viewer is NOT reachable..."
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 "$ARKIME_URL" 2>/dev/null) || code="000"
  if [ "$code" = "000" ]; then
    green "Arkime viewer not running (expected when profile disabled)"
  else
    red "Arkime viewer responded with HTTP $code (should not be running)"
  fi
}

# ─── Enabled-mode validation ────────────────────────────────────────────────
validate_enabled() {
  header "Validation: Arkime profile active"

  echo "Checking AIPAM API is reachable..."
  check_http "AIPAM health endpoint" "$API_BASE/health" "200"

  echo "Checking Arkime viewer is reachable..."
  check_http_noauth "Arkime viewer" "$ARKIME_URL" "200"

  echo "Checking OpenSearch is healthy..."
  check_http_noauth "OpenSearch cluster health" "http://localhost:9200/_cluster/health" "200"

  echo "Checking Docker containers..."
  for svc in aipam-opensearch aipam-arkime-viewer aipam-arkime-importer; do
    local state
    state=$(docker inspect -f '{{.State.Status}}' "$svc" 2>/dev/null || echo "not_found")
    if [ "$state" = "running" ]; then
      green "Container $svc is running"
    else
      red "Container $svc state: $state"
    fi
  done

  echo ""
  echo "Checking Arkime API endpoints respond with enabled=true..."
  local fake_job="00000000-0000-0000-0000-000000000000"
  check_json_field "Status endpoint (enabled)" \
    "$API_BASE/jobs/$fake_job/arkime/status" "enabled" "True"
}

# ─── Main ───────────────────────────────────────────────────────────────────
case "${1:-}" in
  --disabled)
    validate_disabled
    ;;
  --enabled)
    validate_enabled
    ;;
  *)
    echo "Usage: $0 --disabled | --enabled"
    echo ""
    echo "  --disabled   Run checks with Arkime profile OFF (base AIPAM only)"
    echo "  --enabled    Run checks with Arkime profile ON"
    exit 1
    ;;
esac

header "Results"
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] && echo "All checks passed!" || exit 1

