#!/usr/bin/env bash
# Vendor the BlueScrub analysis engine into backend/app/bluescrub/vendored/.
#
# A copy, not a submodule: the upstream is private and the build host is
# air-gapped, so a subtree pull is not reliably available where it matters.
# Re-syncing is therefore a reviewable diff.
#
# The allowlist below was verified against commit 9452a51 — the copied corpus
# imports nothing from Flask, config, job_manager, or api. The script re-checks
# that on every run and refuses to write if it stops being true.
#
#   Usage: scripts/vendor_bluescrub.sh [--check] [<commit>]
set -euo pipefail

REPO_URL="${BLUESCRUB_REPO:-https://github.com/NhanBC/BlueScrub.git}"
PIN="${2:-9452a51673f5fb946b72faf1f51b1818b145fae7}"
DEST="backend/app/bluescrub/vendored"
CHECK_ONLY=false
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=true

ALLOW_DIRS=(scanners enrichment)
ALLOW_FILES=(
  binary_analyzer.py dirty_word_scanner.py dependency_scanner.py
  bluescrub_result_schema.py yara_rule_generator.py simple_scanner.py
  defensive_security_scanner.py anti_analysis_validator.py
  code_similarity_detector.py exploit_reliability_analyzer.py
  forensic_artifact_detector.py metadata_leakage_scanner.py
  network_traffic_analyzer.py payload_obfuscation_analyzer.py
  privilege_escalation_analyzer.py shellcode_security_scanner.py
  exceptions.py
)
# Excluded on purpose: AIPAM supplies web, jobs, config, and persistence.
FORBIDDEN_IMPORTS='^\s*(from|import)\s+(flask|werkzeug|config|job_manager|app_minimal|api)\b'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> cloning $REPO_URL @ ${PIN:0:12}"
git clone --quiet "$REPO_URL" "$tmp/src"
git -C "$tmp/src" checkout --quiet "$PIN"

echo "==> staging allowlist"
mkdir -p "$tmp/out"
for d in "${ALLOW_DIRS[@]}"; do
  [[ -d "$tmp/src/$d" ]] || { echo "MISSING dir: $d" >&2; exit 1; }
  cp -r "$tmp/src/$d" "$tmp/out/"
done
for f in "${ALLOW_FILES[@]}"; do
  [[ -f "$tmp/src/$f" ]] || { echo "MISSING file: $f" >&2; exit 1; }
  cp "$tmp/src/$f" "$tmp/out/"
done
find "$tmp/out" -name '__pycache__' -type d -prune -exec rm -rf {} +

echo "==> checking for excluded imports"
if grep -rEn "$FORBIDDEN_IMPORTS" --include='*.py' "$tmp/out" ; then
  echo "REFUSING: the copied corpus imports an excluded module." >&2
  echo "Either the allowlist is wrong or upstream gained a coupling." >&2
  exit 1
fi
echo "    clean"

echo "==> rewriting imports to the vendored package path"
python3 - "$tmp/out" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
locals_ = {p.stem for p in root.glob("*.py")} | {p.name for p in root.iterdir() if p.is_dir()}
pkg = "backend.app.bluescrub.vendored"
pat = re.compile(r"^(\s*)(from|import)\s+(" + "|".join(sorted(map(re.escape, locals_))) + r")\b")
for path in root.rglob("*.py"):
    out = []
    for line in path.read_text().splitlines(keepends=True):
        m = pat.match(line)
        out.append(pat.sub(rf"\g<1>\g<2> {pkg}.\g<3>", line) if m else line)
    path.write_text("".join(out))
print(f"    rewrote imports across {len(list(root.rglob('*.py')))} files")
PY

if $CHECK_ONLY; then
  echo "==> --check: not writing. Diff against current vendored tree:"
  diff -rq "$DEST" "$tmp/out" 2>&1 | head -40 || true
  exit 0
fi

echo "==> writing $DEST"
rm -rf "$DEST"
mkdir -p "$DEST"
cp -r "$tmp/out/." "$DEST/"
cat > "$DEST/__init__.py" <<PYEOF
"""Vendored from NhanBC/BlueScrub @ ${PIN}.

Do not edit in place. AIPAM-specific behaviour belongs in wrappers and adapters
one level up, so that re-syncing upstream stays a reviewable diff rather than a
merge. See ../VENDOR.md.
"""
PYEOF

echo "==> done. $(find "$DEST" -name '*.py' | wc -l) files, $(find "$DEST" -name '*.py' -exec cat {} + | wc -l) lines"
echo "    Record the pin in backend/app/bluescrub/VENDOR.md before committing."
