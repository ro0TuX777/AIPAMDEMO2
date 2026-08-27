# Vendored BlueScrub engine

> **Upstream**: `NhanBC/BlueScrub` (private)
> **Pinned commit**: `9452a51673f5fb946b72faf1f51b1818b145fae7`
> **Verified**: 2026-08-09 · **Sync**: `scripts/vendor_bluescrub.sh`
> **State**: allowlist verified, copy not yet performed (Sprint 2)

## Why a copy rather than a submodule

The upstream is private and the build host is air-gapped, so a subtree or
submodule pull is not reliably available where it matters. A copy makes each
re-sync a reviewable diff instead of a merge.

## Allowlist

`scanners/`, `enrichment/`, and seventeen root modules — 54 files, ~12,000 LOC.
The script fails loudly if any allowlisted path is missing upstream.

**Excluded**: `app_minimal.py`, `api/`, `job_manager.py`, `config.py`,
`templates/`, `static/`, `bluescrub_scan_service.py`, `services/trend_service.py`,
`docker-compose*.yml`, `bluescrub_migration*/`. AIPAM supplies web, jobs,
config, and persistence.

## Verified properties of the pinned commit

Measured, not assumed — `scripts/vendor_bluescrub.sh` re-checks these on every
run and refuses to write if they stop holding.

1. **The analyzer corpus imports nothing excluded.** Zero references to Flask,
   `config`, `job_manager`, `api`, or `app_minimal`. Flask is confined entirely
   to `api/`, which is excluded, and the only two modules importing `config` —
   `bluescrub_scan_service.py` and `services/trend_service.py` — are excluded
   for other reasons.

   This makes the plan's "strip Flask coupling" step unnecessary. The corpus is
   already decoupled; the port is a copy plus an import rewrite.

2. **Third-party dependencies**: `pefile`, `pyelftools`, `capstone`, `lief`,
   `yara-python`. AIPAM already carries `yara-python` via `binalysis`. The rest
   are binary-analysis libraries, wheel-available and air-gap installable.

## Known gap upstream — `advanced_binary_analyzer`

`scanners/binary/capa.py` and `scanners/binary/__init__.py` import
`advanced_binary_analyzer`, which **does not exist in the repository** and is
not gitignored. Every import site is guarded by `try/except ImportError` and
sets `ADVANCED_AVAILABLE = False`, so the code degrades silently rather than
failing.

The consequence is that `CapaMixin._run_advanced_analysis` — the Radare2 and
Ghidra integration — has never executed in any deployment built from this
repository. It is dead code upstream.

That capability is precisely what the RE-Feasibility decompilation signal
needs, which confirms the pillar is genuinely net-new work rather than a port.
Sprint 9 builds it against the isolation contract instead of inheriting it.

## Local modifications

None yet. Every modification must be recorded here with its reason. Prefer a
wrapper one level up over an edit inside `vendored/`.
