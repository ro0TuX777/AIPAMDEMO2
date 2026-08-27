# Vendored BlueScrub engine

> **Upstream**: `NhanBC/BlueScrub` (private)
> **Pinned commit**: `9452a51673f5fb946b72faf1f51b1818b145fae7`
> **Verified**: 2026-08-09 · **Sync**: `scripts/vendor_bluescrub.sh`
> **State**: vendored — 55 files, 12,038 lines

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
   `yara-python`. AIPAM already carried `yara-python` via `binalysis`; the other
   four are now declared in `backend/requirements.txt`.

   They matter more than a dependency list usually does. Upstream guards every
   one behind an `*_AVAILABLE` flag, so a missing package makes binary analysis
   return no findings rather than fail — indistinguishable from a clean binary.
   Declaring them makes that degradation a deployment choice instead of an
   accident, and the health endpoint (G10) reports it either way.

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

## Known limitation — file-extension coverage

`BaseAnalyzer.EXTENSIONS` restricts every pattern analyzer to a fixed source
list (`.py .js .ts .rb .go .c .cpp .h .hpp .sh .bash`). Attribution material in
a README, `.txt`, `.md`, `.json`, or `.yaml` file is therefore never seen —
which matters, because build notes and deployment docs are exactly where
operator names, internal hostnames, and project codenames tend to survive.

Not fixed by widening the list here: that would change vendored behaviour and
break raw parity with upstream, and the differential test would be measuring
our edit rather than upstream fidelity. The right home is the dirty-word
scanner in Sprint 5, which is specified to scan arbitrary files and recovered
binary strings rather than a source allowlist.

Until then, the Attribution pillar under-reports on non-source files. The
sample fixture places its planted attribution material in a `.py` comment so
the differential test measures the engine rather than this gap.

## Local modifications

**None.** The only transformation applied is the mechanical import rewrite in
`scripts/vendor_bluescrub.sh`, which prefixes local imports with the vendored
package path. Nothing else in `vendored/` differs from upstream.

AIPAM-specific behaviour lives one level up:

| Concern | Where |
|---|---|
| Running analyzers behind a process boundary | `isolation/analyzer_main.py` |
| Normalising analyzer output onto the raw contract | `scanners/vendored_analyzers.py` |
| Family and pillar assignment | `rulemap.py` |
| Deduplication and scoring | `canonicalize.py`, `scoring.py` |

Keep it that way: a modification inside `vendored/` turns the next re-sync from
a diff into a merge.
