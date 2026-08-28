# BlueScrub branch — review notes

> **Branch**: `feature/bluescrub-foundation`
> **Base**: `dc76692` (main)
> **Read this before reviewing the diff.**

## This branch is not a pure BlueScrub change

When the work started, the working tree already carried 1,562 lines of
unrelated uncommitted changes across 35 files. Several of those files are
exactly the integration seams BlueScrub had to touch. Staging by path —
`git add backend/app/api/jobs.py` — commits *the file*, not *the change*, so
the pre-existing edits to those files were swept into BlueScrub commits along
with the intended ones.

Path-level isolation is not change-level isolation. That distinction was missed
at the time and is recorded here rather than quietly left for a reviewer to
trip over.

### Files carrying both

| File | Added lines | Contains |
|---|---|---|
| `frontend/src/api.ts` | ~197 | BlueScrub types and client methods **+** unrelated API client work |
| `frontend/src/pages/NewAnalysisPage.tsx` | ~194 | The Source Code tab **+** unrelated page work |
| `backend/app/api/jobs.py` | ~131 | `_create_code_artifact_job` **+** the log-bundle byte-budget feature (`MAX_LOG_BYTES_PER_JOB`, `_enforce_log_budget`) |
| `backend/app/pipeline/orchestrator.py` | ~110 | `_run_code_artifact_pipeline` **+** unrelated pipeline work |
| `backend/requirements.txt` | 11 | Binary-analysis deps **+** unrelated pins |
| `backend/app/schemas/job.py`, `schemas/common.py`, `tests/test_telemetry_contracts.py` | ~10 | Mostly BlueScrub |

Roughly 200 lines of foreign work is entangled. Everything **not** touching a
BlueScrub seam was left alone and now lives on
`wip/local-changes-20260827`, committed from `main` as a safety net.

### Resolved 2026-08-27

The split was worse than untidy attribution: two of the entangled changes had
their **tests** on the WIP branch and their **implementations** here, so neither
branch passed alone. The WIP branch failed 8 tests with
`ImportError: cannot import name 'MAX_LOG_BYTES_PER_JOB'`.

Both implementations — the log-bundle byte budget in `api/jobs.py` and the
stage-failure resilience in `pipeline/orchestrator.py` — were relocated to
`wip/local-changes-20260827`, which then merged to `main`. This branch keeps its
copies; git resolves the duplication as an identical change, which is why
merging `main` in afterwards was conflict-free.

Both branches now pass independently: `main` at 985, this branch at 1141.

The remaining entanglement is cosmetic — unrelated additions to `api.ts`,
`NewAnalysisPage.tsx`, and `requirements.txt` sit inside BlueScrub commits. Those
have no functional consequence now that main carries the same changes.

### Why the rest was not unpicked

The work is committed and safe, which is strictly better than the uncommitted
state it was in. Extracting hunks across eleven commits would mean rewriting
the branch, risks breaking a green suite, and buys only a tidier review. If a
pure BlueScrub branch is genuinely needed, the cheaper route is to redo the
seam edits — they are small and well specified in the plan's §5.4 allowlist —
on a clean base.

## Test results are now measured on a clean tree

Earlier runs in this branch's history reported ~1,140 passing. Those were
measured **with the uncommitted changes applied**, which is why the count is
higher than what the branch alone produces. Against a clean tree the branch
gives **587 passed, 30 skipped, 0 failed**.

Two defects were found by making that measurement and are fixed in `7edc0d6`:

1. `persistence.py` set `Finding.evidence_status`, a column that existed only
   in the uncommitted work. BlueScrub is additive and must not require another
   change to land first, so the value now always goes to `evidence_json` and
   reaches the column only where it exists.
2. A no-regression test pinned the exact column set of `findings`, baselined
   against the working tree. An equality assertion on a shared, actively
   developed table asserts "nobody else may work on this", not "BlueScrub is
   additive". Replaced with a subset check.

**Lesson worth keeping:** run the suite against a clean tree before reporting
a result. A green run in a dirty tree measures the tree, not the branch.

## Still open

- The differential baseline (`upstream_baseline.json`) is captured from
  `NhanBC/BlueScrub @ 9452a51`. Regenerating it requires that repo; the test
  asserts the pin matches `VENDOR.md` so the two cannot drift silently.
- The golden PCAP behavioural gate skips without Zeek and Suricata. It must be
  run on the deployment host before each merge.
- Binary analysis reports `unavailable` here because `pefile`, `pyelftools`,
  `capstone`, and `lief` are declared but not installed.
