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

## Sprint 5 — Attribution, closed

All seven items in the plan's Sprint 5 line have landed. Three of them were
already partly present and turned out to be wrong rather than missing, which is
recorded here because the failures rhyme.

| Item | State |
|---|---|
| Dirty-word over source | Already landed (`a5950f9`) |
| Dirty-word over **binaries** | New. See below — the binary path did not work |
| FLOSS recovery | Recovery module, tiering, parser and invocation all landed and tested; the emulation-class *invocation* is Sprint 6's — see below |
| Pre-built packs | Landed, **re-calibrated** — see below |
| Category severity ladder | Extended with two tiers below `medium` |
| Regex safety | Landed (`fd5dbcb`): literal-only matcher, three-character floor |
| Gitleaks | New adapter, parser tested against recorded output |
| TruffleHog (verification disabled) | New adapter; disable flag asserted by test |
| gitmeta | Landed (`d2a85e5`) |
| Hardcoded build/PDB paths | New `build_paths` scanner, binaries only |
| Code-similarity fingerprinting | Detector was wired in Sprint 2; four of its six categories were `unmapped` and are now reviewed and mapped |
| Secret masking, keyed fingerprints | Landed (`75e57ab`) |

### Three defects the acceptance criteria found

**1. A codename in a binary could not be reported at all.** The vendored
matcher classifies a file as binary by *extension*, so a stripped ELF named
`loader` was read as text and matched at a line number and column that mean
nothing in a file with no lines. When it did take the binary branch, the adapter
wrote the byte offset into a `source` location — which the raw-finding contract
rejects, because a source location must carry a line number. Nothing validates
raw findings at runtime, so it reached the database anyway, with
`source_facet: "source"` on a binary hit and every offset in a file collapsed
into one canonical group. The offset was being computed and then thrown away.

**2. Any tree containing a `TODO` comment scored F.** The shipped "Common Leaks
(OPSEC)" pack is a mixed bag — personal mail domains next to `TODO`, `DEBUG`,
`admin`, `password` and `/home/` — and the whole pack carried one category,
`identity`, which is the disqualifying tier. So the builtin packs alone, with
no operator input, disqualified essentially every artifact. This is the same
failure the critical ceiling was written for, arriving through the *input* side
rather than the detector side, and the three-character floor does not catch it:
`TODO` is four characters. Fixed with per-term categories and two new tiers
below `medium` (`toolchain`, `hygiene`). Four terms can now disqualify, all of
them personal mail domains.

**3. Two documented rules contradicted each other.** SUPPLY_CHAIN §5 requires
the adapter to pass each tool's verification-disable flag, and its acceptance
list forbade any invocation containing a verification flag — TruffleHog's
disable flag is `--no-verification`. Resolved in favour of the sense of the
flag, with each tool's flag declared in the manifest so the check compares
against a value rather than guessing at a pattern.

### Scope decisions worth knowing

- **`build_paths` reads binaries only.** `MetadataLeakageScanner.embedded_paths`
  already covers `/home/<user>/` in source, and the false-positive measurement
  is explicit that such a path in source *is* the finding. A second regex
  detector over the same text is noise. The gap was the compiled side.
- **A toolchain path is not an operator path.** Every Rust binary contains
  `/rustc/<hash>/`; reporting those at Attribution severity buries the one path
  that does name somebody. CI service accounts (`runner`, `jenkins`) sit on the
  toolchain side of that line for the same reason.
- **Gitleaks and TruffleHog are optional.** They disagree constantly and the
  vendored secrets analyzer already covers the pillar, so neither is required
  and installing either must not move a score — the OSV/Grype argument.
- **Their artefacts go to `quarantine/`.** Their matches *are* the credential,
  and the normalised results file is written before central redaction runs. It
  would otherwise be the one place plaintext lands on disk under the 30-day job
  clock instead of the 72-hour quarantine one. The evidence fields are dropped
  from it entirely, so in the happy path no plaintext reaches disk at all.
- **FLOSS is not wired to a scanner, deliberately.** It is `emulation` class:
  8 GiB, 900 seconds, `deep` only. The two scanners that consume the recovery
  module — dirty-word and build-paths — are `parse_only` and run in profiles
  where `deep` is not selected. Calling FLOSS from inside either one would
  promote a `parse_only` scanner to `emulation` in fact while leaving it
  `parse_only` in the registry, and would run a 900-second tool inside a
  120-second process boundary that would kill it. The recovery module takes
  FLOSS as an injected runner and its parser, tiering and argv are tested; the
  invocation lands with the FLOSS scanner in Sprint 6, where the plan puts it.
  The cost is reported, not hidden: on `deep`, `recovery_state()` returns
  `strings_static_only` and Attribution coverage degrades.

## Post-Sprint-5 pass — measured against a real corpus

Sprint 5 shipped, then the pipeline was run against AIPAM's own backend (414
files) because that is how every calibration defect in this branch has been
found. Four things came out of it.

**The unmapped backlog was 287 findings across 20 rules, and is now zero.**
The counter had been doing its job and nobody had emptied it. Nineteen were
genuinely unreviewed and are now mapped — the exploit-construction categories
(`bypass_techniques`, `heap_sprays`, `stack_pivots`, `predictable_patterns`)
to **Detectability**, on the grounds that a stack pivot in your own exploit is
not a bug in your tool, it is a pattern a defender writes a rule for. One was a
keying gap rather than a review gap: the two normalisation paths disagree about
what they hand `resolve_family` — specialised analyzers pass a bare category,
pattern analyzers pass the whole finding label — so
`information_disclosure_in_logs` arrived as
`information_disclosure_in_logs_f_string_formatting` and missed a key that was
right there. 125 findings were unmapped for that reason alone. Resolved with a
separator-anchored longest-prefix fallback, which resolves a rule to the family
of its own category rather than guessing.

**49% of all findings came from terms nobody declared.** 2853 of 5866 were the
builtin packs' developer-hygiene tier. The scanner's premise is that the
operator declared what matters; upstream's packs declared `TODO`. The terms are
real and weak, so they are neither dropped nor forced on: they now seed into
their own `Developer Hygiene` list, switched off, one toggle from active. This
needed an `enabled` column, which is separate from `builtin` on purpose —
`builtin` means "these terms are not yours to edit", and whether a pack is
hunted at all is a different question. Findings on the corpus fell from 5866 to
2982 and the info tier from 2853 to 3.

**A claim made mid-session was wrong and is corrected here.** The first reading
of the measurement was that the DACV score "does not discriminate", because
Attribution returned 100 on both a 29-file and a 414-file corpus. Measuring the
low end disproved it: a clean library scores 0/A and a single leaky file in
four scores 58/C. The model discriminates over roughly `raw` 0–80 and saturates
above, which is a saturating curve working as specified — and that range
matches the intended subject, an implant of five to fifty files, not a 414-file
defensive application. **No scoring change was made.** The measurement is
recorded in [SCORING_SPEC §1.2](BLUESCRUB_SCORING_SPEC.md) as input for the
Sprint 9 calibration, including the finding that `raw` scales with corpus size
while density is nearly invariant (1.04× for Detectability across a 14× size
change) — which is how that calibration should be fitted.

**External adapter argv is still untested, and now there is something that
tests it.** `make bluescrub-preflight` runs every adapter for real against a
fixture that includes a binary, a git repository and a staged wordlist, and
reports what each one came back with. The case it exists to catch is the quiet
one: a tool that is installed, an adapter that still reports `unavailable` or
`unparseable`, and a pillar that degrades — which means the argv does not match
the version on that host. Run it on the deployment host alongside the golden
PCAP gate.

## Still open

- The differential baseline (`upstream_baseline.json`) is captured from
  `NhanBC/BlueScrub @ 9452a51`. Regenerating it requires that repo; the test
  asserts the pin matches `VENDOR.md` so the two cannot drift silently.
- The golden PCAP behavioural gate skips without Zeek and Suricata. It must be
  run on the deployment host before each merge.
- Binary analysis reports `unavailable` here because `pefile`, `pyelftools`,
  `capstone`, and `lief` are declared but not installed.
- The architecture gate is unsigned five sprints after it was meant to close;
  see the notice at the top of [BLUESCRUB_GATE.md](BLUESCRUB_GATE.md). Both
  blocking items are unanswered, and Semgrep rule licensing has been sidestepped
  rather than resolved — it becomes live again the moment anyone points
  `AIPAM_BLUESCRUB_SEMGREP_CONFIG` at the registry.
- Gitleaks, TruffleHog and FLOSS are not installed here either. Their argv is a
  documented decision a deployment must confirm; their parsers — which is where
  the Semgrep adapter's three defects actually lived — are pure functions tested
  against recorded output. `binstrings` and `build_paths` need no binary and are
  tested against artifacts the suite compiles with `gcc`.
