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

## Sprint 6 — started: FLOSS

The first `emulation`-class scanner, and the one that closes Sprint 5's last
gap.

**What it uniquely reports.** A string recovered from a stack, a tight loop or
a decoding routine is a string somebody deliberately kept out of the data
section. Recovering it proves the obfuscation was attempted and did not work —
a Detectability finding no pattern matcher can produce, because the evidence is
that the code was run. It is the only detector in this pipeline classed
`semantic_dataflow`.

**What it does not report, and why.** An early draft flagged high plaintext
string yield as "trivially signaturable". Measured across six unrelated system
binaries — git, ls, bash, gcc, libc, python — yield sat between 5.9 and 9.1
strings per KiB with no separation whatsoever. A rule that fires on every
unpacked binary ever built is the "C2 matched 67 times" failure in a new hat,
so it was dropped before it shipped. Low yield is the interesting direction and
belongs to the RE-Feasibility packing signal.

**It closes the `strings_static_only` coverage loss.** Dirty-word and
build-path scanning over binaries are both `parse_only`, so both saw only what
was already in the file; a codename assembled at runtime was invisible and a
deep scan admitted it by degrading Attribution. FLOSS now writes what it
recovered to a job-scoped cache keyed by artifact digest, and those scanners
merge it into their own static pass. The test that matters puts a declared term
*only* in the cache and asserts the dirty-word scanner finds it.

**One emulation, shared.** Written up as [ISOLATION_CONTRACT
§3.2](BLUESCRUB_ISOLATION_CONTRACT.md): the artifact is emulated once by the
scanner that is declared emulation class, not once per consumer. Three passes
would triple the cost and triple the exposure, and a `parse_only` scanner that
invoked FLOSS itself would be emulation class in fact and `parse_only` in the
registry. `ScannerSpec.order` makes the producer run first — `floss` sorts
after both its consumers alphabetically, so the dependency had to be declared
rather than left to a name.

## Running it on its intended subject, for the first time

Every measurement that shaped this pipeline — the severity ladder, the category
tiers, the false-positive filters, the `K_P` constants — was taken against
**source trees**. BlueScrub grades offensive tooling, which is compiled. The
existing `sample_repo_spec.json` is source only, so nothing had ever exercised
the pipeline against the thing it exists for.

`implant_spec.json` fixes that: a small, inert C artifact compiled stripped,
carrying a codename, an operator build path, an internal hostname, a hardcoded
C2 address, a mutex name, a user-agent and a ticket reference. The result was
worth the hour.

**What worked.** The declared codename surfaced twice — in the build path and
inside the mutex name — at critical, disqualifying the artifact. The operator
build path, the org term and the internal hostname came back at high, the
compiler version string at medium. Attribution assessed at full coverage. Every
binary finding carried a real artifact digest and a seekable offset.

**What did not, and why it matters.** The artifact has `10.20.30.40:8443`
compiled into it and **nothing reported it**. Co-Optability scored zero with
zero findings — on an implant with a hardcoded C2, which is the single finding
that pillar exists for, because whoever seizes that address inherits every
implant pointing at it.

The capability is not missing. The vendored binary analyzer's
`_find_suspicious_strings` extracts urls, IPs, domains and registry paths with
pure regex over bytes and needs no third-party library at all. It is gated
behind `REQUIRED_CAPABILITIES = ("pe_analysis", "elf_analysis")`, so on a host
without `pefile`/`pyelftools` it goes down with the parsers — a dependency-free
capability lost to the absence of libraries it never uses. The mutex and the
user-agent go the same way, and the mutex surfaces at all only because it
happens to contain a declared term. Rename it and it vanishes.

These are recorded as **tripwire tests** in `test_bluescrub_corpus.py`: the
gaps are asserted, so a fix breaks the test and has to be acknowledged rather
than absorbed. A gap that is merely known gets forgotten.

**How much rests on the operator.** Scanned with no wordlist at all, the same
artifact yields two findings — the build path and the toolchain string. Both
come from detectors that need nothing declared. Everything else depended on
somebody having named the terms in advance.

## Contracts are now enforced at runtime

Three violations were live simultaneously, and none was found by 1500 tests.
Each escaped the same way: the schema was enforced only where a test happened
to call it, and a test validates whatever object it was handed rather than the
one that ships.

1. A binary dirty-word finding wrote a byte offset into a `source` location,
   which the contract rejects for want of a line number. No test exercised the
   binary path. *(Fixed in Sprint 5.)*
2. `dacv` is `additionalProperties: false`, and the service adds
   `findings_created` and `findings_updated` **after** scoring. The scoring
   test validated `score_job`'s return value, so the object actually served by
   `/report/{job_id}` was never checked. Both keys are real data, so they were
   added to the schema rather than removed from the object.
3. `strings_static_only` was introduced as a `ruleset_state` in Sprint 5 —
   by this branch — without extending the enum, so every deep scan without
   FLOSS produced metrics that failed their own schema.

`bluescrub/validation.py` now validates raw findings after redaction and the
metrics object last, and the suite's conftest turns it on globally — which
makes every existing test that runs the pipeline a contract check at no
authoring cost. Off in production: validating thousands of findings per job
costs real time, and a contract violation must never lose a scan. Violations
are logged with the rule id and never the evidence, because a violating finding
may hold a plaintext credential and the policy names logs explicitly.

## The C2 gap, closed

Running the pipeline on a compiled artifact showed Co-Optability scoring zero
on an implant with `10.20.30.40:8443` compiled into it — the one finding that
pillar exists for. `binary_indicators` closes it, and the interesting part is
what the measurement changed about the design.

**An IP regex over binary strings is the shape that once produced 344
criticals**, so the rules were measured before they were written. Across six
unrelated system binaries — git, ls, bash, gcc, libc, python — the shipped
rules produce two hits in total, both genuine IP literals from CPython's own
documentation.

**The obvious regex silently missed the only case that mattered.** A lookbehind
excluding a preceding dot looks right and passes every hand-written test. In a
real binary the address is recovered as `........10.20.30.40:8443` — adjacent
printable junk includes dots — so the detector reported nothing and looked like
it was working. Examining the whole dotted run instead is also what separates an
address from a version string: `1.2.3.4.5` contains a perfectly well-formed
quad, and no lookaround can reject it.

**What was deliberately not shipped.** General domains and URLs measured as
almost entirely licence and bug-tracker boilerplate — gnu.org, python.org,
mitre.org, launchpad.net — and an allowlist separating those from a real host
would be endless. Only internal namespaces are reported, where there is nothing
to separate. `.local` is excluded with them: measured, it is mDNS and
string-boundary noise (`thread.local`, `Setup.local`).

**Private space is reported, not filtered.** `10.20.30.40` in a shipped implant
is exactly the finding, and an internal address additionally says where the
thing was built or aimed.

The detector imports nothing — asserted by a test that parses its imports —
which is the whole point: the vendored analyzer could always do this, and went
dark on any host without `pefile`/`pyelftools`, libraries this code never uses.

## Provisioning the environment found four defects in an hour

`backend/requirements.txt` declares `pefile`, `pyelftools`, `capstone` and
`lief`. None was installed, so `binary_analyzer` reported `unavailable` on
every scan that had ever been run here — and its adapter had therefore never
executed against real output. `pip install -r backend/requirements.txt` was the
whole fix, and it immediately surfaced this:

**1. The adapter read a record shape the analyzer does not produce.** It looked
for a top-level `sha256`, `format` and `architecture`; the analyzer nests them
under `hashes`, `file_type` and `elf_info`. Every binary finding was therefore
built with `artifact_sha256=None` — which the raw-finding contract rejects, so
each one was a live contract violation.

**2. Offsets were silently discarded.** Upstream reports them as `"0x1111"` as
often as `4369`, and the adapter guarded with `isinstance(offset, int)`. The
same shape as the dirty-word defect fixed in Sprint 5: an offset present in the
data, dropped on the way out, with nothing to indicate it had happened.

**3. Every finding had empty evidence.** The adapter looked for `match`, `api`
or `value` on the issue record; the values live in a sibling `suspicious_strings`
list keyed by offset. Correlating on that offset recovers them —
`10.20.30.40` instead of an empty string — without parsing English out of a
description. The offset suffix upstream appends to descriptions is stripped
before the text can reach the evidence field, because it changes on every
rebuild and the evidence feeds the fingerprint.

**4. The unmapped backlog was not actually zero.** The earlier review was
measured with this scanner dark, so its rules were never in the sample.
`OPSEC: Extractable String (<kind>)` became a family of rules, now mapped by
kind: an address is somebody's infrastructure, a PEM header is a key, a shell
path is what a defender signatures. `url`, `domain` and `base64_blob` measure
as licence and bug-tracker boilerplate in ordinary binaries, so they are string
exposure rather than something to inflate a pillar with.

**Both safety nets fired, on their first contact with real data.** Runtime
contract validation reported the missing digests by rule id. The compiled-artifact
regression test failed on two assertions —
`test_every_binary_finding_carries_a_seekable_location` and
`test_nothing_lands_unmapped` — which is exactly the pair of things it was
written to catch and could not have been caught by any unit test, because the
defect was in a scanner that had never run.

**5. The two scanners described one artifact two different ways.** Upstream
reports the container in prose — `"ELF Executable (Linux/Unix)"` — where
`binstrings` reports `"elf"`. `Location.format` feeds `binary_fingerprint`, so
whichever scanner won severity precedence decided the digest, and a change in
which one won would re-key the finding and orphan its triage. Normalised to the
token vocabulary on the way in.

**And canonicalization did its job.** With both scanners live, `binary_indicators`
and the binary analyzer independently report the C2 at offset 8416; they now
collapse to one canonical finding with the second recorded as a corroborating
sensor, rather than counting the same address twice. Detectability scores for
the first time on a compiled artifact — five shellcode-pattern findings, each
with a seekable offset.

**A sixth defect, outside BlueScrub, was unmasked by the same install.**
`test_flow_vectorstore.py` opens with `pytest.importorskip("lancedb")`, and
lancedb was not installed — so all ten of its tests had been skipping. With the
module present they fail immediately on
`patch("app.flow_vectorstore.get_effective_settings")`: a patch target that
predates the `backend.app.` layout. The file has been dead for however long
that has been true, and nothing said so, because a skipped test and a passing
test look identical in a summary line.

`alembic` arrived with the same install, so `alembic heads` now runs and
confirms a single head. The hand-written chain-parsing test stays: it is the
only check that works on a machine where alembic is absent, which is the
machine this was written on.

## Installing the tools found what writing the adapters could not

Two `pip install`s — semgrep and flare-floss — produced more defects in an hour
than a day of feature work.

**Semgrep could not run at all, for a contract-level reason.** `RLIMIT_AS`
kills it at *every* value tested: 2, 4 and 8 GiB all produce "the engine was
killed" and exit 2. Its OCaml core reserves an enormous virtual arena at
startup, and `RLIMIT_AS` bounds address space reserved rather than memory used,
so the two are barely related. `RLIMIT_DATA` is the control that means what
§2.2 intended — semgrep runs at 8 GiB under it and is killed at 4. Every
remaining external tool (Gitleaks, TruffleHog, OSV-Scanner, Grype, Syft) is a
Go binary with the same reserving runtime, so this was blocking five more
adapters nobody had reached yet. `ResourceLimits.for_external_tool()` sets
`RLIMIT_DATA` and leaves `RLIMIT_AS` unset; the wall clock, CPU ceiling, file
size and process-group kill are unchanged, and they are what actually bound a
runaway tool.

**Its failure was machine-dependent.** Semgrep forks a worker per core, and its
memory need scales with that. On this 32-core host at an 8 GiB ceiling, `-j 4`
completes and `-j 8` is killed — so the same artifact would have scanned
cleanly on a small machine and silently degraded the Vulnerability pillar on a
large one. That is the machine-independence invariant in
[SCORING_SPEC §5](BLUESCRUB_SCORING_SPEC.md) failing in the worst way: not a
different score, but a different *coverage*, depending on the hardware. Job
count is pinned at 4.

**A shipped rule disqualified any file containing a TODO comment.** Identical
to the dirty-word pack defect fixed the day before, in a different place, and
invisible for the same reason: semgrep was not installed on the machine the
calibration was done on. `bluescrub.attribution.operator-todo` declares
`severity: INFO, confidence: LOW`, but its family was `attribution-identity`,
whose default is critical — tier-1 severity comes from the family and the
rule's own severity is discarded.

Underneath it, a deeper error: **detector class was assigned per tool.**
`semgrep → ast_pattern`, while the shipped pack mixes `pattern-regex` rules
with real AST ones. Calling a regex match an AST match exempts it from the
ceiling that exists precisely to stop a regex disqualifying an artifact. The
rulemap's own docstring says pillar assignment is "rule-level, never
tool-level"; the same argument applies to detector class, and rules now declare
`bluescrub_detector` alongside `bluescrub_family`.

**Every Semgrep finding carried the evidence `requires login`.** The OSS build
does not return matched lines. That is useless to an analyst and worse than
useless to the fingerprint: `matched_tokens` feeds `source_fingerprint`, so
every Semgrep finding in a job shared one token stream. The adapter now reads
the matched region from disk.

**FLOSS is PE-only, and the adapter claimed otherwise.** Handed an ELF, FLOSS
3.1 prints "supports the following formats ...: PE" and exits **0** — read as a
failed emulation and reported as lost coverage on every Linux artifact. Worse,
`recovery_state()` cleared the degradation whenever a cache file existed, and
the cache is written even when empty: a deep ELF scan would have reported
*full* Attribution coverage having recovered nothing. An unsupported format is
now skipped and said so, and a PE that genuinely fails still degrades.

The adapter itself was correct. Validated against a real PE — a setuptools
launcher stub — it emulated the binary, recovered two genuine stack strings and
wrote the cache. The parser written from recorded output needed no changes.

**Two of this branch's own tests had encoded a broken environment.** They
asserted that Detectability and Vulnerability were below full coverage, which
was true only because the tooling was missing. Installing it made them fail.
Restated as the rule rather than the observation: whatever is missing must be
reported, and whatever ran must not be.

**And installing semgrep broke an unrelated feature.** Into the application
virtualenv, pip resolved `opentelemetry-*` in semgrep's favour and left
LanceDB's grpc exporter mismatched, so knowledge-base indexing started failing.
Realigned, and written up as
[SUPPLY_CHAIN §5.1](BLUESCRUB_SUPPLY_CHAIN.md): a tool declared
`runner: subprocess` is invoked by path and never imported, so it has no
business sharing the application's dependency resolution. Install them with
pipx, a container, or a dedicated virtualenv on `PATH`.

## Gitleaks validated; the secret path holds against a real scanner

Installed outside the virtualenv this time — `GOBIN=~/.local/bin go install`,
per the lesson above — so nothing in the application's dependency resolution
moved.

**The argv guess was right.** `detect --source ... --report-path /dev/stdout`
works on 8.30.1, and the report is the bare TitleCase array the parser was
written for. 8.19+ also offers `gitleaks git` / `gitleaks dir`, but `detect`
still works and is what the adapter uses.

**The Sprint 5 acceptance criterion now holds against a real tool rather than a
stub.** A planted GitHub PAT reached the database as `ghp_…8B4a` with an
`hmac-sha256:` fingerprint, the plaintext appeared in no column and in no file
except the artifact the operator uploaded, and the normalised output went to
`quarantine/` with its evidence withheld. Until today that path had only ever
been exercised by a synthetic scanner the tests wrote themselves.

**One finding in, one finding out.** Gitleaks reports a single hit on a file
holding three credential-shaped strings, because it allowlists the AWS
documentation keys itself. Worth checking rather than assuming: an adapter that
silently drops findings looks identical to a tool that is simply precise.

**TruffleHog could not be installed the same way.** Its `go.mod` carries
`replace` directives, which Go refuses for module installs, so it needs a
release binary or the vendor's install script. Its argv and parser remain
tested against recorded output only, and it is the one remaining adapter in
that state.

**Semgrep is still in the application virtualenv.** Moving it out needs a
second virtualenv, and `ensurepip` is unavailable here — `python3.12-venv` is
not installed and needs apt. The opentelemetry pin from earlier keeps the
environment consistent, but the recommendation in
[SUPPLY_CHAIN §5.1](BLUESCRUB_SUPPLY_CHAIN.md) stands and this machine does not
yet follow it.

## The dependency scanners, and a quarantine defect they exposed

`osv-scanner`, `grype` and `syft` installed with `go install` outside the
virtualenv. All three crashed at exit 2 on first contact — the same
`RLIMIT_AS`-versus-Go-runtime failure as semgrep, because `deps_cve.py` and
`sbom.py` declare their own limits and the earlier fix had only reached the
registry and `secrets.py`. With the external profile applied: **osv-scanner 36
findings, grype 18, syft correctly 0** on declared packages and **1** on an
undeclared one, which is the discrimination that adapter exists to make.

Grype returned nothing on its very first run because it downloads a
vulnerability database on demand. Worth knowing for an air-gapped deployment,
where that download will not happen and the manifest's `db_snapshot_date` and
`db_checksum` — both still null — are what has to carry it.

**Then a Sprint 5 acceptance test failed, and it was right to.** With real
scanners installed, a parser failure wrote a tool's raw stdout to
`sensors/<tool>/<tool>.unparseable.raw`, under the job's 30-day clock, holding
a plaintext secret.

Two things were wrong. The quarantine tier was routed on `secret_bearing` — the
tool's declared purpose — where the policy tier reads "plaintext secrets in
**raw scanner output**". Semgrep's raw report carries the matched source lines,
and a matched line can be a credential whatever rule found it, so *any* tool's
unparseable stdout belongs under the 72-hour clock. And the test asserted no
plaintext in *any* file in the job, which is stricter than the policy: it
permits `quarantine/` explicitly. That assertion passed for as long as it did
because nothing was exercising the code path — it was measuring the absence of
a failure, not the presence of a rule.

**The fix exposed a third.** `output_dir.parents[1]` assumed a
`<job>/sensors/<sensor>` depth. Given anything shallower it resolves *above*
the job directory, so the quarantine folder would be created outside everything
the retention sweep looks at — silently, and only on the path that runs when a
parser has already failed. The job root is now found by the layout convention
rather than by counting.

## Baselines and comparability enforcement

`bluescrub/baseline.py`, with the design decided by one line of the contract:

    A rejected comparison returns `incomparable` with the differing field
    named. "Incomparable" without a reason is an error message users cannot
    act on.  — SCORING_SPEC §6

A differing field cannot be recovered from a SHA-256, so a baseline stores the
signature's *payload* beside its digest. The digest still decides comparability;
the payload only explains it, naming each field that moved, both values, and
why it matters. No migration: it goes in the existing `findings_json` blob.

**New, fixed and regressed are three separate answers.** A net count cannot
tell "three fixed, three appeared" from "nothing happened", and a severity that
rose on a finding nobody touched is the one an analyst most needs to see. A
refusal carries no diff at all — returning counts alongside "incomparable"
invites reading them anyway.

**A snapshot stores the minimum a diff needs.** Not the evidence: baselines are
kept indefinitely while job evidence expires at thirty days, and freezing
snippets here would quietly recreate the retention the policy removed.

One defect found by its own tests: unreadable baseline content fell through to
the digest path and reported *every* current finding as new — the same
misleading answer as treating an absent baseline as empty, reached from the
other direction. `_stored` now separates "unparseable" from "legacy row" and
refuses rather than guessing.

Still to do before it is usable: wiring into the service, and the
`PUT /baseline` and diff endpoints.

## Baselines, wired

`PUT /jobs/{job_id}/baseline` and `GET /jobs/{job_id}/baseline-diff`.

**The snapshot is the currency, not the canonical groups.** A baseline is set
when an operator decides a scan is the reference point, which is not when the
scan ran — by then the groups are gone and `Finding` rows are all there is. So
both paths build the same snapshot shape, and a test pins that they agree,
because a mismatch would report phantom changes on the first diff.

**The signature fields had to survive the scan.** A digest cannot name the
field that differs, so `bluescrub_job_lineage` gains `signature_fields_json`
(migration `d4e5f6a7b8c9`). Nullable on purpose: a baseline built from an
older row falls back to comparing digests — able to say whether two scans are
comparable, honest that it cannot say which field moved. Recomputing the
fields from the stored report was rejected: the report does not carry all of
them, and guessing at a comparability decision is worse than declining to
explain one.

**A baseline belongs to a project, so an unbound job is refused** with the
binding endpoint named rather than inferred. Inferring one would bind the job
by side effect, which is the kind of quiet action an audit trail exists to
prevent — and replacing a baseline records the one it superseded, so "what
were we comparing against in March" stays answerable.

**A refusal carries no diff over the API either.** The endpoint returns
`status: "incomparable"` with the differing fields, both values, and why each
matters — and no `new`/`fixed`/`regressed` keys at all, because including
counts alongside a refusal invites reading them.

## Still open

- The differential baseline (`upstream_baseline.json`) is captured from
  `NhanBC/BlueScrub @ 9452a51`. Regenerating it requires that repo; the test
  asserts the pin matches `VENDOR.md` so the two cannot drift silently.
- The golden PCAP behavioural gate skips without Zeek and Suricata. It must be
  run on the deployment host before each merge.
- Semgrep is still absent, so the Vulnerability pillar runs at half coverage;
  it is the one *required* binary still missing after provisioning.
- **Binary grouping buckets on position, not distance.** `_grouping_key` uses
  `offset // 64` where the contract says "offsets within 64 bytes". Two findings
  11 bytes apart were reported twice because a bucket edge fell between them
  (8382 and 8393 → buckets 130 and 131). Recorded in
  [DATA_CONTRACTS §2.1](BLUESCRUB_DATA_CONTRACTS.md); it is a `canon/2` change
  because grouping decides fingerprints and fingerprints carry triage.
- Mutex names, registry paths and hardcoded user-agents are still not extracted
  from binaries. They are Windows-shaped and there is no Windows corpus here to
  calibrate a threshold against — shipping them would be guessing. Held as
  tripwire assertions in `test_bluescrub_corpus.py`.
- The architecture gate is unsigned five sprints after it was meant to close;
  see the notice at the top of [BLUESCRUB_GATE.md](BLUESCRUB_GATE.md). Both
  blocking items are unanswered, and Semgrep rule licensing has been sidestepped
  rather than resolved — it becomes live again the moment anyone points
  `AIPAM_BLUESCRUB_SEMGREP_CONFIG` at the registry.
- TruffleHog is the one adapter still unvalidated against its tool: its
  `go.mod` carries replace directives, so it needs a release binary.
- The incremental cache is not started. Its acceptance criterion has two
  halves — only changed files re-analyzed, **and** the score still reflects
  findings from unchanged files — and the obvious implementation satisfies the
  first while silently failing the second, with a score that drifts downward as
  a project stabilises. Their argv is a
  documented decision a deployment must confirm; their parsers — which is where
  the Semgrep adapter's three defects actually lived — are pure functions tested
  against recorded output. `binstrings` and `build_paths` need no binary and are
  tested against artifacts the suite compiles with `gcc`.
