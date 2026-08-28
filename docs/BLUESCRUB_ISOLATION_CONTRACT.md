# BlueScrub — Analyzer Isolation Contract (G1)

> **Gate item**: G1 · **Status**: proposed · **Owner**: platform
> **Governs**: every component that reads attacker-authored bytes.
> **Plan reference**: [BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md](BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md) §5.2

## 1. Rule

**No process that parses attacker-authored input runs inside the Celery worker process.**

"Attacker-authored input" means anything staged from an upload or extracted from a PCAP: source files,
archives, binaries, manifests, build config, git history, and any scanner output derived from them.
This includes pure-Python pattern matchers. A Python thread cannot be reliably terminated, so a
`ThreadPoolExecutor` timeout is a scheduling hint, not a security control.

## 2. Two runners

| Runner | Scanners | Mechanism |
|---|---|---|
| **Container** | External tools (Semgrep, CodeQL, Joern, Weggli, Gitleaks, TruffleHog, OSV/Grype/Syft, hadolint, checkov, zizmor, capa, FLOSS, Detect-It-Easy, Ghidra, rizin) | Existing `run_sensor` ([`pipeline/sensor_runner.py:52`](../backend/app/pipeline/sensor_runner.py#L52)) |
| **Subprocess** | Vendored Python analyzers, dirty-word matching, wordlist regex evaluation | New `bluescrub/isolation/runner.py` |

Nothing else. If a scanner does not fit one of these, it does not ship.

### 2.1 Container runner — inherited guarantees

`run_sensor` already provides `network_mode="none"`, `read_only=True`, job dir at `/input` read-only,
output at `/output` read-write, `mem_limit`, `pids_limit`, `cpu_limit`, `timeout_seconds`, and an image
allowlist. **No new sandboxing code is written for container scanners.** The only additions are
registry entries and allowlist entries.

Deviation from existing practice: BlueScrub images are pinned by **digest**, not tag (§G10).

### 2.2 Subprocess runner — required properties

The worker container runs as root (no `user:` directive in `docker-compose.yml` for the worker
service), so the runner can drop privileges. This is the enabling precondition; if the worker is ever
run as non-root, the runner must fail closed rather than silently run privileged.

| Property | Mechanism | Value |
|---|---|---|
| Unprivileged UID | `setresgid`/`setresuid` in `preexec_fn` before `exec` | dedicated `bluescrub` uid/gid, created in the image |
| New process group | `os.setsid()` in `preexec_fn` | required for reliable kill |
| Read-only input | Input path passed as an argument; the runner does not grant write | analyzer opens `O_RDONLY` |
| Private writable output | One temp dir per invocation, mode 0700, owned by the analyzer uid | deleted after result capture |
| No network | `unshare(CLONE_NEWNET)` where permitted; otherwise the analyzer allowlist forbids any socket-using analyzer | fail closed |
| Address space | `RLIMIT_AS` | 2 GiB default, per-scanner override |
| CPU time | `RLIMIT_CPU` | soft `AIPAM_BLUESCRUB_ANALYZER_TIMEOUT` (120 s), hard soft+5 (§2.4) |
| Process count | `RLIMIT_NPROC` | 64 — **per-UID, not per-tree**; applied only when a dedicated uid was acquired (§2.4) |
| Output file size | `RLIMIT_FSIZE` | 256 MiB |
| Core dumps | `RLIMIT_CORE` | 0 — a core dump of an analyzer contains attacker data |
| Environment | Explicit allowlist, not inheritance | `PATH`, `LANG`, `HOME`, scanner-specific vars only |
| Wall-clock kill | `SIGTERM` to the **process group**, `SIGKILL` after 5 s | never `Popen.kill()`, which misses children |

**Credential scrubbing is mandatory and explicit.** The worker environment holds `aipam_api_token`,
`DATABASE_URL`, `CELERY_BROKER_URL`, `AIPAM_BLUESCRUB_SECRET_HMAC_KEY`, and Security Onion / Arkime
passwords. The child environment is constructed from an allowlist; it is never `os.environ.copy()`
with deletions, because a deletion list silently fails to cover variables added later.

### 2.3 Failure classification

Every invocation returns exactly one outcome, and the outcome — not an exception traceback — is what
reaches `metrics_json.scanners[]`:

| Class | Trigger | Job effect |
|---|---|---|
| `completed` | Exit 0, parseable output | Findings ingested |
| `completed_truncated` | Output hit `RLIMIT_FSIZE` or the byte cap | Findings ingested, `truncated: true`, pillar → `degraded` |
| `timeout` | Wall-clock or `RLIMIT_CPU` | Pillar → `degraded`, reason recorded |
| `oom` | `RLIMIT_AS` / killed by OOM | Pillar → `degraded` |
| `crashed` | Non-zero exit, signal death | Pillar → `degraded` |
| `unparseable` | Exit 0 but output fails schema validation | Treated as `crashed`; raw output quarantined for debugging |
| `unavailable` | Tool absent, image missing, digest mismatch | Pillar → `degraded` or `not_assessed` |
| `skipped` | Excluded by profile | Not a degradation |

**A scanner failure never fails the job.** It degrades the affected pillar and is reported. The only
job-level failures are ingest failures and persistence failures.

### 2.4 Two rlimit properties that are easy to get wrong

Both were found by the Sprint 1 tests rather than by review, and both silently
degrade the boundary rather than breaking it visibly.

**`RLIMIT_CPU` soft must be strictly below hard.** At the soft limit the kernel
sends `SIGXCPU`, which the runner classifies as `timeout`. At the hard limit it
sends `SIGKILL`, which is indistinguishable from an OOM kill. Setting both to the
same value skips `SIGXCPU` entirely, so every CPU exhaustion is reported as `oom`
and the operator chases a memory problem that does not exist. The runner sets
hard = soft + 5.

**`RLIMIT_NPROC` counts every process owned by the UID, not the process tree.**
It is only meaningful once privileges have been dropped to a dedicated account.
Applied against a shared UID it does the opposite of its intent: on a busy host
the limit is already exceeded, so the analyzer's first `fork()` fails with
`EAGAIN` and a legitimate scanner crashes. The runner applies it only when a uid
drop actually occurred.

A corollary for deployment: because the limit is per-UID, concurrent analyzers
running as the same `bluescrub` account share one process budget. With worker
concurrency of 1 this is not a live concern; raising concurrency means raising
`max_processes` proportionally, or giving each concurrent slot its own uid.

## 3. Scanner risk classes

Declared per scanner in `bluescrub/registry.py` and enforced by profile gating.

| Class | Members | Policy |
|---|---|---|
| `parse_only` | Semgrep, dirty-word, vendored pattern analyzers, dependency-manifest parsing, hadolint, checkov, zizmor | Enabled in all profiles that include their pillar |
| `emulation` | capa, FLOSS, Detect-It-Easy, Ghidra, rizin, RetDec | `deep` only. Extended limits: 8 GiB `RLIMIT_AS`, 900 s. Never executes the sample — static analysis and emulation only |
| `repo_history` | Gitleaks, TruffleHog, gitmeta | Enabled where Attribution is in scope. **Network verification hard-disabled** — asserted by test, not config (§G10) |
| `build_capable` | Anything that may invoke a language build system, package resolver, or project script (e.g. CodeQL database construction for compiled languages, `cargo`/`go`/`npm` resolution modes) | **Disabled by default.** Requires an approved hardened mode with a written threat model. Not shipped in R1–R4 |

`build_capable` is the class that matters: a scanner that builds the project executes attacker-authored
code by design, and no amount of process isolation makes that equivalent to parsing.

### 3.1 `repo_history` — the repository's config is not configuration

Found while implementing gitmeta, and it applies to Gitleaks and TruffleHog too because all three
invoke git or read a repository git also reads.

`.git/config` ships inside the artifact, which makes it attacker-authored input. Several of its keys
do not hold data — they hold the name of a program git will run: `core.pager`, `core.fsmonitor`,
`core.sshCommand`, `core.alternateRefsCommand`, `core.hooksPath`, `diff.external`, and
`log.showSignature`, which reaches for gpg. Repository-local config cannot be switched off the way
system and global config can (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL`), so the boundary here is not
"do not read it" but "outrank it": every invocation passes those keys as `-c key=` on the command
line, where they take precedence over the repository's own values. `protocol.allow=never` is set on
the same line, so a transport cannot be reached even by a future misuse of the adapter.

Two consequences worth carrying to the other two scanners in this class:

- **Remotes are read by parsing the file, not by asking git.** The file is evidence; handing it back
  to the program we are keeping it away from would defeat the point.
- **`safe.directory` must be set explicitly.** The staged tree belongs to the worker and the analyzer
  drops to a dedicated account, so git refuses the repository as "dubious ownership" and every history
  scanner silently reports nothing. This presents as a clean result, which is the failure mode this
  project keeps finding.

A `.git` *file* — how submodules and linked worktrees record their object store — holds a
`gitdir:` pointer that may be absolute. It is resolved and refused when it leaves the staged tree.

### 3.2 `emulation` — emulate once, share the result

Found while wiring FLOSS, and it applies to capa, Ghidra and rizin for the same
reason.

Three scanners want recovered strings: FLOSS reports on them directly, and the
dirty-word and build-path scanners match against them. The obvious shape gives
each one its own recovery pass, and it is wrong twice over. It triples the
cost, which for an emulation-class tool is 900 seconds per artifact. More
importantly it triples the *exposure*: emulation is the tier where
attacker-authored code is interpreted rather than parsed, and running it three
times over the same bytes multiplies the number of chances for a vivisect or
Ghidra defect to matter.

So the artifact is emulated **once**, by the one scanner that is declared
`emulation` class and therefore gets the extended ceilings, and the recovered
strings are written to a job-scoped cache the `parse_only` consumers read. The
consumers do not gain an emulation capability by reading a file.

Two consequences worth stating:

- **The cache is keyed on the artifact digest, not its path.** The same binary
  staged twice under different names is one recovery, and a path that differs
  between scanners is not a cache miss.
- **Run order is declared, not inferred.** `ScannerSpec.order` puts the
  producer ahead of its consumers. `floss` sorts *after* both `build_paths` and
  `dirty_word` alphabetically, so leaving the dependency to the accident of a
  name would make it invisible and one rename away from silently breaking —
  with the symptom being reduced findings, not an error.

A `parse_only` scanner must never invoke an `emulation`-class tool itself. That
would promote its risk class in fact while leaving it `parse_only` in the
registry, and would run a 900-second tool inside a 120-second process boundary
that would kill it.

## 4. What this contract does not cover

- The container runner's existing isolation is inherited, not re-specified. Changes to
  `sensor_runner.py` beyond allowlist entries are out of scope for BlueScrub.
- Kernel-level hardening (seccomp profiles, AppArmor) is desirable and explicitly deferred. The
  contract is written so it can be added later without changing the runner's interface.

## 5. Acceptance

1. A vendored analyzer given a catastrophic-backtracking input is killed by process group; the worker
   survives and the pillar is marked `degraded` with class `timeout`.
2. A vendored analyzer that forks children and hangs is fully reaped — no orphan survives the kill.
3. The child environment contains no token, DB URL, broker URL, or HMAC key. Asserted by a test that
   dumps the child environment and diffs it against the allowlist.
4. A scanner writing unbounded output is stopped at `RLIMIT_FSIZE` and reports
   `completed_truncated`.
5. A `build_capable` scanner cannot be enabled by configuration alone in R1–R4.
6. With the worker running as non-root, the runner refuses to start rather than running analyzers with
   worker privileges.
