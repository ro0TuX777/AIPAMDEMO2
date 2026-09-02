# BlueScrub — DACV+R Code-Artifact Analysis inside AIPAM

> **Version**: 1.3 (2026-08-09)
> **Status**: **Ready after architecture gates** — see §1
> **Base Commit**: `dc76692` (main)
> **Target**: Single-VM, air-gapped Ubuntu 24.04 LTS
> **Upstream**: [`NhanBC/BlueScrub`](https://github.com/NhanBC/BlueScrub) (private) · [static demo](https://bluecloakforged.github.io/BlueScrubDEMO/)
> **Goal**: Bring BlueScrub's exploit-code auditing engine inside AIPAM as an additive `code_artifact` job type, scored along five OPSEC pillars (DACV+R), sharing AIPAM's findings model, cockpit, IOC correlation, and LLM narrative.

### Changelog — v1.0 → v1.1

v1.0 was reviewed externally and had eight internal contradictions plus four design defects that
would have produced misleading scores. This revision resolves all of them. Material changes:

| Area | v1.0 | v1.1 |
|---|---|---|
| Source type | `source_code` | **`code_artifact`** — the pipeline accepts repos, standalone binaries, build config, manifests, and PCAP-extracted binaries; `source_code` was semantically wrong for a binary-only child job |
| Analyzer isolation | Container for tools, **in-process** for vendored Python analyzers | **Every** analyzer runs in a process boundary — container or a hardened subprocess runner (§5.2) |
| Scoring input | Every raw scanner hit | **Canonical issue groups** after dedup (§2.4) — N scanners finding one bug counted N times in v1.0 |
| Absent pillars | Scored 0 ⇒ graded A | `not_assessed`; **scoped** grade kept structurally separate from **overall** grade (§3.4) |
| Missing RE signal | Weight redistributed | Fixed weights, coverage reported — redistribution made scores machine-dependent (§4.4) |
| Binary fingerprint | Included full artifact SHA-256 | Semantic anchors; SHA moves to evidence — any rebuild orphaned all triage in v1.0 (§2.5) |
| PCAP RE assessment | Wrote findings into the parent PCAP job | **Derived child job**; parent immutable (§5.6) |
| Critical attribution | "Disqualifying", floored at D | Grade **F** + `disqualified: true` (§3.5) |
| Source↔network bridge | "Call `correlate_job`" | Typed observables through AIPAM's **existing** IOC model and `ti_matcher` (§7) |
| LLM narrative | Not addressed | Prompt-injection boundary + indexing policy (§11) — the largest gap in v1.0 |
| Retention | Not addressed | Retention, secret masking, purge (§13) |
| Schedule | 8 sprints | Architecture gate + **9 sprints** |

### Changelog — v1.1 → v1.2

Deployment-policy decisions A–E resolved as items 25–29 (§17); **no open decisions remain**. Also
restores the Configuration section (§10), which was dropped in the v1.1 rewrite while its variables
continued to be referenced throughout. Retention becomes three tiers rather than one number (§13),
purge gains a second-tier token following the existing `aipam_kb_admin_token` convention, and Sprint 1
picks up retroactive project binding plus the global-findings filter chip.

### Changelog — v1.2 → v1.3 (architecture gate output)

Gate contracts drafted on `spike/bluescrub-contracts` — see [BLUESCRUB_GATE.md](BLUESCRUB_GATE.md).
The gate surfaced three plan-level defects:

1. **`cleanup_old_jobs` deletes whole jobs at 30 days and `Finding` cascades**, so triage carry-forward
   as designed would have silently stopped working for any project scanned less often than monthly.
   Resolved by a sixth table, `bluescrub_triage_ledger`, with no FK to `jobs` (§6). Carry-forward moves
   to Sprint 1 scope because the ledger is now a prerequisite, not a Sprint 6 nicety.
2. **Two scoring models coexist** — accumulation for four pillars, signal model for RE-Feasibility — and
   §3.1 read as if one formula covered all five. Made explicit in the scoring spec.
3. **A single `K_P` = 25 across pillars is wrong**; per-pillar provisional constants now set.

---

## 0) Strategy Overview

### Problem Statement

AIPAM analyzes what an adversary did *on the wire*. It has no view of the tooling itself — the source,
binaries, and build config of offensive code — and therefore cannot answer the pre-deployment question
red teams actually ask: *"if this ships, what will defenders see, and what will they be able to trace
back to us?"*

BlueScrub answers exactly that and already exists as a working Flask product with a mature analyzer
corpus. But it lives in its own silo: its own job system, its own findings store, its own UI, no
correlation with network evidence, and no LLM narrative.

### Solution

Port BlueScrub's **analysis engine** into AIPAM as a library behind a new `code_artifact` job
source-type, add two net-new pillars (Co-Optability, RE-Feasibility), and reuse AIPAM's existing
findings model, IOC correlation, cockpit, and LLM tail. An architecture gate, then four releases across
nine sprints, each independently deployable to the air-gapped server.

| Release | Branch | Sprints | Theme |
|---|---|---|---|
| **Gate** | `spike/bluescrub-contracts` | — | Contracts frozen before code (§1) |
| **R1** — Foundation | `feature/bluescrub-foundation` | 1–3 | Seam · engine port · canonicalization |
| **R2** — Pillars | `feature/bluescrub-pillars` | 4–5 | Vulnerability + Co-Optability + Attribution |
| **R3** — Detect & Workflow | `feature/bluescrub-detect-workflow` | 6–7 | Detectability, baselines, triage, agent API |
| **R4** — RE & Provenance | `feature/bluescrub-re-provenance` | 8–9 | RE-Feasibility + bridge, build/CI, scoring, exports |

### Non-negotiables

1. **AIPAM behaves identically today and after every merge.** No PCAP/log/Zeek/Suricata code path is
   modified. Every release gates on the existing suites passing unchanged plus a golden PCAP job.
2. **Additive-only edits, against a reviewed allowlist.** §5.4 enumerates every existing file that may
   be touched; anything outside it requires explicit review. *(v1.0 claimed "five files" and then
   modified nine.)*
3. **Untrusted input, always.** Every analyzer processes attacker-authored code inside a process
   boundary. No exceptions, including pure-Python ones.
4. **No silent degradation.** A missing tool, stale ruleset, or unassessed pillar is reported as such
   and never renders as "clean".
5. **Air-gapped and reproducible.** Same artifact + same manifest ⇒ same score, on any host.
6. **Port, don't rewrite.**

---

## 1) Architecture Gate

The following must be specified, reviewed, and merged as contracts **before Sprint 1 opens**. Each
produces a written artifact, not just a decision.

| # | Gate item | Deliverable |
|---|---|---|
| G1 | Analyzer process-isolation contract | `docs/BLUESCRUB_ISOLATION_CONTRACT.md` + scanner risk classification (§5.2) |
| G2 | Raw normalized finding contract | JSON Schema, versioned (§2.3) |
| G3 | Canonical group contract + severity normalization | JSON Schema + precedence table (§2.4, §3.2) |
| G4 | Fingerprint scheme, versioned | `fp/2` specification (§2.5) |
| G5 | Persistence and upsert semantics | Analyst-owned field list (§2.7) |
| G6 | Project identity and lineage | Schema for `bluescrub_projects` / `bluescrub_job_lineage` (§6) |
| G7 | Coverage-aware score semantics + comparability signature | Scoring spec (§3) |
| G8 | Derived child-job model for PCAP artifacts | Job lifecycle spec (§5.6) |
| G9 | Retention, secret handling, access control | Implement the policy resolved in §13 / §17 items 25–26 — tier enforcement, purge token, key generation in the deploy script |
| G10 | Offline tool / ruleset / database provenance | Tool manifest schema (§12) |
| G11 | LLM narrative boundary | Injection-resistance spec (§11) |

The canonical *data model* (G3) is frozen at the gate. The canonical *grouping logic* is calibrated in
Sprint 3, once the port supplies real overlapping scanner output to calibrate against.

**Gate status and artifacts:** [BLUESCRUB_GATE.md](BLUESCRUB_GATE.md) — contracts drafted on
`spike/bluescrub-contracts`, awaiting review. Two blocking questions for the reviewer are recorded
there: Semgrep rule licensing (needed before Sprint 1, not Sprint 4) and acceptance of the job-retention
consequence.

---

## 2) Data Contracts

Everything is additive. `Finding` and `Job` gain no columns.

### 2.1 Pipeline

```
raw scanner output
   → adapter normalization          (§2.3)  raw normalized findings
   → canonicalization + dedup       (§2.4)  canonical issue groups
   → false-positive suppression
   → scoring                        (§3)    coverage-aware pillar scores
   → persistence                    (§2.7)  Finding rows, upsert-safe
```

Scoring consumes **canonical groups**, never raw hits. Persistence writes one `Finding` per canonical
group, with contributing scanners recorded as corroborating evidence.

### 2.2 Why canonicalization is load-bearing

Semgrep, CodeQL, Joern, Weggli, and the vendored `MemorySafetyAnalyzer` can all report the same buffer
overflow. Scoring raw hits would count it five times and inflate the Vulnerability pillar by 5×, with
the inflation proportional to *how many optional tools happen to be installed* — making scores
non-comparable across hosts. Canonicalization is the difference between a scorecard and a tool-count
meter.

### 2.3 Raw normalized finding

The adapter's only job: map any scanner's output into this shape. No scoring decisions here.

```jsonc
{
  "schema": "bluescrub.raw/1",
  "sensor": "semgrep",
  "sensor_version": "1.92.0",
  "ruleset_version": "p/security-audit@2026-07-18",
  "rule_id": "python.lang.security.audit.exec-detected",
  "rule_version": "3",
  "raw_severity": "ERROR",
  "issue_family": "command-injection",     // canonical family, from the mapping table
  "pillar_hint": "Vulnerability",
  "location": {
    "file": "agent/tasks.py",
    "start_line": 88, "end_line": 88, "start_column": 4, "end_column": 27,
    "symbol": "run_task",                  // when the scanner reports it
    "node_kind": "call_expression"         // when the scanner reports it
  },
  "matched_tokens": "exec(payload)",
  "context_hash": "…",                     // normalized ±3 lines
  "observables": [],                        // §7
  "confidence": 0.81
}
```

`pillar_hint` is derived from **rule identity**, not tool identity. A single scanner produces findings
across pillars — `semgrep` serves both Vulnerability and Co-Optability in this plan — so the v1.0
`tool → pillar` map was structurally wrong. The mapping table is keyed on
`(sensor, rule_namespace, rule_id)` with an `issue_family` fallback.

### 2.4 Canonical issue group

```jsonc
{
  "schema": "bluescrub.canon/1",
  "canonical_id": "bs-canon-<fp>",
  "issue_family": "hardcoded-secret",
  "pillar": "Attribution",                 // one primary pillar
  "related_pillars": ["Co-Optability"],    // shown, never double-scored
  "severity": "high",                      // §3.2 — normalized, not raw
  "severity_source": "rule_mapping",       // rule_mapping|impact_modifier|precedence|fallback
  "scoring_confidence": 0.86,
  "primary_sensor": "semgrep",
  "primary_rule_id": "BC.SECRET.HARDCODED",
  "corroborating_sensors": [
    { "sensor": "gitleaks",    "rule_id": "generic-api-key", "confidence": 0.79 },
    { "sensor": "dirty_word",  "rule_id": "DW.KEY_PATTERN",  "confidence": 0.61 }
  ],
  "occurrences": 1,
  "location": { "...": "as raw" }
}
```

**Corroboration does not affect the numeric score in v1.** It raises analyst confidence and is
displayed as independent confirmation, but severity reflects impact and impact does not change because
a second tool agreed. Making corroboration score-bearing would reintroduce the machine-dependence
problem that §4.4 rejects: installing an optional scanner would change the score of an unchanged
artifact.

A future calibrated model may add a capped corroboration bonus (≤ +0.10 confidence), but only under a
fixed scanner manifest, with genuinely independent detectors — two wrappers over the same engine, or
two rule packs derived from the same corpus, are not independent — and only where a *missing* optional
scanner cannot lower an existing score.

### 2.5 Fingerprints — scheme `fp/2`

The scheme is itself versioned. v1.0's scheme was wrong in two ways and a third revision is plausible;
without a version field, that migration orphans every triage decision in the system.

**Source findings:**

```
fp/2:source = sha1(
    project_id            |   # stable UUID, not a path or basename
    rule_namespace        |
    rule_id               |
    relative_path         |
    enclosing_symbol      |   # when reported; else ""
    node_kind             |   # when reported; else ""
    normalized_tokens     |
    context_hash          |   # normalized ±3 lines, whitespace/comment stripped
    occurrence_index          # 0 unless the same match repeats in one semantic scope
)[:16]
```

**Binary findings** — semantic anchors only:

```
fp/2:binary = sha1(
    project_id | rule_id | format | architecture | section |
    nearest_symbol_or_function_fingerprint |
    normalized_value        # import sequence, recovered string, or config value
)[:16]
```

Artifact SHA-256, exact offset, and offset bucket live in **evidence**, never in the key. v1.0 put the
full artifact SHA in the binary key and then claimed offset bucketing preserved triage "across small
layout shifts" — but a rebuild changes the SHA entirely, so no binary finding could ever have retained
its triage.

**`occurrence_index` is a correctness requirement, not a refinement.** `findings` already carries
`UniqueConstraint("job_id", "finding_id")`, so two identical vulnerable statements in one function
would raise `IntegrityError` and fail the job, not merely collapse in the UI. A fingerprint collision
caused by a defective scheme must be distinguishable in logs from a legitimate retry.

**Carry-forward is scoped to lineage.** Triage transfers only within the same `project_id`, from the
job's bound `lineage_parent_job_id` (§6), never by scanning all prior jobs for a matching key.

```jsonc
"triage_carry": {
  "origin_job_id": "…",
  "match": "exact",                 // exact|semantic|ambiguous
  "prior_rule_version": "2",
  "current_rule_version": "3",
  "requires_review": true           // set when the rule changed materially
}
```

### 2.6 `evidence_json` envelope

```jsonc
{
  "schema": "bluescrub/2",
  "fingerprint_scheme": "fp/2",
  "scoring_model": "dacvr/1.1",
  "pillar": "Attribution",
  "related_pillars": [],
  "source": "source",                 // source|binary|vulnerability|iac|hardening|yara
  "issue_family": "hardcoded-secret",
  "primary_sensor": "gitleaks",
  "sensor_version": "3.90.2",
  "ruleset_version": "…",
  "rule_id": "generic-api-key",
  "rule_version": "3",
  "corroborating_sensors": [ /* §2.4 */ ],
  "location": { "file": "config.py", "start_line": 42, "end_line": 42,
                "start_column": 8, "end_column": 44, "symbol": "load_config" },
  "code": "…",                        // size-capped, inert-rendered
  "cwe": ["CWE-798"],                 // arrays
  "mitre": [ { "id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access" } ],
  "severity_rationale": "…",
  "severity_source": "rule_mapping",
  "recommendation": "…",
  "auto_fix": { "available": true, "patch_digest": "sha256:…", "patch_ref": "report/fixes/…" },
  "fp_filters_applied": ["test_fixture_path"],
  "observables": [ /* §7 */ ],
  "secret": { "secret_type": "api_key", "masked_value": "abcd…wxyz",
              "fingerprint": "hmac-sha256:…" },   // §13 — never the plaintext
  "re_signal": null,
  "artifact": { "sha256": "…", "filename": "beacon.exe", "format": "PE32+",
                "offset": 12480, "offset_bucket": 3 },
  "triage_carry": null,
  "truncated": false
}
```

Hard caps: `code` ≤ 4 KiB, `severity_rationale` ≤ 2 KiB, `recommendation` ≤ 2 KiB, envelope ≤ 64 KiB.
Auto-fix patches over 8 KiB are written to `report/fixes/` and referenced by digest. Anything truncated
sets `truncated: true` — a silently clipped envelope is a lie about the evidence.

All evidence is **rendered inert**: the source viewer serves uploaded content as text and never as
HTML, SVG, or script. Attacker-authored source reaching a browser is an XSS vector.

### 2.7 Persistence and upsert semantics

One `Finding` row per canonical group. On `(job_id, finding_id)` conflict, the persistence layer
performs an explicit upsert that updates **scanner-owned** fields only:

| Scanner-owned — may be overwritten | Analyst-owned — never overwritten |
|---|---|
| `severity`, `category`, `title`, `summary` | `analyst_status` |
| `confidence`, `evidence_json` | `analyst_notes` |
| `evidence_status`, `corroboration_score` | `reviewed_at`, `reviewer_id` |
| `corroborating_sources_json` | `feedback`, `explanation_feedback` |

*(The existing `binalysis` persistence uses a SELECT-then-skip pattern that the unique constraint makes
racy under concurrency; the BlueScrub adapter uses a real upsert instead. `binalysis` itself is not
modified.)*

### 2.8 `job.metrics_json` — the `dacv` object

```jsonc
{
  "dacv": {
    "schema": "bluescrub/2",
    "scoring_model": "dacvr/1.1",
    "fingerprint_scheme": "fp/2",
    "project_id": "8f2c…",
    "analysis_kind": "source_audit",        // source_audit | re_assessment
    "profile": "deep",
    "compatibility_signature": "sha256:…",  // §3.6
    "pillars": {
      "Attribution": {
        "status": "assessed",               // assessed | degraded | not_assessed
        "score": 91, "raw": 34.2, "coverage": 1.0, "findings": 6,
        "top_driver": { "finding_id": "bs-attribution-…", "rule_id": "DW.CODENAME",
                        "contribution": 8.7 }
      },
      "RE-Feasibility": {
        "status": "degraded", "score": 78, "raw": 27.9, "coverage": 0.85, "findings": 8,
        "unavailable_signals": [ { "signal": "decompilation", "weight": 0.15,
                                   "reason": "ghidra_not_installed" } ],
        "effort_band": "Hours"
      },
      "Co-Optability": { "status": "not_assessed", "score": null, "coverage": 0.0,
                         "reason": "profile_excludes" }
    },
    "overall": { "status": "incomplete", "score": null, "grade": null },
    "scoped":  { "profile": "deep", "score": 71, "grade": "D",
                 "pillars_assessed": 4, "pillars_total": 5,
                 "label": "Deep profile grade — 4 of 5 pillars assessed" },
    "disqualified": true,
    "grade_override": { "finding_id": "bs-attribution-…",
                        "reason": "critical_attribution_exposure" },
    "files_scanned": 42,
    "scanners": [
      { "sensor": "semgrep", "status": "completed", "version": "1.92.0",
        "ruleset_version": "…", "duration_ms": 41200, "truncated": false },
      { "sensor": "ghidra", "status": "unavailable", "reason": "not_installed" },
      { "sensor": "binary_analyzer", "status": "failed",
        "failure_class": "unsupported_format",
        "detail": "Mach-O universal binary" }
    ],
    "partial": true,
    "partial_reasons": [ { "sensor": "binary_analyzer", "class": "unsupported_format",
                           "pillars_affected": ["Detectability"] } ]
  }
}
```

`overall` and `scoped` are **structurally separate fields**. A scoped grade can never be read as an
artifact-level OPSEC grade by a client that doesn't know the difference, because `overall.grade` is
`null` when coverage is incomplete.

---

## 3) Scoring Model

### 3.1 Pillar score

```
sev_weight   = {critical: 10, high: 6, medium: 3, low: 1, info: 0.25}
group_contrib= sev_weight[g.severity] × g.scoring_confidence          # per canonical group
pillar_raw   = Σ group_contrib, subject to the caps below
pillar_score = round(100 × (1 − exp(−pillar_raw / K_P)))
```

`K_P` defaults to **25**, calibrated in Sprint 9 against a labelled corpus. Higher score = worse OPSEC
in every pillar.

**Contribution caps**, so volume cannot substitute for severity:

- Per `(rule_id)`: at most **5** groups contribute at full weight; beyond that, log-damped.
- Per `issue_family`: capped at **35%** of that pillar's raw total.
- `info` severity: retained (the dirty-word category ladder uses it for weak-but-real signal such as a
  stale build path) but capped at **10%** of the pillar's raw total in aggregate.

### 3.2 Canonical severity — precedence

Raw scanner severity is never used directly; vocabularies are inconsistent and a weak regex declaring
`CRITICAL` must not outrank a dataflow analyzer declaring `medium`. Resolution order:

1. Explicit BlueScrub/AIPAM canonical rule mapping.
2. Contextual impact modifiers — reachability, secret validity, execution path, exposure.
3. Versioned scanner-rule precedence table (semantic/dataflow > taint > pattern > regex).
4. Highest calibrated member severity — fallback only.

The tier used is recorded in `severity_source`.

### 3.3 Scoring confidence

```
scoring_confidence = calibrated confidence of the highest-precedence qualifying detector
```

Chosen by a **versioned precedence table**, not by whichever installed scanner reports the highest
number. Optional tool installation must not move the score. Corroborating detectors are retained as
evidence and do not contribute in v1.

### 3.4 Coverage, scoped grade, overall grade

| Pillar status | Meaning | Effect |
|---|---|---|
| `assessed` | All required detectors ran | Scores normally |
| `degraded` | Ran with missing optional signals or stale rules | Scores, coverage < 1.0, flagged |
| `not_assessed` | Profile excluded it, or all required detectors unavailable | `score: null` — **never zero** |

- `overall.grade` is computed **only** when every pillar is `assessed` and each coverage ≥ 0.9.
  Otherwise `overall.status` is `incomplete` and `overall.score`/`grade` are `null`.
- `scoped` always carries a grade over the pillars actually assessed, explicitly labelled. This
  preserves Quick-profile fast feedback without producing a misleading artifact-level result.
- UI wording: **"Quick profile: B — 3 of 5 pillars assessed. Not an overall artifact OPSEC grade."**

Pillar weights for the overall grade: Detectability 0.25, Attribution 0.25, Vulnerability 0.20,
Co-Optability 0.15, RE-Feasibility 0.15. Bands: A 0–19, B 20–39, C 40–59, D 60–79, F 80–100.

### 3.5 Critical attribution override

Any `critical` Attribution finding — classification marking, operator handle, org name — sets:

```jsonc
{ "grade": "F", "disqualified": true,
  "grade_override": { "finding_id": "…", "reason": "critical_attribution_exposure" } }
```

v1.0 called this disqualifying and then assigned D, which no reader interprets as disqualification.

### 3.6 Comparability signature

Baselines and trends compare only where the signature matches. It is the SHA-256 of:

```
profile | scoring_model | fingerprint_scheme | canonicalization_version |
scanner_manifest_digest | ruleset_versions_digest | required_scanner_availability |
pillar_scope | coverage_threshold | config_hash
```

| Comparison | Allowed |
|---|---|
| Quick ↔ compatible Quick | Yes, explicitly scoped |
| Standard ↔ compatible Standard | Yes, explicitly scoped |
| Deep complete ↔ compatible Deep complete | Yes — the artifact-level DACV+R baseline |
| Quick ↔ Deep | No |
| Degraded ↔ fully provisioned | No, or prominently marked non-comparable |
| Different scoring / canonicalization version | No, unless recalculated |

### 3.7 Legacy risk score

BlueScrub's `risk_score` from `bluescrub_result_schema.py` is retained **only** inside the differential
test harness for upstream parity checking. It never appears in AIPAM's UI, API, or exports. Two
unexplained risk numbers in front of an operator is worse than one.

---

## 4) RE-Feasibility — Pillar Specification

**Question:** if this binary is captured — especially pulled off the wire from a PCAP — how much effort
does a defender need to reverse it?

**Direction:** inverted relative to intuition, consistent with the other pillars — *high score = easy to
reverse = bad OPSEC*. The gauge is labelled explicitly.

### 4.1 Signals and weights

| Signal | Weight | Cheap to reverse (→1.0) | Hard to reverse (→0.0) | Implementation |
|---|---|---|---|---|
| Symbols / debug info | 0.20 | Unstripped, full symtab, DWARF/PDB, embedded PDB path | Fully stripped | `nm`/`readelf`/`objdump`; PE debug directory |
| Packing / protection | 0.15 | No packer, code entropy < 6.5 | Known packer, entropy > 7.2 | Detect-It-Easy + `binalysis` entropy engine |
| Recoverable-string yield | 0.15 | High meaningful-strings-per-KiB | FLOSS recovers almost nothing | `strings` + FLOSS |
| Anti-analysis | 0.15 | None present | anti-debug, anti-VM, timing, obfuscated flow | capa + vendored `anti_analysis_validator` |
| Decompilation success | 0.15 | > 80% of functions decompile cleanly | < 30% recovered | Ghidra headless (fallback rizin) |
| Runtime / language | 0.10 | Go, Rust w/ symbols, .NET, PyInstaller, Java | Hand-written C/asm, custom VM | format + section heuristics |
| Import table | 0.05 | Rich named imports | Dynamic resolution, API hashing, ordinal-only | vendored `binary_analyzer` |
| Config / IOC exposure | 0.05 | Plaintext C2 config, keys, mutexes | Encrypted config, per-build key | dirty-word + string recovery |

#### 4.1.1 Where the numeric anchors came from

The table above is qualitative — "high strings-per-KiB" is not a number. The
constants in `re_signals.py` were measured rather than guessed, on this bench:

| Artifact | Entropy | Symbols | Imports | Substantial strings/KiB |
|---|---|---|---|---|
| debug build (`-g -O0`) | 4.4 | 42 | 5 | 3.83 |
| stripped build (`-O2 -s`) | 5.2 | 0 | 5 | 1.79 |
| `ls` / `bash` / `curl` / `python3.12` | 5.6–6.1 | 128–2286 | 81–479 | 4.19–5.09 |
| `grep` / `tar` / `sed` / `gzip` | 5.4–6.0 | — | — | 2.53–3.46 |
| 60 KiB of random bytes | 8.0 | 0 | 0 | 0.32 |

Ordinary binaries hold 2.5–5.1 substantial strings per KiB, so 4.0 anchors
"yields plenty" and 0.5 anchors "yields nothing" — the packed case sits below it.

**"Substantial" means eight characters or more, and that floor is load-bearing.**
Counting four-character runs, the block of random bytes yielded 12.9 per KiB —
more than any real binary measured — because noise throws off short accidental
ASCII runs prolifically. A packed artifact therefore scored as the *most*
readable thing on the bench, which inverts the signal exactly where it matters
most. At eight characters accidental runs die out (0.32/KiB) and deliberate text
survives. This was caught by comparing artifact shapes, not by reading the code.

Effort bands on that bench: debug **Trivial** (80), stripped **Days** (46),
random-bytes **Weeks** (21).

### 4.2 Score and coverage

```
available_weight = Σ weight_s   for signals that ran
re_score         = round(100 × Σ (weight_s × signal_score_s) / available_weight)
coverage         = available_weight
```

The divisor normalizes over what actually ran, but **weights are never redistributed**. Each
unavailable signal is reported in `unavailable_signals` with its weight and reason, and the pillar drops
to `degraded`. v1.0 redistributed a missing Ghidra's weight across the remaining signals, which meant
the same binary scored differently depending on how the host was provisioned.

### 4.3 Effort band

| `re_score` | Band |
|---|---|
| 76–100 | Trivial |
| 51–75 | Hours |
| 26–50 | Days |
| 0–25 | Weeks |

Bands are reported alongside coverage; a `degraded` RE pillar shows the band with an explicit
"partial assessment" marker.

### 4.4 Scope limits

- Decompilation runs **only** in `deep`, **only** in the sandbox, with a hard timeout.
- The scanner **never executes** the sample. All signals are static.
- Sprint 8 ships the seven cheap static signals; decompilation lands in Sprint 9 behind
  `AIPAM_BLUESCRUB_GHIDRA_HOME`. A deployment without Ghidra is a supported configuration reporting
  0.85 coverage, not a broken one.

---

## 5) Architecture

### 5.1 New files

```
backend/app/bluescrub/
  __init__.py
  VENDOR.md               # upstream commit pin, allowlist, local modifications
  isolation/
    runner.py             # hardened subprocess runner for vendored analyzers (§5.2)
    limits.py             # rlimits, uid, cgroup/prlimit wiring, process-group kill
  contracts/              # JSON Schemas: raw, canonical, evidence, tool manifest
  pillars.py              # (sensor, rule_namespace, rule_id) → pillar + issue_family
  adapters.py             # scanner output → raw normalized finding (§2.3)
  canonicalize.py         # raw findings → canonical groups (§2.4)
  severity.py             # canonical severity precedence table (§3.2)
  vendored/               # ported from NhanBC/BlueScrub — read-only, see §1
  scanners/
    base.py semgrep.py codeql.py joern.py weggli.py
    gitleaks.py trufflehog.py gitmeta.py cooptability.py
    floss.py yargen.py deps.py build.py re_feasibility.py
  registry.py             # SCANNERS + profile gating + risk class (§5.2)
  scoring.py              # §3 — coverage-aware, versioned
  manifest.py             # incremental-scan cache (§5.7)
  baseline.py             # baseline persistence + comparability + diffing
  observables.py          # typed observable extraction → AIPAM IOCs (§7)
  wordlists.py            # pre-built packs + operator CRUD + regex safety (§13)
  narrative.py            # LLM boundary (§11)
  redaction.py            # secret masking + keyed fingerprints (§13)
  export.py ingest.py service.py

backend/app/api/bluescrub.py
backend/app/models/bluescrub.py     # Project, JobLineage, Baseline, Wordlist, ScoreHistory, Audit
backend/alembic/versions/<rev>_add_bluescrub_tables.py

frontend/src/pages/{DacvReportPage,BlueScrubTrendsPage,BlueScrubBaselineDiffPage}.tsx
frontend/src/components/{PillarGauge,CoverageBadge,WordlistEditor}.tsx

scripts/vendor_bluescrub.sh
deploy/bluescrub/                   # scanner images (digest-pinned), rule packs, offline bundle
docs/BLUESCRUB_ISOLATION_CONTRACT.md
docs/BLUESCRUB_OPERATOR_GUIDE.md
```

### 5.2 Isolation model

**Every analyzer runs in a process boundary.** v1.0 exempted the vendored Python analyzers on the
grounds that they are "pure-Python pattern matchers", which contradicted its own non-negotiable. Attacker
-controlled source triggers catastrophic backtracking, parser defects, unbounded allocation, and
pathological recursion without the sample ever being executed — and a Python thread timeout cannot
terminate a spinning regex.

Two runners:

| Runner | Used for | Mechanism |
|---|---|---|
| **Container** | External tools | Existing `run_sensor`: `network_mode="none"`, `read_only=True`, job dir at `/input` ro, output at `/output` rw, `mem_limit`, `pids_limit`, `cpu_limit`, `timeout_seconds`, digest-pinned image from the allowlist |
| **Hardened subprocess** | Vendored Python analyzers | Unprivileged UID · read-only input · private writable output · no network namespace · `RLIMIT_AS`/`RLIMIT_CPU`/`RLIMIT_NPROC`/`RLIMIT_FSIZE` · scrubbed environment (no credentials, no DB URL) · wall-clock kill by **process group** |

Scanner **risk classes**, declared in the registry and enforced by profile gating:

| Class | Examples | Policy |
|---|---|---|
| `parse_only` | Semgrep, dirty-word, metadata readers | Default enabled |
| `emulation` | FLOSS, capa, Ghidra, rizin | `deep` only, extended limits |
| `repo_history` | Gitleaks, TruffleHog, gitmeta | Enabled; network verification **hard-disabled** (§12) |
| `build_capable` | Anything that may invoke a language build system or project script | **Disabled by default**; requires an approved hardened mode |

### 5.3 Orchestrator seam

```python
# orchestrator.py, immediately after the existing binary branch at :372
if (job.source_type or "") == "code_artifact":
    from backend.app.bluescrub.service import run_code_artifact_pipeline
    return run_code_artifact_pipeline(job_id, job, db, job_root=job_root, upload_root=upload_root)
```

Mirrors `_run_binary_pipeline`'s shape: create job dir → emit `stage.status` per scanner → canonicalize
→ score → persist → write `metrics_json` → `_update_job_status` → emit `job.complete`.

**The generic network tail is not called.** `correlate_job` depends on `community_id`, IP pairs, and
timestamps, all null for code findings. §7 replaces it with typed observable extraction into AIPAM's
existing IOC pipeline, which works with `AIPAM_BLUESCRUB_CORRELATE` off. `auto_index_job` is off by
default (§11).

### 5.4 Existing-file modification allowlist

Non-negotiable #2 is enforced against this list; anything else requires review.

| File | Edit | Sprint |
|---|---|---|
| `schemas/common.py` | `code_artifact` in `SourceType` | 1 |
| `schemas/job.py` | request/response unions | 1 |
| `pipeline/orchestrator.py` | one branch beside the binary branch | 1 |
| `pipeline/artifact_classifier.py` | classify source archives | 1 |
| ~~`api/uploads.py`~~ | **not needed** — `POST /uploads/artifact` already exists and `artifact_classifier` already recognises zip/gzip/bzip2/tar, so code artifacts use the existing uploader unchanged (Sprint 1 finding) | — |
| `api/jobs.py` | `_create_code_artifact_job()`, derived child job | 1, 8 |
| `backend/app/main.py` | router registration | 1 |
| `pipeline/sensor_runner.py` | image allowlist entries only | 1 |
| `frontend/src/api.ts` | types + calls (**and the pre-existing `SourceType` drift: `binary` is missing today**) | 1 |
| `frontend/src/pages/NewAnalysisPage.tsx` | new tab | 1 |
| `frontend/src/App.tsx` | routes | 6 |
| `models/ioc.py`, IOC schemas | new observable types (§7) | 8 |

**Explicitly not modified:** `sensor_handlers.py`, `binalysis/`, `normalize/`, `sensors/registry.py`
entries for existing sensors. The platform-wide health work (§12) determines existing-sensor rule
availability by inspecting the same paths and env vars the handlers inspect — it does not change the
handlers. Enriching existing sensor status reporting is deferred to separate work with its own
regression gate.

### 5.5 Job directory

```
<job_root>/<job_id>/
  input/source/          # staged tree, read-only to analyzers
  input/binaries/
  sensors/<scanner>/     # sensor.meta.json + sensor.results.jsonl  (existing contract)
  extracted_files/       # existing
  report/                # DACV+R report, generated YARA, exports, fixes/
  runtime/manifest.json  # incremental-scan cache keys
  quarantine/            # raw scanner output containing secrets — restricted, short retention
```

### 5.6 Derived child jobs for PCAP artifacts

`POST /bluescrub/re_feasibility/{parent_job_id}/{file_id}` **enqueues a new job and returns its id.**
It does not write to the parent.

- Child `source_type = "code_artifact"`, `analysis_kind = "re_assessment"`.
- Lineage in `bluescrub_job_lineage`: `derived_from_job_id`, `derived_from_file_id`,
  `artifact_sha256`.
- The completed PCAP parent stays immutable; its metrics are not contaminated by code findings;
  retries, failures, and access control have their own lifecycle; multiple extracted files can be
  assessed without overwriting one another.
- The cockpit shows the derived analysis beside the extracted file with a link back to parent evidence.

### 5.7 Incremental scanning

A file-hash manifest alone is insufficient. Cache keys include file SHA-256 **+ scanner version +
ruleset/database version + scanner config hash + profile-affecting options**.

Project-level invalidation: dependency scanners on manifest/lockfile change; gitmeta on history change;
build/IaC scanners on related config change; dirty-word on wordlist change; any scanner or rule-pack
upgrade invalidates its own entries.

**Cached findings from unchanged files are materialized into the new job before scoring.** Otherwise an
incremental scan reports a phantom improvement — the acceptance test checks both halves.

### 5.8 Profiles

AIPAM's literal is `triage | standard | deep`; BlueScrub's is `quick | standard | deep`. Map
`quick → triage`, keep AIPAM's names on the wire, show BlueScrub's labels in the UI.

| AIPAM | UI | Source | Deps | Binary | Decompile | Pillars assessed |
|---|---|---|---|---|---|---|
| `triage` | Quick | ✓ | — | — | — | 3 of 5 (scoped grade only) |
| `standard` | Standard | ✓ | ✓ | — | — | 4 of 5 (scoped grade only) |
| `deep` | Deep | ✓ | ✓ | ✓ | ✓ | 5 of 5 (overall grade eligible) |

---

## 6) Database

Six new tables. No existing table is altered.

> **Gate finding.** `aipam.prune_old_jobs` deletes the **whole job** — row and directory — at
> `aipam_job_retention_days` (default 30), and `Finding` cascades. Carry-forward that reads a prior
> job's `Finding` rows therefore breaks silently for any project scanned less often than monthly.
> `bluescrub_triage_ledger` below carries triage outside the job lifecycle. This also validates two
> earlier choices that must not be revisited: `bluescrub_baselines.job_id` is `SET NULL`, and
> `bluescrub_score_history` has no foreign key. Full analysis in
> [BLUESCRUB_DATA_CONTRACTS.md](BLUESCRUB_DATA_CONTRACTS.md) §0.

```python
class BlueScrubTriageLedger(Base):
    """Triage decisions, outside the job lifecycle. Carry-forward reads this, never a prior job."""
    __tablename__ = "bluescrub_triage_ledger"
    project_id   = Column(String, primary_key=True)   # no FK — survives job deletion
    finding_id   = Column(String, primary_key=True)
    status       = Column(String, nullable=False)
    notes        = Column(Text, nullable=True)
    rule_version = Column(String, nullable=True)
    fingerprint_scheme = Column(String, nullable=False)
    decided_at   = Column(String, nullable=False)
    decided_by   = Column(String, nullable=True)      # self-asserted; see §13
    origin_job_id = Column(String, nullable=True)     # provenance only, may dangle
```

```python
class BlueScrubProject(Base):
    __tablename__ = "bluescrub_projects"
    project_id   = Column(String, primary_key=True)    # generated UUID — the durable identity
    display_name = Column(String, nullable=False)      # renameable, never load-bearing
    created_at   = Column(String, nullable=False)
    archived     = Column(Boolean, nullable=False, default=False)

class BlueScrubJobLineage(Base):
    __tablename__ = "bluescrub_job_lineage"
    job_id                = Column(String, ForeignKey("jobs.job_id", ondelete="CASCADE"),
                                   primary_key=True)
    project_id            = Column(String, ForeignKey("bluescrub_projects.project_id"),
                                   nullable=True, index=True)
    lineage_parent_job_id = Column(String, nullable=True)   # bound at CREATION, not at persist
    derived_from_job_id   = Column(String, nullable=True)   # PCAP parent, for re_assessment
    derived_from_file_id  = Column(String, nullable=True)
    analysis_kind         = Column(String, nullable=False)  # source_audit | re_assessment
    compatibility_signature = Column(String, nullable=False)

class BlueScrubBaseline(Base):
    __tablename__ = "bluescrub_baselines"
    id            = Column(Integer, primary_key=True)
    project_id    = Column(String, ForeignKey("bluescrub_projects.project_id"),
                           nullable=False, index=True)
    job_id        = Column(String, ForeignKey("jobs.job_id", ondelete="SET NULL"), nullable=True)
    active        = Column(Boolean, nullable=False, default=False)
    label         = Column(String, nullable=True)
    compatibility_signature = Column(String, nullable=False)
    findings_json = Column(Text, nullable=False)   # frozen — survives deletion of the source job
    metrics_json  = Column(Text, nullable=False)
    created_at    = Column(String, nullable=False)
    created_by    = Column(String, nullable=True)
    __table_args__ = (
        Index("uq_bluescrub_active_baseline", "project_id",
              unique=True, sqlite_where=text("active = 1")),
    )

class BlueScrubScoreHistory(Base):
    __tablename__ = "bluescrub_score_history"
    id            = Column(Integer, primary_key=True)
    project_id    = Column(String, nullable=False, index=True)
    job_id        = Column(String, nullable=False, unique=True)   # append-only, no cascade
    scanned_at    = Column(String, nullable=False)
    profile       = Column(String, nullable=False)
    scoring_model = Column(String, nullable=False)
    compatibility_signature = Column(String, nullable=False)
    coverage_json = Column(Text, nullable=False)
    pillars_json  = Column(Text, nullable=False)
    overall_score = Column(Integer, nullable=True)    # null when incomplete
    grade         = Column(String, nullable=True)
    scoped_score  = Column(Integer, nullable=False)
    severity_counts_json = Column(Text, nullable=False)

class BlueScrubAudit(Base):
    __tablename__ = "bluescrub_audit"
    id         = Column(Integer, primary_key=True)
    actor      = Column(String, nullable=True)
    at         = Column(String, nullable=False)
    action     = Column(String, nullable=False)   # baseline.set|wordlist.update|triage.batch|purge
    project_id = Column(String, nullable=True, index=True)
    job_id     = Column(String, nullable=True)
    old_json   = Column(Text, nullable=True)
    new_json   = Column(Text, nullable=True)
    reason     = Column(Text, nullable=True)
    session    = Column(String, nullable=True)
```

**Baseline durability.** v1.0 used `ON DELETE CASCADE` on the baseline's `job_id`, so deleting the
source job destroyed the supposedly frozen baseline. `SET NULL` keeps the frozen snapshot and drops only
the provenance pointer. Score history carries no FK at all — it is append-only under a documented
retention policy.

**Concurrency.** Each job binds `lineage_parent_job_id` at creation, so two concurrent scans of the same
project inherit deterministically from the same parent rather than racing on "latest completed". The
project's latest-job pointer updates under optimistic concurrency; baseline activation is transactional
under the partial unique index.

**Ad-hoc scans** may run without a `project_id` (basename shown as display metadata only), but
cross-job triage carry-forward, baselines, and trends are disabled until an operator binds the scan to
a project.

---

## 6.5) Domain separation — traffic versus code

AIPAM analyses **traffic**: what was observed on the wire. BlueScrub analyses
**code**: source, binaries, and build configuration. Every BlueScrub finding is
derived from a file, never from an observation, and the two must not be
mistakable for one another in the same cockpit.

Three guarantees, each enforced by test rather than convention:

**No shared storage.** BlueScrub writes to `findings` and its own tables. It
references no network model — not `Connection`, `DnsQuery`, `TlsSession`,
`Alert`, `Host`, `NormalizedEvent`, `TimelineEvent`, or `JobPcap`. Asserted
against the package source, so a future import fails the suite rather than
quietly landing.

**No borrowed evidence.** A code finding leaves `community_id`, `src_ip`,
`dest_ip`, `ts`, and `pcap_label` null. An IP literal in a source file is not
an observed connection, and a finding that populated `src_ip` would enter host
views, connection views, and the IOC bridge as though something had been seen
on the wire. Every envelope also carries `analysis_domain: "code"` explicitly.

**No borrowed vocabulary.** This is the one that nearly slipped through.
Several vendored analyzers use AIPAM's own terms for source patterns:
`beacon_patterns`, `dns_patterns`, `c2_references`, `network_indicators`.
AIPAM's `beaconing` sensor reports beaconing observed in captured traffic;
BlueScrub's `beacon_patterns` reports a hardcoded sleep interval in a file.
Side by side in one findings list they read alike and mean nothing alike, so
those titles are annotated — "Fixed sleep interval (hardcoded beacon interval
in source)". Sensor names are also asserted disjoint from AIPAM's, since
`Finding.sensor` is a filter facet and a shared name would merge the two
domains in the UI.

**The deliberate exception** is §7. Typed observables extracted from code flow
into AIPAM's existing IOC pipeline, so a domain literal in source can be matched
against the same domain seen in traffic. That is a join on an *indicator value*,
not a merging of evidence: the code finding stays a code finding, the network
finding stays a network finding, and the correlation records that both mention
the same string. Nothing about the source finding claims it was observed.

## 7) Source ↔ Network Correlation

The stated product advantage — correlating tooling with network evidence — needs a real mechanism.
Calling the generic `correlate_job` cannot provide it: the fields it matches on are null for code
findings.

**Reuse AIPAM's existing IOC machinery.** The platform already has an `IocType` union
(`ip`, `domain`, `url`, `hash`, `ja3`, `ja3s`, `sni`, `email`, `mutex`, `registry`), a `models/ioc.py`,
and a `ti_matcher` sensor that correlates IOCs across jobs. BlueScrub extracts typed observables from
source and recovered strings and emits them into that pipeline.

| Observable | Handling |
|---|---|
| IP, domain, URL, hash, email, mutex, registry key | **Existing `IocType`** — no change |
| Certificate fingerprint | **New `IocType`** — exact-match semantics, distinct from `ja3` (a client-hello fingerprint, not a cert hash) |
| Service name | **New `IocType`** once normalization is defined (case, prefix, platform) |
| PDB / build path | **Typed evidence, not an IOC** — attribution-useful but needs partial-match and path-normalization semantics first |
| YARA family | **Typed evidence** — a classification label, not an observable value |
| API sequence, import sequence, recovered function fingerprint | **Typed evidence** — structured behavioural data requiring similarity matching, not string equality |

`IocType` stays a taxonomy of things with defined equality, not a bucket for anything worth correlating.
The three evidence categories participate in correlation later, once normalization, equality, partial
matching, confidence, and collision behaviour are specified.

```jsonc
"observables": [
  { "type": "domain", "value": "cdn.example.invalid", "normalized": "cdn.example.invalid",
    "origin": "source_literal", "location": "loader/net.c:112", "confidence": 0.82 },
  { "type": "mutex", "value": "Global\\RT2411", "origin": "recovered_string",
    "artifact_sha256": "…", "confidence": 0.75 }
]
```

This is why open decision #7 resolves cleanly: the bridge works with the generic correlation path
**off**.

---

## 8) API Surface

Routes split across two prefixes; v1.0 claimed a single prefix and then listed routes outside it.

**Existing prefixes, extended:** `POST /api/v1/uploads/source` · `POST /api/v1/jobs` with
`source_type: "code_artifact"`.

**New, under `/api/v1/bluescrub`:**

| Endpoint | Method | Purpose |
|---|---|---|
| `/projects` · `/projects/{id}` | GET/POST · GET/PUT | Project identity management |
| `/jobs/{job_id}/project` | PUT | **Retroactively bind an ad-hoc job to a project** — no re-scan; enables carry-forward from that point (§17 D) |
| `/report/{job_id}` · `/report/{job_id}/pillars` | GET | Full report · scorecard with coverage |
| `/wordlists` · `/wordlists/{id}` · `/wordlists/prebuilt` | CRUD | Dirty-word lists; builtins read-only |
| `/dirty_scan` | POST | Ad-hoc dirty-word scan |
| `/baseline/{project_id}` | GET/POST/DELETE | Get / set / clear active baseline |
| `/baseline/{project_id}/diff/{job_id}` | GET | new / fixed / regressed — **or `incomparable` with the reason** |
| `/trends/{project_id}` | GET | History, filtered by compatibility signature |
| `/export/{job_id}/{fmt}` | GET | `pdf` · `executive` · `html` · `yara` · `dirty_csv` |
| `/re_feasibility/{parent_job_id}/{file_id}` | POST | **Enqueues a derived child job**, returns its id |
| `/purge/{job_id}` · `/purge/project/{project_id}` | POST | Operator purge of staged source and quarantine (§13) |
| `/agent/health` | GET | Platform-wide tool, ruleset, and database status (§12) |
| `/agent/capabilities` | GET | API manifest + recommended workflow |
| `/agent/findings/{job_id}` | GET | Filtered (severity, pillar, source, family, limit, offset) |
| `/agent/triage/batch` | POST | Batch triage — upsert-safe, audited |

---

## 9) Frontend

| Component | Work |
|---|---|
| `NewAnalysisPage.tsx` | `code_artifact` tab: project selector (or "ad-hoc"), profile picker, accept `.zip,.tar.gz,.tgz`, standalone binary, guarded repo-URL / server-path |
| `DacvReportPage.tsx` | 5 gauges with **coverage badges**; `not_assessed` renders as a hatched empty gauge, never a zero-score green bar; scoped-grade banner; `disqualified` treatment; Overview / Findings / Dirty Words / Export tabs |
| Finding detail | MITRE + CWE arrays, severity rationale with `severity_source`, corroborating sensors, auto-fix, **inert** source viewer, masked secrets only |
| `BlueScrubTrendsPage.tsx` | Trends filtered by compatibility signature; incomparable points shown as gaps, not joined lines |
| `BlueScrubBaselineDiffPage.tsx` | Set baseline; new/fixed/regressed; explicit `incomparable` state with reason |
| `WordlistEditor.tsx` | CRUD; builtins read-only; regex validated against §13 limits before save |
| Extracted-files table | "Assess RE feasibility" → creates a child job, links to it |
| Ad-hoc job banner | Persistent on project-less results: *"Ad-hoc scan — triage will not carry forward."* with a **Bind to a project →** action that calls `PUT /jobs/{id}/project` (§17 D) |
| Global findings list | A **source-type filter chip**, default **off**, that pulls `code_artifact` findings into the shared list. A deployment flag would be a decision made once and never revisited; a filter is volume-safe by default and one click from discoverable (§17 C) |
| `api.ts` | New types; fix pre-existing `SourceType` drift (`binary` missing today) |

---

## 10) Configuration

Names mirror BlueScrub's `BLUESCRUB_*` where they map 1:1, so operator knowledge transfers.

| Variable | Default | Purpose |
|---|---|---|
| `AIPAM_BLUESCRUB_ENABLED` | `true` | Master switch |
| `AIPAM_BLUESCRUB_MAX_WORKERS` | `4` | Parallel analyzer processes |
| `AIPAM_BLUESCRUB_ANALYZER_TIMEOUT` | `120` | Per-analyzer wall-clock seconds (enforced by process-group kill) |
| `AIPAM_BLUESCRUB_ADMIN_TOKEN` | unset | Elevated token for project-wide purge and legal-hold override, via `X-BlueScrub-Admin-Token`. **Unset = open to any valid API token**, matching the existing `aipam_kb_admin_token` convention |
| `AIPAM_BLUESCRUB_SECRET_HMAC_KEY` | *(generated at install)* | Keyed-HMAC key for secret fingerprints (§13). Required; deploy script generates 32 random bytes into the same `.env` as `aipam_api_token` |
| `AIPAM_BLUESCRUB_RETENTION_SOURCE_DAYS` | `30` | Staged source/binaries — counted from the project's **last scan**, not from upload |
| `AIPAM_BLUESCRUB_RETENTION_EXTRACTED_DAYS` | `14` | `extracted_files/` on derived RE child jobs |
| `AIPAM_BLUESCRUB_RETENTION_QUARANTINE_HOURS` | `72` | Raw scanner output containing plaintext secrets |
| `AIPAM_BLUESCRUB_INDEX_SOURCE` | `false` | Allow `auto_index_job` to index code-artifact content (§11) |
| `AIPAM_BLUESCRUB_RE_ON_PCAP` | `false` | Run RE-Feasibility automatically on PCAP-extracted binaries |
| `AIPAM_BLUESCRUB_CORRELATE` | `false` | Let code findings enter the generic cross-job correlation path (the IOC bridge in §7 works with this off) |
| `AIPAM_BLUESCRUB_ALLOW_GIT_CLONE` | `false` | Permit repo-URL ingest |
| `AIPAM_BLUESCRUB_ALLOW_ADHOC` | `true` | Permit project-less scans (§17 D) |
| `AIPAM_BLUESCRUB_SCAN_ROOTS` | unset | Allowlisted server-side paths for directory scanning |
| `AIPAM_BLUESCRUB_GHIDRA_HOME` | unset | Ghidra headless install; absent ⇒ rizin fallback, RE coverage 0.85 |
| `AIPAM_BLUESCRUB_MAX_ARCHIVE_MB` | `512` | Upload ceiling |
| `AIPAM_BLUESCRUB_MAX_EXTRACT_FILES` | `50000` | Zip-bomb guard |
| `AIPAM_BLUESCRUB_DB_STALE_DAYS` | `30` | Vulnerability-database age at which health reports `database_stale` |

**On `AIPAM_BLUESCRUB_SECRET_HMAC_KEY` as an env var rather than a file path.** Environment values are
readable via `/proc/<pid>/environ` and `docker inspect`, and a file path would avoid that. It is not
worth the inconsistency here: the key's only job is preventing fingerprint enumeration by someone with
database read but not host access, and on a single-VM air-gapped deployment those are effectively the
same principal. Documented limitation, deliberately accepted, consistent with how `aipam_api_token` is
already handled.

---

## 11) LLM Narrative and Sensitive-Code Handling

The narrative stage is a security boundary. Source comments, READMEs, build scripts, and even scanner
rule descriptions are attacker-authored and can carry prompt-injection payloads.

**Rules:**

1. The narrative model receives **bounded, schema-validated canonical findings** — never a repository,
   never raw file contents beyond size-capped snippets.
2. Snippets are wrapped in explicit untrusted-evidence delimiters, and the system prompt states that
   instructions inside evidence are data to be described, never followed.
3. The narrative stage has **no tool access**. It cannot trigger scans, file reads, or network calls.
4. Every claim carries the `finding_id` it derives from; unsourced claims are dropped in
   post-validation.
5. Model id, prompt-template version, and scoring-model version are recorded with the narrative.
6. Deterministic scanner rationale (`severity_rationale`) and LLM interpretation are stored and
   displayed as **separate fields**, never merged.
7. Secrets are masked before the narrative stage; the model never sees plaintext.
8. Narrative output is treated as untrusted for rendering (inert, no HTML passthrough).

**`auto_index_job` is off by default for `code_artifact` jobs.** Indexing raw offensive source and
recovered secrets into a persistent vector store is materially more sensitive than indexing network
metadata: it is a long-lived copy of the most sensitive content in the system, outside the job
retention lifecycle. Enabling it requires `AIPAM_BLUESCRUB_INDEX_SOURCE=true`, honours
the retention policy, and excludes any finding carrying a `secret` block.

**Acceptance:** a fixture repository containing prompt-injection strings in comments, a README, and a
Dockerfile cannot alter narrative instructions, cause tool invocation, or suppress findings.

---

## 12) Air-Gap and Supply Chain

Tool presence is not sufficient. Dependency and vulnerability scanners depend on offline databases whose
age directly changes results.

**Offline tool manifest** (`deploy/bluescrub/tool-manifest.json`), one entry per tool:

```
name · version · container image digest (not tag) · binary checksum ·
license · redistribution status · ruleset version · rule pack checksum ·
vulnerability DB snapshot date · DB checksum · supported architectures
```

**Health states** — per tool, surfaced by `/agent/health` and echoed into every report:
`installed` · `missing` · `unhealthy` · `incompatible` · `database_stale` · `rules_stale` ·
`checksum_mismatch`.

A job must distinguish: *ran and found nothing* · *skipped by profile* · *unavailable* · *failed* ·
*ran with stale rules* · *output truncated* · *completed with reduced capabilities*. "Empty findings" is
never proof of a clean result.

**Platform-wide, not BlueScrub-only.** The existing `capa` handler writes empty results and continues
when `AIPAM_CAPA_RULES_DIR` is missing, so a capa-less PCAP job is today indistinguishable from one where
capa found nothing. `/agent/health` inspects the same paths and env vars the existing handlers inspect
and reports their rule availability too — **without modifying those handlers** (§5.4).

**Specific attention:**

- OSV and Grype database snapshots — age reported, staleness threshold configurable.
- Semgrep, capa, YARA, dirty-word rule pack versions. **Semgrep's engine, registry rules, and Pro rules
  carry distinct licensing**; "Semgrep installed" does not establish that the intended rules may ship in
  the bundle. Same column as CodeQL.
- Secret scanners' online verification modes (e.g. TruffleHog verification) **hard-disabled**, asserted
  by test, not just by config.
- Redistribution terms for Ghidra, FLOSS, Detect-It-Easy, rizin, RetDec.
- The private BlueScrub source licence and copyright notices carried into `vendored/`.

The offline update bundle is signed or integrity-verified and ships licence notices plus an SBOM.

---

## 13) Retention, Secrets, and Data Handling

Staged offensive source and extracted artifacts are among the most sensitive data the platform holds.

**Retention — three tiers, not one number.**

| Path | Default | Reasoning |
|---|---|---|
| `quarantine/` — raw scanner output with plaintext secrets | **72 hours** | The only legitimate use is confirming a secret is real during false-positive triage, a same-week activity. Longer retention of plaintext credentials buys nothing. |
| `input/source/`, `input/binaries/` | **30 days since the project's last scan** | Not 30 days since upload. Absolute age purges the staged tree of an actively-scanned project and silently destroys its incremental cache. |
| `extracted_files/` on derived RE child jobs | **14 days** | These are copies; the parent PCAP job retains the original. |

What makes short retention safe: **purging staged source does not destroy findings.** Evidence,
snippets, scores, and triage live in the database. What is lost is the inline source viewer for old
jobs, re-scan without re-upload, and cache warmth — a convenience cost, not evidence loss.

Also: automatic cleanup after failed or cancelled jobs · restrictive job-directory permissions · no
source contents in application logs · every purge writes an audit record.

**Purge access.** AIPAM has no user or role model — authentication is a single shared bearer token
(`aipam_api_token`), so every caller is the same principal. Rather than invent an identity system,
reuse the existing second-tier pattern set by `aipam_kb_admin_token`: single-job purge is open to any
valid API token; **project-wide purge and legal-hold override require `AIPAM_BLUESCRUB_ADMIN_TOKEN`**
via `X-BlueScrub-Admin-Token`, and when that variable is unset the operation is open — exactly how the
KB admin token already behaves.

**Consequence to state plainly:** with no authenticated identity, the `actor` column in
`bluescrub_audit` is self-asserted. The audit trail is a record of what happened, not proof of who did
it. Do not let its presence imply an assurance the auth layer does not provide.

**Secrets.** The database, API, UI, logs, and exports never persist a complete secret:

```jsonc
{ "secret_type": "api_key", "masked_value": "abcd…wxyz",
  "fingerprint": "hmac-sha256:…", "file": "config.py", "line": 42 }
```

A **keyed HMAC**, not a plain hash — many secret formats have low effective entropy and a bare digest is
reversible by enumeration. Raw scanner output containing plaintext secrets is deleted after
normalization or moved to `quarantine/` under the 72-hour tier above.

**Key custody.** `AIPAM_BLUESCRUB_SECRET_HMAC_KEY`, 32 random bytes generated by the deploy script into
the same `.env` that already holds `aipam_api_token`, mode 0600. Back it up with the deployment
secrets; losing it is equivalent to rotating it.

**Rotation: only on suspected key compromise, never on a schedule.** Rotation is **permanently lossy**
and cannot be undone — re-fingerprinting requires the plaintext secrets, and those were deliberately
destroyed at normalization. Every previously-triaged secret finding therefore reappears as new after a
rotation. Two requirements follow:

1. Rotation writes a `secret_hmac.rotate` row to `bluescrub_audit`.
2. Trend rendering reads those rows and draws a discontinuity marker at the boundary, so the resulting
   jump in open Attribution findings is visibly a key change and not a real regression.

**Untrusted regexes.** Operator wordlists accept regex, which is itself untrusted input. Patterns are
validated on save — length cap, nesting-depth cap, rejection of nested unbounded quantifiers — and
matching executes inside the §5.2 subprocess boundary with a wall-clock kill. A catastrophic expression
must not hang a worker.

---

## 14) Release Plan

### Architecture Gate — `spike/bluescrub-contracts`
Deliver G1–G11 (§1). Exit criterion: contracts merged and reviewed; no implementation code.

### R1 — Foundation · `feature/bluescrub-foundation`

**Sprint 1 — Seam, isolation, coverage.** `code_artifact` enum + schema unions · `POST /uploads/source`
+ archive classification · `_create_code_artifact_job()` · safe ingest (path traversal, symlink escape,
hard links, device files, nested decompression, Unicode path collisions, file-count and size ceilings) ·
`run_code_artifact_pipeline` + orchestrator branch · **hardened subprocess runner** · Semgrep (container)
· raw normalization · coverage states and scoped-only scoring · minimal scorecard showing partial
coverage · projects/lineage/**triage-ledger** tables · **ad-hoc scans with retroactive project binding**
(`PUT /jobs/{id}/project` + banner) · **`code_artifact` findings excluded from the global findings list
by default, behind a filter chip** · golden PCAP regression test.

> The triage ledger moves from Sprint 6 to Sprint 1: carry-forward depends on it, and retrofitting a
> persistence layer after findings already exist means a backfill migration.

> **Acceptance** — a Semgrep-only job renders a *scoped* grade with two pillars `not_assessed` and
> `overall.grade == null`; a repo bomb and a symlink-escape archive are rejected; a deliberately hung
> analyzer is killed by process group without touching the worker; existing suites and the golden PCAP
> job pass unchanged.

**Sprint 2 — Engine port.** Sync script + `VENDOR.md` + pinned commit · vendor the allowlist, rewrite
imports (**no Flask coupling to strip — measured, the corpus is already decoupled**) · **7** `BaseAnalyzer` analyzers + FP helpers · 9 specialised scanners with a separate interface (**upstream's README says ten BaseAnalyzer subclasses; it is seven**) ·
`binary_analyzer` with its calibrated API tier model, injection-combo upgrade, low-value downgrade ·
`dependency_scanner`, `mitre`, `auto_fix` · rule-level pillar mapping · profile gating · partial-failure
handling · adapt BlueScrub's suite. **`vendored/` stays effectively read-only** — AIPAM behaviour lives
in wrappers and adapters, so re-syncing upstream is a reviewable diff.

> **Acceptance** — raw-layer differential parity with standalone BlueScrub (§15); a Mach-O universal
> binary yields a *partial* job, not a failed one.

**Sprint 3 — Canonicalization.** Canonical grouping and dedup calibrated against real overlapping output
from Sprint 2 · severity precedence table · scoring confidence precedence · contribution caps ·
occurrence discriminators · upsert semantics · triage carry-forward bound to lineage · full coverage-aware
scoring · compatibility signature.

> **Acceptance** — two scanners finding one bug produce one scored canonical finding listing both; two
> identical vulnerable statements in one function remain two findings and persist without
> `IntegrityError`; installing an additional overlapping scanner does not change the score.

### R2 — Pillars · `feature/bluescrub-pillars`

**Sprint 4 — Vulnerability + Co-Optability.** CodeQL (licence-gated), Joern, Weggli, gosec, cargo-audit ·
OSV / Grype / Syft + SBOM · `cooptability.py` rule pack (hardcoded C2, kill-switches, unauthenticated
control channels, control-granting keys).

**Sprint 5 — Attribution.** Dirty-word over source and binaries with FLOSS recovery, pre-built packs,
category severity ladder, regex safety · Gitleaks · TruffleHog (verification disabled) · gitmeta ·
hardcoded build/PDB paths · code-similarity fingerprinting · secret masking and keyed fingerprints.

> **Acceptance** — a planted codename in a binary surfaces with category and offset context; a critical
> Attribution hit sets grade F and `disqualified: true`; no plaintext secret appears anywhere in DB, API,
> logs, or exports.

### R3 — Detect & Workflow · `feature/bluescrub-detect-workflow`

**Sprint 6 — Detectability + persistence.** YARA/capa/FLOSS · yarGen signature-derivation scoring · YARA
export · Alembic migration · incremental cache with full invalidation semantics · baselines with
comparability enforcement.

**Sprint 7 — Workflow, agent API, offline DBs.** Triage carry-forward UI · batch triage (audited,
upsert-safe) · `/agent/*` including platform-wide health · wordlist CRUD + editor · baseline diff UI ·
offline database management before dependency scanners are declared production-ready.

> **Acceptance** — triage a finding, edit an unrelated file, re-scan: status persists, only changed files
> are re-analyzed, **and the score still reflects findings from unchanged files**; a Quick scan compared
> to a Deep baseline returns `incomparable` with a reason.

### R4 — RE & Provenance · `feature/bluescrub-re-provenance`

**Sprint 8 — RE static signals + bridge + child jobs.** Seven cheap static signals · effort band with
coverage · derived child-job workflow and endpoint · typed observable extraction into the existing IOC
pipeline · new `IocType` values (cert fingerprint, service name).

> **Acceptance** — a PCAP carrying a PE/ELF, extracted by `file_triage`, assessed via the action, produces
> a child job with RE findings while the **parent PCAP job is byte-for-byte unchanged**; a domain literal
> in source correlates to the same domain seen in traffic with `AIPAM_BLUESCRUB_CORRELATE` off.

**Sprint 9 — Decompilation, provenance, scoring calibration, exports.** Ghidra headless in the sandbox
with rizin fallback · hadolint / checkov / zizmor + SBOM · `K_P` calibration against a labelled corpus ·
`DacvReportPage` + trends · exports · LLM narrative with the §11 boundary · operator guide · signed
air-gap bundle.

> **Acceptance** — the RE calibration pair (stripped/packed vs. debug build of the same source) separates
> in the expected direction; removing Ghidra changes coverage and status but not the other signals' scores;
> the prompt-injection fixture cannot alter narrative instructions.

---

## 15) Test Plan

### No-regression gate — every release
Existing suites unchanged · automated **golden PCAP** regression test (not a manual pass) · `openapi.yaml`
diff shows only additive paths.

### Differential testing — five layers
Only layer 1 is upstream parity. A **smaller** canonical set after dedup is correct, not a regression.

1. **Raw parity** — standalone BlueScrub raw output vs. vendored raw output. *The regression gate.*
2. **Normalization** — raw fixtures → expected AIPAM normalized findings.
3. **Canonicalization** — normalized findings → expected canonical groups (expected-collapse fixtures).
4. **Scoring** — canonical groups → expected contribution and pillar score.
5. **Persistence** — canonical groups → stable database representation across re-runs.

### Acceptance criteria

1. Two scanners finding the same vulnerability produce one canonical scored finding listing both.
2. Two identical vulnerable statements in one function remain two findings and persist without error.
3. A source finding keeps triage after unrelated line insertions, and never inherits triage from another
   project.
4. Quick and Standard display unassessed pillars, not zero-risk pillars; `overall.grade` is `null`.
5. Missing Ghidra changes coverage and status; other signals' scores are unchanged.
6. Incremental scans reuse unchanged results **and** reproduce the complete current score.
7. Scanner timeout or parser failure cannot terminate or poison the worker process.
8. Malicious archives — nested decompression, hard links, device files, Unicode path collisions, symlink
   escapes — are rejected.
9. A catastrophic custom regex cannot exhaust a worker.
10. A PCAP parent job is unchanged after an extracted file is assessed.
11. Baseline comparisons with different profile, scoring model, or canonicalization version are labelled
    incomparable.
12. Tool and vulnerability-database staleness appear in health **and** in the report.
13. A prompt-injection fixture in source cannot alter narrative instructions or trigger tool use.
14. Deleting an original scan does not remove a frozen baseline or required history.
15. Large or malformed scanner output is bounded, marked truncated, and cannot fill the VM disk.
16. Installing an additional overlapping scanner does not change an artifact's score.
17. No plaintext secret appears in DB, API, UI, logs, or exports; masked value + keyed fingerprint only.
18. Two concurrent scans of one project inherit the same lineage parent deterministically.
19. Retention purge removes staged source and quarantine and writes an audit record.
20. A `not_assessed` pillar never renders as a zero-score green gauge.

---

## 16) Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| Score inflation from duplicate findings | Scorecard measures tool count, not risk | Canonicalization before scoring; acceptance #1, #16 |
| Absent pillars read as clean | Operator ships a leaky artifact on a false A | `not_assessed`; `overall.grade` null; acceptance #4, #20 |
| Prompt injection via source | Narrative subverted, possible tool abuse | §11 boundary; no tool access; acceptance #13 |
| Secrets persisted in DB or vector store | Long-lived exposure outside retention | Masking + keyed HMAC; indexing off by default; acceptance #17 |
| Analyzer compromise or hang | Worker loss, host exposure | Process boundary for every analyzer; acceptance #7, #9 |
| Fingerprint scheme revision | Mass triage loss | Scheme versioned; migration path required before any change |
| Vendored engine drift | Fixes diverge | `VENDOR.md` pin; `vendored/` read-only; wrappers carry AIPAM behaviour |
| Non-reproducible air-gap results | Two hosts, two scores | Digest-pinned images; fixed weights; compatibility signature; acceptance #5, #16 |
| Parent PCAP mutation | Evidence integrity loss | Derived child jobs; acceptance #10 |
| Baseline destroyed by job deletion | Lost regression reference | `SET NULL` + frozen snapshot; acceptance #14 |
| Concurrent scans racing on carry-forward | Nondeterministic triage | Lineage bound at creation; acceptance #18 |
| Licence non-compliance in the bundle | Cannot ship | Manifest redistribution column covering engine, rules, and DBs separately |
| Scope creep from BlueScrub UI parity | Slipped releases | Keyboard shortcuts and legacy UI are explicit Sprint 9 nice-to-haves |

---

## 17) Decisions

### Resolved

| # | Decision | Resolution |
|---|---|---|
| 1 | Port mechanism | Vendored copy + sync script; `vendored/` effectively read-only |
| 2 | Upstream sync policy | Stay in step; net-new pillars contributed back |
| 3 | Git-URL ingest | Off by default |
| 4 | Server-side directory scanning | Allowlisted roots, unset by default |
| 5 | CodeQL | Optional; Semgrep + Joern are the baseline |
| 6 | Ghidra | Optional, explicitly provisioned; **no weight redistribution** when absent |
| 7 | Generic cross-job correlation | Off; replaced by typed observables through the existing IOC pipeline |
| 8 | RE score direction | High = easy to reverse = bad; gauge labelled explicitly |
| 9 | Source type name | **`code_artifact`** — `source_code` was wrong for binary-only child jobs |
| 10 | PCAP-extracted RE persistence | Derived child job; parent immutable |
| 11 | Project identity | Generated UUID; basename is display metadata only |
| 12 | Missing pillar behaviour | `not_assessed` / `degraded`, never implicit zero |
| 13 | Build-capable scanners | Disabled pending an approved hardened mode |
| 14 | Raw source indexing | Off by default; role-controlled; retention-bounded |
| 15 | Canonical severity | Highest **normalized, rule-calibrated** severity; never raw, never scanner-count |
| 16 | Corroboration in scoring | No numeric effect in v1; evidence and display only |
| 17 | Scoring detector selection | Versioned precedence table |
| 18 | Scoped comparability | Scoped ↔ compatible scoped allowed; scoped ↔ complete prohibited |
| 19 | Observable taxonomy | Extend `IocType` only where equality is defined; rest stay typed evidence |
| 20 | Upsert semantics | Analyst-owned fields never overwritten |
| 21 | Triage lineage | Bound at job creation, not resolved at persist time |
| 22 | Secret handling | Masked everywhere; keyed HMAC fingerprint |
| 23 | Health scope | Platform-wide, read-only introspection of existing sensors |
| 24 | Schedule | Architecture gate + 9 sprints |
| 25 | Retention and purge access | **Three tiers** — quarantine 72 h, staged source 30 days *since last scan*, derived extracted files 14 days. Project-wide purge and legal-hold behind `AIPAM_BLUESCRUB_ADMIN_TOKEN`, following the `aipam_kb_admin_token` convention; single-job purge open. Audit `actor` is self-asserted — recorded, not authenticated (§13) |
| 26 | HMAC key custody | Env var beside `aipam_api_token`, generated at install, 0600, backed up with deployment secrets. **No scheduled rotation** — rotation is permanently lossy and marks a discontinuity in trends (§13) |
| 27 | Code findings in the global list | **BlueScrub views by default, exposed as a UI filter chip rather than a deployment flag.** Volume-safe by default, one click to include. No cost to correlation: the source↔network bridge operates at the IOC layer (§7), not the findings-list layer |
| 28 | Ad-hoc (project-less) scans | **Permitted**, with a persistent "triage will not carry forward" banner and **retroactive project binding** (`PUT /jobs/{id}/project`, no re-scan). Prohibiting them would regress the workflow operators already have in standalone BlueScrub and put a dialog in front of a 20-second hygiene check |
| 29 | Standalone BlueScrub after R4 | **Kept, with its role changed from product to engine upstream and parity oracle.** Feature-freeze the Flask UI; continue engine changes; pin it in CI as the layer-1 differential oracle. Retiring it would destroy the only mechanism that proves the vendored port has not drifted, strand existing air-gapped installs, and remove the lightweight option for auditing code without the full platform |

All decisions are resolved. New questions arising during the gate are appended here rather than
tracked separately.

---

## 18) References

**Review lineage:** v1.0 external plan review (2026-08-09) and response round; all eight identified
contradictions and six foundational items resolved above.

**Product sources:** [NhanBC/BlueScrub](https://github.com/NhanBC/BlueScrub) (private — README and tree
reviewed via `gh`) · [BlueScrub static demo](https://bluecloakforged.github.io/BlueScrubDEMO/).

**Tool selection:** [DeepSource SAST 2026](https://deepsource.com/resources/static-analysis-tools) ·
[Semgrep vs CodeQL 2026](https://dev.to/rahulxsingh/semgrep-vs-codeql-lightweight-patterns-vs-semantic-analysis-for-sast-2026-412k) ·
[OSV-Scanner V2](https://appsecsanta.com/osv-scanner) ·
[Syft/Grype guide](https://www.sachith.co.uk/sboms-and-supply%E2%80%91chain-basics-syft-grype-security-pitfalls-fixes-practical-guide-feb-27-2026/) ·
[Joern](https://joern.io/impact/) ·
[zizmor](https://blog.packagist.com/securing-our-github-actions-workflows-with-zizmor/).

**AIPAM internals:** `AMMPOP_Whitepaper.md:82` (original BlueScrub concept) ·
[`docs/ANALYST_COCKPIT_IMPLEMENTATION_PLAN.md`](ANALYST_COCKPIT_IMPLEMENTATION_PLAN.md) ·
[`docs/AIPAM_SensorsV2_Implementation_Plan.md`](AIPAM_SensorsV2_Implementation_Plan.md).

**Verified against the codebase during review:** `UniqueConstraint("job_id", "finding_id")` on `findings`
· `IocType` and `models/ioc.py` · `ti_matcher` sensor · `handle_capa` empty-result behaviour on missing
`AIPAM_CAPA_RULES_DIR` · `run_sensor` isolation flags · `_run_binary_pipeline` as the seam precedent ·
`SourceType` union drift in `frontend/src/api.ts`.
