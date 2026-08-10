# BlueScrub — Data Contracts (G2–G6, G8)

> **Gate items**: G2 raw finding · G3 canonical group + severity · G4 fingerprints · G5 persistence ·
> G6 project identity and lineage · G8 derived child jobs
> **Status**: proposed · **Schemas**: [`backend/app/bluescrub/contracts/`](../backend/app/bluescrub/contracts/)
> **Plan reference**: [BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md](BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md) §2, §6

This document resolves what the plan left ambiguous. Shapes already fixed in the plan are not restated;
the JSON Schemas are normative.

---

## 0. Gate finding — job retention deletes the carry-forward source

**Discovered while writing this contract; it changes the design.**

`aipam.prune_old_jobs` runs daily and calls
[`cleanup_old_jobs`](../backend/app/services/cleanup.py#L15), which deletes the **entire job** — the
`jobs` row and the job directory — once `created_at` is older than `aipam_job_retention_days`
(default **30**). `Finding` cascades on `job_id`.

The plan's retention model (§13) assumed findings outlive staged source. They do not: at day 30 the
findings are gone too. Two consequences the plan did not account for:

1. **Triage carry-forward silently stops working** for any project scanned less often than monthly,
   because it reads the prior job's `Finding` rows and those rows no longer exist.
2. `bluescrub_job_lineage` cascades on `jobs.job_id`, so the lineage chain is severed at the same
   moment.

Two earlier decisions are validated by this and must not be revisited: `bluescrub_baselines.job_id` is
`SET NULL` (the frozen snapshot survives), and `bluescrub_score_history` carries **no** foreign key
(history survives).

### Resolution — a triage ledger outside the job lifecycle

Add `bluescrub_triage_ledger` (§4.3). Triage state is written there as well as to `Finding`, keyed by
`(project_id, finding_id)` with no FK to `jobs`. Carry-forward reads the **ledger**, never a prior
job's rows.

This is strictly better than the alternative of exempting `code_artifact` jobs from
`cleanup_old_jobs`: it requires no change to platform cleanup (which is not on the §5.4 allowlist), it
makes carry-forward independent of retention entirely, and it removes the concurrency hazard of two
scans racing to read "the latest prior job".

**Accepted consequence:** job-level detail (evidence, snippets, per-job scores) still expires at the
platform's 30-day setting, like every other job type. BlueScrub does not change platform retention
behavior. What survives is exactly what needs to: triage decisions, frozen baselines, and score
history. The trends UI must tolerate a `score_history` row whose `job_id` no longer resolves.

---

## 1. Raw normalized finding (G2)

Schema: [`raw-finding.schema.json`](../backend/app/bluescrub/contracts/raw-finding.schema.json)

The adapter maps scanner output into this shape and makes **no scoring decisions**. Resolved
ambiguities:

### 1.1 `issue_family` is a closed vocabulary

Free-text families would make canonicalization non-deterministic. v1 vocabulary:

```
memory-safety · command-injection · path-traversal · deserialization · ssrf · xxe ·
sql-injection · weak-crypto · insecure-random · hardcoded-secret · credential-exposure ·
authz-bypass · unauth-control-channel · hardcoded-c2 · kill-switch · dependency-vulnerable ·
dependency-confusion · typosquat · attribution-marking · attribution-identity ·
attribution-infrastructure · build-path-leak · metadata-leak · forensic-artifact ·
signature-trivial · signature-known · anti-analysis · obfuscation-weak · shellcode-pattern ·
packer-detected · symbol-exposure · string-exposure · import-exposure · decompile-easy ·
iac-misconfig · ci-misconfig · container-misconfig
```

Extending the vocabulary is a versioned change to `bluescrub.raw/N`, reviewed like a schema change.

### 1.2 Unmapped rules

A `(sensor, rule_namespace, rule_id)` with no mapping entry gets
`issue_family: "unmapped"` and `pillar_hint: null`. Unmapped findings are **persisted and displayed but
never scored**, and the count appears in `metrics_json.dacv.unmapped_findings`. Silently discarding
them would hide scanner output; silently scoring them would put an unreviewed rule into the grade.

A non-zero unmapped count is a backlog signal, surfaced in the report.

### 1.3 Pillar assignment is rule-level, never tool-level

The mapping table is keyed on `(sensor, rule_namespace, rule_id)` with an `issue_family` fallback. The
v1.0 `tool → pillar` map was structurally wrong: `semgrep` serves Vulnerability *and* Co-Optability in
this very plan.

### 1.4 Location fields are optional but ordered

`symbol` and `node_kind` are present only when the scanner reports them. Consumers must not require
them. `start_line`/`start_column` are required whenever the finding is file-scoped, because
`occurrence_index` ordering depends on them (§3.3).

---

## 2. Canonical group (G3)

Schema: [`canonical-group.schema.json`](../backend/app/bluescrub/contracts/canonical-group.schema.json)

### 2.1 Grouping key

Two raw findings join the same canonical group when **all** hold:

1. Same `issue_family`.
2. Same `project_id`.
3. Same **location equivalence class**:
   - *Source*: same `relative_path` **and** overlapping line ranges, or the same `symbol` when both
     report one.
   - *Binary*: same `artifact_sha256` **and** same `section` **and** offsets within 64 bytes, or the
     same recovered-function fingerprint.
   - *Project-scoped* (dependency, git metadata, IaC): same `issue_family` and same subject identifier
     (package name + version, commit, file path).

Grouping never crosses `issue_family`. Two genuinely different defects at one line stay separate.

### 2.2 Grouping is deterministic

Raw findings are sorted before grouping by
`(relative_path, start_line, start_column, sensor, rule_id)`. Group membership must not depend on
scanner completion order, or fingerprints become unstable between runs.

### 2.3 Severity precedence (G3)

Raw scanner severity is never used directly. Resolution order, first match wins; the tier used is
recorded in `severity_source`:

| Tier | Source | Note |
|---|---|---|
| 1 | `rule_mapping` | Explicit BlueScrub/AIPAM canonical severity for that rule |
| 2 | `impact_modifier` | Reachability, secret validity, exposure, execution path — may raise **or lower** tier 1 by at most one level |
| 3 | `precedence` | Detector-class table below, applied to the members' calibrated severities |
| 4 | `fallback` | Highest calibrated member severity |

**Detector-class precedence** (tier 3), highest authority first:

```
semantic_dataflow  >  taint  >  ast_pattern  >  regex_pattern  >  heuristic
```

A `regex_pattern` detector claiming `critical` does not outrank a `semantic_dataflow` detector claiming
`medium`. Class is declared per rule in the mapping table, not per tool — one tool can own rules in
several classes.

### 2.4 Scoring confidence

```
scoring_confidence = calibrated confidence of the highest-precedence qualifying detector in the group
```

Selected by the **versioned precedence table**, not by whichever member reports the highest number.
This is what keeps the score invariant under optional-tool installation.

Corroborating members are recorded and displayed. **They do not affect `severity` or
`scoring_confidence` in v1.** A future calibrated bonus is bounded at +0.10 and requires a fixed
scanner manifest plus a demonstration that the detectors are independent — two wrappers over one engine
are not.

---

## 3. Fingerprints (G4) — scheme `fp/2`

The scheme identifier is stored on every finding. v1.0's scheme was wrong twice; a third revision is
plausible, and without a version field that migration orphans every triage decision in the system.

### 3.1 Source

```
fp/2:source = sha1(
  project_id | rule_namespace | rule_id | relative_path |
  enclosing_symbol | node_kind | normalized_tokens | context_hash | occurrence_index
)[:16]
```

### 3.2 Binary

```
fp/2:binary = sha1(
  project_id | rule_id | format | architecture | section |
  nearest_symbol_or_function_fingerprint | normalized_value
)[:16]
```

Artifact SHA-256, exact offset, and offset bucket live in evidence, never in the key. Including the
artifact SHA meant every rebuild orphaned every binary finding's triage.

### 3.3 Normalization — must be byte-deterministic

Non-deterministic normalization produces unstable fingerprints, which is indistinguishable from a
correctness bug at triage time. Exact rules:

**`normalized_tokens`** — from the matched text:
1. Decode as UTF-8; on failure, latin-1. Apply Unicode NFC.
2. Strip comments using the language's comment syntax; unknown language ⇒ no stripping.
3. Collapse all runs of whitespace to a single U+0020; strip leading/trailing.
4. Lowercase using ASCII case folding only — never locale-dependent `str.lower()`.
5. Replace integer and string literals with `<num>` and `<str>` so a changed constant does not orphan
   triage.
6. Truncate to 512 bytes.

**`context_hash`** — `sha1` of the three source lines before and after the match, each put through
steps 1–4 above and joined with `\n`. Fewer than three available lines at file boundaries is not
padded.

**`occurrence_index`** — assigned after the deterministic sort in §2.2, counting only findings that are
identical in every other fingerprint component. First occurrence is `0`.

### 3.4 Collision handling

`findings` carries `UniqueConstraint("job_id", "finding_id")`, so a fingerprint collision raises
`IntegrityError` rather than merging rows. The persistence layer must distinguish:

- **Legitimate re-run** — same job re-persisting the same finding ⇒ upsert (§4).
- **Defective fingerprint** — two *different* canonical groups producing one key within a single job
  ⇒ log at ERROR with both groups' locations, assign a `-dup<N>` suffix so the job completes, and
  count it in `metrics_json.dacv.fingerprint_collisions`.

A non-zero collision count is a defect signal, not a warning to ignore.

---

## 4. Persistence (G5)

### 4.1 Upsert field ownership

One `Finding` per canonical group. On `(job_id, finding_id)` conflict:

| Scanner-owned — overwritten | Analyst-owned — never overwritten |
|---|---|
| `severity`, `category`, `title`, `summary` | `analyst_status` |
| `confidence`, `evidence_json` | `analyst_notes` |
| `evidence_status`, `corroboration_score` | `reviewed_at`, `reviewer_id` |
| `corroborating_sources_json` | `feedback`, `explanation_feedback` |

Implemented as an explicit `INSERT … ON CONFLICT DO UPDATE SET <scanner-owned only>`. The
SELECT-then-skip pattern used by `binalysis` is racy under the unique constraint; `binalysis` itself is
not modified.

### 4.2 Write order

Within a job: canonicalize all → score → open transaction → upsert findings → write
`metrics_json` → write `score_history` → commit. A job never presents findings without the scorecard
that explains them.

### 4.3 Triage ledger (new, per §0)

```python
class BlueScrubTriageLedger(Base):
    __tablename__ = "bluescrub_triage_ledger"
    project_id   = Column(String, primary_key=True)   # no FK to jobs — survives job deletion
    finding_id   = Column(String, primary_key=True)
    status       = Column(String, nullable=False)     # unreviewed|confirmed|false_positive|
                                                      # needs_review|deferred
    notes        = Column(Text, nullable=True)
    rule_version = Column(String, nullable=True)      # rule version at the time of the decision
    fingerprint_scheme = Column(String, nullable=False)
    decided_at   = Column(String, nullable=False)
    decided_by   = Column(String, nullable=True)      # self-asserted — see G9
    origin_job_id = Column(String, nullable=True)     # provenance only, may dangle
```

**Carry-forward algorithm** at persist time, for a job with a `project_id`:

1. Look up `(project_id, finding_id)` in the ledger.
2. No row ⇒ `analyst_status = "unreviewed"`.
3. Row found, `fingerprint_scheme` matches, `rule_version` unchanged ⇒ apply the status, set
   `triage_carry.match = "exact"`.
4. Row found but `rule_version` changed materially ⇒ apply the status **and** set
   `triage_carry.requires_review = true`, `match = "ambiguous"`. The prior disposition is context, not
   a decision on the new rule.
5. `fingerprint_scheme` differs ⇒ no carry-forward; `match = null`.

Ad-hoc jobs (no `project_id`) neither read nor write the ledger.

---

## 5. Project identity and lineage (G6)

### 5.1 `project_id` assignment

Generated UUID, created explicitly via `POST /bluescrub/projects` or implicitly when a job is bound to
a new project name. **A slug or archive basename is never the identity** — two projects can share a
filename, and renaming an archive would silently split a project's history.

`display_name` is renameable and carries no behaviour.

### 5.2 Lineage is bound at job creation

```python
lineage_parent_job_id = <latest completed job for this project at enqueue time, or NULL>
```

Resolved **once, at creation**, and stored. Two concurrent scans of one project therefore inherit from
the same parent deterministically, rather than racing on "whichever finished last".

With the triage ledger (§4.3), lineage is provenance rather than a functional dependency — carry-forward
no longer needs the parent job to exist. This is what makes the design survive job deletion.

### 5.3 Ad-hoc jobs

Permitted (`AIPAM_BLUESCRUB_ALLOW_ADHOC`, default true). `project_id` is `NULL`; carry-forward,
baselines, and trends are disabled. `PUT /bluescrub/jobs/{job_id}/project` binds retroactively: it sets
`project_id`, resolves `lineage_parent_job_id` as of that moment, and enables carry-forward **from that
point forward**. It does not retroactively re-triage the already-persisted findings, and it does not
re-scan.

---

## 6. Derived child jobs (G8)

### 6.1 Lifecycle

`POST /bluescrub/re_feasibility/{parent_job_id}/{file_id}`:

1. Validate that `file_id` exists in the parent's `extracted_files/manifest.json`.
2. Copy — never move or link — the artifact into the child's `input/binaries/`. The parent's
   `extracted_files/` is not touched, not read-locked, and not modified.
3. Create a job with `source_type = "code_artifact"`, `execution_profile = "deep"`,
   `analysis_kind = "re_assessment"`.
4. Write lineage: `derived_from_job_id`, `derived_from_file_id`, `artifact_sha256`.
5. Return `202` with the child `job_id`. The caller polls the normal job endpoints.

### 6.2 Invariants

- The parent job's row, directory, findings, and `metrics_json` are **not written to**. Asserted by a
  test that hashes the parent's DB row and directory tree before and after.
- The child scores **only** the RE-Feasibility pillar. All others are `not_assessed`. `overall.grade`
  is therefore always `null` for a child job; only `scoped` is populated.
- The child inherits `project_id` from the parent **only if the parent has one**. A PCAP job normally
  does not, so most child jobs are ad-hoc.
- Parent deletion by retention does not delete the child. `derived_from_job_id` may dangle; the UI
  renders "parent expired" rather than erroring.
- Multiple children per parent file are allowed; each is an independent job.

### 6.3 `analysis_kind`

| Value | Meaning |
|---|---|
| `source_audit` | Full DACV+R over an uploaded code artifact |
| `re_assessment` | RE-Feasibility only, over a single binary |

Stored in `bluescrub_job_lineage.analysis_kind` and echoed into `metrics_json.dacv.analysis_kind`.

---

## 7. Acceptance

1. Two scanners reporting one buffer overflow at the same location produce one canonical group with
   both listed; the Vulnerability score is identical with either scanner alone.
2. Two identical vulnerable statements in one function produce two findings with
   `occurrence_index` 0 and 1, and both persist.
3. Inserting an unrelated line above a finding leaves its fingerprint unchanged.
4. Changing an integer literal inside a matched expression leaves the fingerprint unchanged
   (literals normalize to `<num>`).
5. Rebuilding a binary changes its SHA-256 but not its binary finding fingerprints.
6. Grouping output is byte-identical across two runs with scanners completing in different orders.
7. Triage survives deletion of every prior job for the project.
8. An unmapped rule is persisted, displayed, excluded from scoring, and counted.
9. A deliberate fingerprint collision within one job is logged, suffixed, counted, and does not fail
   the job.
10. A parent PCAP job's DB row and directory hash identically before and after a child RE assessment.
