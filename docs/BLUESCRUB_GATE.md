# BlueScrub — Architecture Gate

> **Branch**: `spike/bluescrub-contracts` · **Status**: contracts drafted, **review not signed off**
> **Exit criterion**: all eleven contracts reviewed and merged. **No implementation code.**
> **Plan**: [BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md](BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md) §1

> ## ⚠ This gate did not hold
>
> The line below used to read "Sprint 1 does not open until this gate closes."
> Sprints 1 through 5 have shipped and every checkbox in the review checklist is
> still empty, including both items marked as blocking. Leaving the original
> sentence in place would have made this document assert something untrue about
> how the work actually happened, so it is recorded here instead.
>
> **What that means in practice.** The contracts were used as designed — the
> implementation follows them closely and several of them caught real defects
> during Sprint 5 — but nobody with authority has signed them off, so their
> authority is self-asserted. Where implementation and contract disagreed, the
> contract won and was amended in the same commit; those amendments are also
> unreviewed.
>
> **The two blocking items are still unanswered**, and one of them has already
> been overtaken:
>
> - **Semgrep rule licensing (G10)** was to be resolved *before Sprint 1*
>   because Semgrep was the Sprint 1 vertical slice. Sprint 1 shipped with a
>   BlueScrub-authored rule pack instead of registry rules, which sidesteps the
>   licensing question rather than answering it. It becomes live again the
>   moment anyone points `AIPAM_BLUESCRUB_SEMGREP_CONFIG` at the registry.
> - **Accepting the retention consequence (G9)** — job-level evidence expires
>   at the platform's 30-day setting. This has been implemented on the
>   assumption the answer is yes. If it is no, the triage ledger, baselines and
>   score history are unaffected, but snippets and per-job detail are already
>   being written on that assumption.
>
> The four questions waiting on a person — these two plus the gate's own
> disposition and a real-artifact review — are gathered with their evidence in
> [BLUESCRUB_OPEN_DECISIONS.md](BLUESCRUB_OPEN_DECISIONS.md).
>
> **Recommended disposition.** Do not retro-tick the boxes. Either run the
> review now against the shipped implementation — which is a stronger review
> than the paper one would have been, because the contracts have been tested —
> or convert this document into a post-hoc design record and drop the gate
> framing. What should not persist is a gate that says work cannot start on
> work that has finished.

## Deliverables

| # | Gate item | Artifact | State |
|---|---|---|---|
| G1 | Analyzer process isolation | [BLUESCRUB_ISOLATION_CONTRACT.md](BLUESCRUB_ISOLATION_CONTRACT.md) | Drafted |
| G2 | Raw normalized finding | [`raw-finding.schema.json`](../backend/app/bluescrub/contracts/raw-finding.schema.json) · [DATA_CONTRACTS §1](BLUESCRUB_DATA_CONTRACTS.md) | Drafted |
| G3 | Canonical group + severity normalization | [`canonical-group.schema.json`](../backend/app/bluescrub/contracts/canonical-group.schema.json) · [DATA_CONTRACTS §2](BLUESCRUB_DATA_CONTRACTS.md) | Drafted |
| G4 | Fingerprint scheme `fp/2` | [DATA_CONTRACTS §3](BLUESCRUB_DATA_CONTRACTS.md) | Drafted |
| G5 | Persistence and upsert semantics | [DATA_CONTRACTS §4](BLUESCRUB_DATA_CONTRACTS.md) | Drafted |
| G6 | Project identity and lineage | [DATA_CONTRACTS §5](BLUESCRUB_DATA_CONTRACTS.md) | Drafted |
| G7 | Coverage-aware scoring + comparability | [BLUESCRUB_SCORING_SPEC.md](BLUESCRUB_SCORING_SPEC.md) · [`dacv-metrics.schema.json`](../backend/app/bluescrub/contracts/dacv-metrics.schema.json) | Drafted |
| G8 | Derived child jobs | [DATA_CONTRACTS §6](BLUESCRUB_DATA_CONTRACTS.md) | Drafted |
| G9 | Retention, secrets, access | [BLUESCRUB_DATA_HANDLING_POLICY.md](BLUESCRUB_DATA_HANDLING_POLICY.md) | Drafted |
| G10 | Offline provenance | [BLUESCRUB_SUPPLY_CHAIN.md](BLUESCRUB_SUPPLY_CHAIN.md) · [`tool-manifest.schema.json`](../backend/app/bluescrub/contracts/tool-manifest.schema.json) | Drafted |
| G11 | LLM narrative boundary | [BLUESCRUB_LLM_BOUNDARY.md](BLUESCRUB_LLM_BOUNDARY.md) | Drafted |

Shared: [`evidence-envelope.schema.json`](../backend/app/bluescrub/contracts/evidence-envelope.schema.json).

---

## Findings that changed the plan

The gate's purpose is to surface what a plan review cannot. Three items did.

### 1. Job retention deletes the carry-forward source — **new table required**

`aipam.prune_old_jobs` runs daily and calls
[`cleanup_old_jobs`](../backend/app/services/cleanup.py#L15), which deletes the **whole job** — row and
directory — at `aipam_job_retention_days` (default 30). `Finding` cascades.

The plan's retention model assumed findings outlive staged source. They do not. Triage carry-forward,
which reads the prior job's `Finding` rows, would have **silently stopped working** for any project
scanned less often than monthly — presenting as "triage keeps resetting", with no error anywhere.

**Resolution:** `bluescrub_triage_ledger`, keyed `(project_id, finding_id)` with no foreign key to
`jobs`. Carry-forward reads the ledger. This needs no change to platform cleanup, makes carry-forward
independent of retention, and removes the concurrency hazard of racing to read "the latest prior job".
Details in [DATA_CONTRACTS §0 and §4.3](BLUESCRUB_DATA_CONTRACTS.md).

Two earlier decisions are validated by this and must not be revisited: `bluescrub_baselines.job_id` is
`SET NULL`, and `bluescrub_score_history` has no foreign key. Both survive job deletion; had either
cascaded, baselines and trends would have quietly emptied at 30 days.

### 2. Two pillars, two scoring models

The plan gives a saturating accumulation formula "for each pillar" (§3.1) and a weighted-signal formula
for RE-Feasibility (§4.2), without stating that both apply. An implementer would have had to guess.
Made explicit in [SCORING_SPEC §0](BLUESCRUB_SCORING_SPEC.md): accumulation for four pillars, signal
model for RE-Feasibility, `K_P` applies only to the former.

### 3. A single `K_P` across pillars is wrong

The plan's default of 25 everywhere makes Vulnerability — an order of magnitude higher in finding
volume — saturate at trivial severity, while Attribution never moves for a single decisive finding.
Per-pillar provisional constants set in [SCORING_SPEC §1.1](BLUESCRUB_SCORING_SPEC.md), to be calibrated
in Sprint 9.

### Smaller specification gaps closed

- `issue_family` is now a **closed vocabulary**; free text would make grouping non-deterministic.
- Unmapped rules are **persisted, displayed, and excluded from scoring**, with a visible count.
  Discarding them hides scanner output; scoring them puts unreviewed rules into the grade.
- Fingerprint normalization is specified byte-exactly (NFC, ASCII case folding, literal masking,
  512-byte truncation) — non-deterministic normalization is indistinguishable from a correctness bug at
  triage time.
- `occurrence_index` ordering is fixed by a deterministic pre-sort, so grouping does not depend on
  scanner completion order.
- Fingerprint collisions within a job are logged, suffixed, and counted rather than failing the job —
  and are distinguished from legitimate re-runs.
- `checksum_mismatch` is the one health state that **blocks** rather than degrades.
- Legal hold protects against the BlueScrub sweep but **not** `cleanup_old_jobs`, because BlueScrub does
  not modify platform cleanup. Documented rather than worked around.

---

## Review checklist

Reviewer signs off per item. The gate closes when all eleven are accepted.

**Unsigned as of Sprint 5.** Every box below is empty and the implementation is
five sprints past it. Where Sprint 5's work bore directly on an item, the
evidence now exists to review it against something real rather than against a
proposal — G1, G2 and G10 in particular. See the notice at the top.

- [ ] **G1** — Every analyzer, including pure-Python ones, runs behind a process boundary. Credential
      scrubbing is allowlist-based, not deletion-based. Failure classes map to pillar degradation, never
      job failure.
- [ ] **G2** — `issue_family` vocabulary is complete enough for R1–R2. Unmapped handling is agreed.
      Pillar assignment is rule-level.
- [ ] **G3** — Grouping key and severity precedence produce the intended collapse on a real overlapping
      example. Corroboration has no numeric effect.
- [ ] **G4** — Normalization is deterministic across platforms. Nothing rebuild-sensitive is in a binary
      key.
- [ ] **G5** — Analyst-owned field list is complete. Collision handling distinguishes defect from retry.
- [ ] **G6** — Project identity is a UUID; lineage binds at creation. Retroactive binding semantics
      agreed.
- [ ] **G7** — Machine-independence invariant holds under the specified rules. Provisional `K_P` values
      accepted for R1. Comparability signature covers the right fields.
- [ ] **G8** — Parent immutability is enforceable and testable. Child job scoring scope agreed.
- [ ] **G9** — Retention tiers, purge token, HMAC custody, and the self-asserted-actor limitation
      accepted.
- [ ] **G10** — Manifest fields sufficient. Semgrep rule licensing resolved **before Sprint 1**, not
      Sprint 4.
- [ ] **G11** — Injection defences adequate. Indexing default-off accepted.

### Blocking items for the reviewer

Two need an answer before Sprint 1 opens, and neither is a technical question:

1. **Semgrep rule licensing** (G10). Semgrep is the Sprint 1 vertical slice and the Co-Optability
   engine. Engine, community registry rules, and Pro rules carry distinct terms. "Semgrep installed"
   does not establish that the intended rules may ship in an air-gapped bundle. If the answer is no, the
   Sprint 1 slice changes tool.
2. **Accepting the retention consequence** (G9). Job-level evidence expires at the platform's 30-day
   setting. Triage, baselines, and score history survive; snippets and per-job detail do not. The
   alternative is changing platform retention, which is out of scope for an additive feature.

---

## What is deliberately not here

- **No implementation code.** The JSON Schemas are declarative contracts and the `contracts/` directory
  contains no Python.
- **No Alembic migration.** The table shapes are specified; the migration lands in Sprint 5 with its
  first consumer, plus `bluescrub_triage_ledger` promoted to Sprint 1 since carry-forward depends on it.
- **No seccomp or AppArmor profiles.** Deferred, and G1 is written so they can be added without changing
  the runner interface.
- **No `K_P` calibration.** Requires a labelled corpus; Sprint 9.
