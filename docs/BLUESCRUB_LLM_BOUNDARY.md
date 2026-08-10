# BlueScrub — LLM Narrative Boundary (G11)

> **Gate item**: G11 · **Status**: proposed
> **Governs**: the narrative stage and knowledge-base indexing for `code_artifact` jobs
> **Plan reference**: [BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md](BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md) §11

## 1. Threat

Every byte BlueScrub analyses was written by someone who wants their tooling to evade analysis. Source
comments, README files, build scripts, commit messages, variable names, and recovered strings are all
attacker-authored and all plausible carriers for instructions aimed at the narrative model.

Two distinct exposures:

1. **Prompt injection** — content in the artifact attempts to redirect the narrative: suppress a
   finding, downgrade a severity, or induce tool use.
2. **Persistent capture** — `auto_index_job` writes content into a long-lived vector store that sits
   *outside* the job retention lifecycle, so offensive source and recovered secrets survive every purge
   described in [BLUESCRUB_DATA_HANDLING_POLICY.md](BLUESCRUB_DATA_HANDLING_POLICY.md).

The second is the more serious of the two and the easier to overlook: it is a silent, permanent copy of
the most sensitive data in the system, created as a side effect of an existing pipeline stage.

## 2. Rules

### R1 — Findings in, not repositories in
The narrative model receives canonical groups validated against
[`canonical-group.schema.json`](../backend/app/bluescrub/contracts/canonical-group.schema.json) plus the
`dacv` metrics object. It never receives a file tree, a whole file, or raw scanner output. Snippets are
the size-capped `code` field from the evidence envelope (≤ 4 KiB), nothing more.

### R2 — Evidence is fenced and labelled
Untrusted content is wrapped in explicit delimiters, and the system prompt states that text inside them
is data to be described and never instructions to follow:

```
<untrusted-evidence finding_id="bs-attribution-dirty-word-a1b2c3d4e5f60718">
…snippet…
</untrusted-evidence>
```

The delimiter token is generated per request and included in the system prompt, so evidence cannot close
its own fence by containing the literal string.

### R3 — No tools
The narrative stage runs with an empty tool set. It cannot read files, trigger scans, query the
database, or make network calls. Injected instructions have nothing to actuate.

### R4 — Every claim is sourced
Each narrative statement carries the `finding_id` it derives from. A post-validation pass drops any
sentence whose cited id is not in the input set, and drops the narrative entirely if more than 20% of
claims fail. Validation failure is reported as `narrative: {status: "rejected", reason: …}` — the report
renders without a narrative rather than with an unvalidated one.

### R5 — Deterministic and generated content stay separate
`severity_rationale` (produced by the scoring engine) and the LLM interpretation are distinct fields in
the API and distinct blocks in the UI. They are never concatenated. An operator must always be able to
tell which claims are mechanical and which are inferred.

### R6 — Secrets never reach the model
Masking happens at normalization, before the narrative stage. The model sees `masked_value` and
`fingerprint`. Asserted by the same canary test used in the data-handling policy.

### R7 — Provenance recorded
Model id, prompt-template version, `scoring_model`, and input finding-id set are stored with the
narrative, so a suspect narrative can be traced to the exact inputs and template that produced it.

### R8 — Output is untrusted for rendering
Narrative text is rendered inert, exactly like evidence. A model that has been fed HTML or script from
a source file may reproduce it.

## 3. Indexing policy

**`auto_index_job` does not run for `code_artifact` jobs by default.**

Enabling it requires `AIPAM_BLUESCRUB_INDEX_SOURCE=true`, and even then:

- Findings carrying a `secret` block are excluded entirely.
- Only canonical findings and their capped snippets are indexed — never whole files.
- Indexed content honours the retention policy: the retention sweep removes the corresponding vector
  entries, so indexing cannot outlive the artifact it came from.
- The `agent/health` response reports whether source indexing is enabled, so the exposure is visible
  rather than buried in configuration.

The default is off because the vector store's lifetime is decoupled from the job's. Everything else in
BlueScrub's data handling assumes an expiry; indexing quietly opts out of it.

## 4. Acceptance

1. A fixture repository containing injection strings in comments, a README, a commit message, and a
   Dockerfile produces a narrative that describes them as findings and follows none of them.
2. The narrative stage has an empty tool set; an attempt to invoke a tool from it fails by construction,
   not by refusal.
3. A narrative citing an unknown `finding_id` has that claim dropped; one citing mostly unknown ids is
   rejected wholesale and the report renders without it.
4. A canary secret in a fixture never appears in narrative input or output.
5. With `AIPAM_BLUESCRUB_INDEX_SOURCE` unset, a `code_artifact` job writes nothing to the vector store.
6. With it set, a retention purge removes the corresponding vector entries.
7. Evidence containing the literal delimiter string cannot break out of its fence.
8. `severity_rationale` and LLM interpretation are separately addressable in the API response.
