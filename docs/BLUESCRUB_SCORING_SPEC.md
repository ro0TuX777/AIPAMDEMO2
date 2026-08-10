# BlueScrub — Scoring Specification (G7)

> **Gate item**: G7 · **Status**: proposed, constants provisional until Sprint 9 calibration
> **Schema**: [`dacv-metrics.schema.json`](../backend/app/bluescrub/contracts/dacv-metrics.schema.json)
> **Plan reference**: [BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md](BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md) §3, §4

`scoring_model` for this specification is **`dacvr/1.1`**. Any change to a formula, constant, cap, or
weight in this document requires a new model version, because scores across versions are not comparable
(§6).

---

## 0. Gate finding — two pillars, two models

The plan gives a saturating finding-accumulation formula "for each pillar" (§3.1) and a completely
different weighted-signal formula for RE-Feasibility (§4.2). Both are correct for their subject; the
plan never says they coexist, which would leave an implementer to pick one.

Made explicit here:

| Pillar | Model | Why |
|---|---|---|
| Detectability, Attribution, Co-Optability, Vulnerability | **Accumulation** (§1) | Score reflects how much evidence of exposure accumulated |
| RE-Feasibility | **Signal** (§4) | Score reflects a fixed set of measured properties of one artifact, most of which are present-or-absent rather than countable |

`K_P` applies only to accumulation pillars. RE-Feasibility has no `K`.

---

## 1. Accumulation model

```
sev_weight    = {critical: 10, high: 6, medium: 3, low: 1, info: 0.25}

group_contrib = sev_weight[g.severity] × g.scoring_confidence      # canonical groups only
pillar_raw    = Σ capped(group_contrib)                            # §2
pillar_score  = round(100 × (1 − exp(−pillar_raw / K_P)))
```

Inputs are **canonical groups** (`scored: true`), never raw scanner hits. Unmapped groups are excluded
and counted separately.

### 1.1 `K_P` — provisional constants

A single `K` across pillars is wrong: pillars differ by an order of magnitude in typical finding count,
so a shared constant makes high-volume pillars saturate at trivial severity and low-volume pillars never
move.

| Pillar | `K_P` | Rationale |
|---|---|---|
| Attribution | **15** | Low volume, high consequence. One operator handle should move the score decisively. |
| Co-Optability | **20** | Low volume; findings are structural rather than incidental. |
| Detectability | **25** | Moderate volume; many weak signals, some strong. |
| Vulnerability | **40** | Highest volume by far — a medium repo yields dozens of legitimate findings, and a handful of mediums must not read as catastrophic. |

**These are provisional.** Sprint 9 calibrates them against a labelled corpus of at least 20 artifacts
with analyst-assigned OPSEC grades, minimising disagreement between computed and assigned grade. Until
then, reports carry `"calibration": "provisional"` and the UI states that pillar scores are directionally
meaningful but not yet calibrated.

### 1.2 Worked example

Attribution, `K = 15`, three groups:

| Finding | Severity | Confidence | Contribution |
|---|---|---|---|
| Operation codename in `.rdata` | critical | 0.95 | 9.50 |
| Author email in git history | high | 0.88 | 5.28 |
| Internal hostname in a comment | medium | 0.70 | 2.10 |

```
pillar_raw   = 16.88
pillar_score = round(100 × (1 − exp(−16.88 / 15))) = 68
```

Adding a second overlapping scanner that also reports the codename changes nothing: it joins the
existing canonical group as a corroborating sensor and does not alter `severity` or
`scoring_confidence`.

---

## 2. Contribution caps

Volume must not substitute for severity, and one noisy rule must not own a pillar.

### 2.1 Per-rule cap

The first **5** groups sharing a `rule_id` contribute at full weight. For the *n*-th such group where
`n > 5`:

```
damped_contrib = group_contrib / (1 + ln(n − 4))
```

Groups are ordered by `group_contrib` descending before damping, so the most severe instances count in
full. The 6th contributes at 100%, the 10th at ~38%, the 50th at ~21%.

### 2.2 Per-family cap

No single `issue_family` may exceed **35%** of a pillar's `pillar_raw`. Excess is discarded and the
groups are flagged `capped_by: "family_cap"`. Capping is applied after per-rule damping.

### 2.3 `info` cap

`info` severity findings contribute at most **10%** of a pillar's `pillar_raw` in aggregate.

`info` is retained rather than dropped because the dirty-word category ladder legitimately uses it —
a stale build path is weak but real attribution signal, and removing the tier would make the pillar
discontinuous at the bottom.

### 2.4 Cap transparency

Every capped group records `capped_by`, and `metrics_json` reports
`caps_applied: {rule_cap: N, family_cap: N, info_cap: N}`. A scorecard that quietly discards evidence
is worse than one that scores it.

---

## 3. Coverage

Each pillar declares, per profile, a set of **required detectors**. Coverage is the fraction that
reached a terminal successful state:

```
coverage = |detectors with status ∈ {completed, completed_truncated}| / |required detectors|
```

`completed_truncated` counts toward coverage but forces the pillar to `degraded`, because the finding
set is known to be incomplete.

| Pillar status | Condition |
|---|---|
| `assessed` | `coverage == 1.0` and no member `completed_truncated` |
| `degraded` | `0 < coverage < 1.0`, or any truncation, or any stale ruleset |
| `not_assessed` | `coverage == 0`, or the profile excludes the pillar |

A `not_assessed` pillar has `score: null`. **Never zero.** Zero means "measured, nothing found"; null
means "not measured", and conflating them is what let a v1.0 Quick scan grade an unassessed pillar as
clean.

Optional detectors — those that only corroborate — do not affect coverage. This is deliberate: coverage
must not change when an optional tool is installed, for the same reason scoring must not (§5).

---

## 4. RE-Feasibility signal model

```
available_weight = Σ weight_s              for signals with status ∈ {completed, completed_truncated}
re_score         = round(100 × Σ (weight_s × signal_score_s) / available_weight)
coverage         = available_weight        (weights sum to 1.0 when all signals run)
```

Signal weights are fixed in plan §4.1 and **never redistributed**. The divisor normalizes over what
ran so the score stays on a 0–100 scale, but each absent signal is reported in `unavailable_signals`
with its weight and reason, and the pillar drops to `degraded`.

The distinction matters: normalizing the *scale* keeps the number readable, whereas redistributing the
*weights* would silently reassign a missing signal's importance to the signals that happen to be
installed — making the same binary score differently on two hosts.

Each `signal_score_s ∈ [0,1]` is produced by a documented per-signal rubric with the anchors in plan
§4.1. Effort bands: 76–100 Trivial · 51–75 Hours · 26–50 Days · 0–25 Weeks. A `degraded` RE pillar
displays the band with an explicit partial-assessment marker.

---

## 5. Machine-independence invariant

> **Installing or removing an *optional* scanner must not change any pillar score, coverage value, or
> grade for an unchanged artifact.**

This is the single property the whole scoring design protects, and it is what motivates four otherwise
unrelated decisions: canonicalization before scoring, corroboration having no numeric effect,
precedence-table detector selection rather than highest-confidence-wins, and fixed RE weights.

Only **required** detectors move the numbers, and their absence moves coverage rather than score.
Asserted by acceptance test 16 in the plan.

---

## 6. Comparability signature

Baselines and trends compare only where signatures match. SHA-256 over the canonical JSON of:

```jsonc
{
  "profile": "deep",
  "scoring_model": "dacvr/1.1",
  "fingerprint_scheme": "fp/2",
  "canonicalization_version": "canon/1",
  "scanner_manifest_digest": "sha256:…",   // required detectors + versions, sorted
  "ruleset_versions_digest": "sha256:…",   // rule pack + DB versions, sorted
  "required_scanner_availability": ["semgrep", "gitleaks", "…"],
  "pillar_scope": ["Detectability", "Attribution", "Vulnerability"],
  "coverage_threshold": 0.9,
  "config_hash": "sha256:…"                // scoring-relevant config only
}
```

`config_hash` covers only settings that change results — caps, `K_P`, wordlist content digest, profile
gating. It excludes operational settings such as worker count and timeouts, which would otherwise make
every tuning change break comparability.

| Comparison | Allowed |
|---|---|
| Quick ↔ compatible Quick | Yes, explicitly scoped |
| Standard ↔ compatible Standard | Yes, explicitly scoped |
| Deep complete ↔ compatible Deep complete | Yes — the artifact-level DACV+R baseline |
| Quick ↔ Deep | No |
| Degraded ↔ fully provisioned | No |
| Differing scoring model or canonicalization version | No, unless recalculated |

A rejected comparison returns `incomparable` **with the differing field named**. "Incomparable" without
a reason is an error message users cannot act on.

---

## 7. Grades

Overall weights: Detectability 0.25 · Attribution 0.25 · Vulnerability 0.20 · Co-Optability 0.15 ·
RE-Feasibility 0.15. Bands: A 0–19 · B 20–39 · C 40–59 · D 60–79 · F 80–100.

`overall.grade` is computed **only** when every pillar is `assessed` and every coverage ≥ 0.9. Weights
therefore always sum to 1.0 and no renormalization case exists.

Otherwise `overall.status = "incomplete"`, `overall.score = null`, `overall.grade = null`, and `scoped`
carries a grade over the assessed pillars with `pillars_assessed` / `pillars_total` and a label. The two
objects are structurally separate so a client that does not understand the distinction cannot render a
scoped grade as an artifact grade.

### 7.1 Critical attribution override

Any `critical` Attribution group sets:

```jsonc
{ "grade": "F", "disqualified": true,
  "grade_override": { "finding_id": "…", "reason": "critical_attribution_exposure" } }
```

The override applies to `scoped` as well as `overall` — a Quick scan that finds a classification
marking must not report "Quick profile: B". `disqualified` is a top-level boolean so it cannot be
missed by a client reading only the summary.

---

## 8. Acceptance

1. Adding an overlapping optional scanner leaves every score, coverage value, and grade unchanged.
2. 200 findings from one noisy rule produce a lower pillar score than 20 critical findings across
   distinct rules.
3. A pillar with no detectors run reports `score: null`, not `0`, and no grade is computed.
4. Removing Ghidra changes RE coverage to 0.85 and the status to `degraded`, and leaves the other seven
   signals' contributions numerically unchanged.
5. A Quick scan finding a classification marking reports `disqualified: true` and grade F, not "B".
6. Comparing a Quick scan to a Deep baseline returns `incomparable` naming `profile` as the differing
   field.
7. Two runs of the same artifact on hosts with different *optional* tooling produce identical scores.
8. Every capped group carries `capped_by`, and the report totals match the per-group flags.
