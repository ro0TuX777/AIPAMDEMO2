# BlueScrub — decisions waiting on a person

Four questions that no amount of implementation answers, gathered in one place
with the evidence needed to settle each. Three have been open since the
architecture gate; all four now cost more to leave open than to close, and the
reasons are specific rather than general.

Each section states what is actually being asked, what is true today, what
happens if the answer is yes, and what happens if it is no — including what
would have to be undone.

---

## 1. Semgrep rule licensing (gate item G10)

**The question.** May Semgrep registry rules be used, and may they ship in an
air-gapped bundle?

**Why it changed this week.** It used to be theoretical. Semgrep 1.175.0 is now
installed and running: 4 findings on the preflight fixture, and the Vulnerability
pillar reaches full coverage for the first time. Pointing
`AIPAM_BLUESCRUB_SEMGREP_CONFIG` at the registry is one environment variable
away, and nothing in the code stops an operator doing it.

**What is true today.** Sprint 1 shipped a BlueScrub-authored pack — three YAML
files, nine rules — which sidesteps the question rather than answering it. The
engine is LGPL-2.1 and freely redistributable. Semgrep-maintained registry rules
are under the Semgrep Rules License v1.0, limited to internal, non-competing,
non-SaaS use, and are **not** bundled.

**If registry rules are permitted:** the pack grows substantially and
Vulnerability coverage improves. The bundle build must then carry the rules
licence and honour its terms, and `ruleset_version` in the manifest has to name
which registry snapshot shipped.

**If they are not:** nothing breaks — this is the current state. What is needed
is a guard so an operator cannot enable them unknowingly, and a note in the
manifest saying so. That guard does not exist today.

**Cost of leaving it open.** Low but non-zero, and it is the kind that surfaces
at the worst moment: at a customer deployment, in an air-gapped bundle, after
somebody set the variable because it made the scan better.

---

## 2. Retention consequence (gate item G9)

**The question.** Is it accepted that job-level evidence — snippets, per-job
detail, raw scanner output — expires at the platform's 30-day
`aipam_job_retention_days`?

**What is true today.** It is implemented on the assumption the answer is yes,
and every scan writes more on that basis. What survives regardless: triage
decisions (`bluescrub_triage_ledger`, no foreign key), frozen baselines
(`job_id` is `SET NULL`), and score history (no foreign key). Those three were
designed specifically to outlive the sweep, and the gate confirmed that decision.

**If yes:** nothing to do. The design already reflects it.

**If no:** the alternative is changing platform retention, which is outside the
§5.4 allowlist and affects every job type, not just BlueScrub. There is no
BlueScrub-local fix — the sweep is `cleanup_old_jobs`, which deletes the job row
and directory together.

**Cost of leaving it open.** Grows monotonically. Every scan writes evidence on
an assumption that has never been confirmed, and the first 30-day boundary is
where an unconfirmed "yes" becomes visible as data that is simply gone.

---

## 3. The architecture gate itself

**The question.** Run the review against the shipped implementation, or convert
the document into a post-hoc design record?

**What is true today.** All eleven items are unsigned and six sprints have
shipped. The document previously asserted "Sprint 1 does not open until this
gate closes", which was untrue; it now carries a notice recording that, rather
than the boxes being retro-ticked.

**The case for reviewing now.** It is a stronger review than the paper one would
have been. Several contracts have been tested against real code and three caught
live defects this week — a binary location the raw-finding schema rejected, a
metrics object that failed its own schema, and a `ruleset_state` value that was
never added to its enum. G1, G2 and G10 in particular can now be reviewed
against evidence rather than intent.

**The case for converting it.** A gate that cannot gate anything is a document
pretending to be a process, and pretending is worse than recording.

**What should not happen:** ticking the boxes without a review. The value was
never the checkbox.

---

## 4. A real artifact, in front of a person who does OPSEC review

**The question.** Are the grades right?

**Why this is the most important one.** Nothing in the codebase can answer it.
Every calibration decision — the severity ladder, the category tiers, the
false-positive filters, the `K_P` constants — was measured against source trees
and synthetic binaries written by the same process that then graded them.

This has already caused one wrong conclusion. Measuring the score against a
414-file defensive application produced "the score does not discriminate";
measuring the low end disproved it, and the working range turned out to match
the intended subject — an implant of five to fifty files — rather than the thing
being measured. One afternoon of measuring the wrong subject produced a wrong
conclusion that was nearly acted on. Six sprints of building against it deserves
a check.

**What it needs.** One real compiled artifact and one analyst's reaction to the
report. Not a corpus, not a study — the first honest reaction will say more than
the next sprint will.

**What it unblocks.** Sprint 9's calibration needs at least 20 labelled
artifacts. That is people-time on a long lead and it is on the critical path for
the only thing that makes the score mean anything. Starting it in Sprint 9 means
discovering in Sprint 9 that it cannot be finished.

---

## Summary

| # | Decision | Cost of delay | Who can settle it |
|---|---|---|---|
| 1 | Semgrep rule licensing | Low, but surfaces at deployment | Whoever owns licence risk |
| 2 | Retention consequence | Grows with every scan | Product owner |
| 3 | Gate: review or convert | Reputational, compounding | Reviewer |
| 4 | Real artifact review | Blocks Sprint 9 entirely | An OPSEC analyst |

Nothing here is a blocker for the current sprint. All four are blockers for
believing the results.
