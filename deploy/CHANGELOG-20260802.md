# AIPAM Update — 2026-08-02

Changes since the previously shipped package, **`aipam-code-update-20260726`**
(cut 2026-07-26 18:38, at commit `08691ec`).

Two themes: uploaded logs now corroborate and confirm PCAP detections, and the
capture-parsing stages no longer lose data on large or connection-dense PCAPs.

---

## 1. Uploaded logs corroborate and confirm detections

Previously the Correlations tab was dominated by Zeek and Suricata rows and
uploaded logs rarely appeared. Two causes, both fixed.

**Zeek/Suricata were correlating with themselves.** Since the previous package,
`normalize_network_events` mirrors Zeek/Suricata records into
`normalized_events` so the Raw Events explorer works for plain captures. The
temporal correlator treated that table as "the log side" and `connections` /
`alerts` as "the PCAP side" — but both are built from the *same* sensor records,
so every flow matched itself on an identical `community_id` at a zero time
delta. Those perfect scores filled the 5,000-row per-job cap and buried the real
uploaded-log matches. The log side now excludes PCAP-derived rows.

**Findings are now a correlation counterparty.** Previously only alerts and
connections were, and `findings` carried no timestamp or IPs to match on — the
sensor emitted them and normalization discarded them. Findings now keep `ts`,
`src_ip` and `dest_ip`, and match on a widened time window because a finding is
an aggregate rather than a point-in-time packet.

**New evidence lifecycle on findings:**

| uploaded source matching a finding | result |
|---|---|
| C2 operator log (`c2_callback` / `c2_task`, or a `c2_bundle` source) | `confirmed`, confidence 1.0 |
| any other log — EVTX, router, firewall, proxy | `corroborated`, confidence raised by match strength |
| nothing | unchanged (`observed`) |

Confirmation requires the match to actually score well (≥ 0.45), not merely
share a host IP somewhere inside the window — on a busy victim host every event
overlaps every finding, and confirming all of them confirms nothing.

**UI:** findings list and detail pages show `GROUND TRUTH` / `CORROBORATED`
badges naming the attesting sources; the Correlations tab renders and links the
new `finding` counterparty.

**Schema:** `findings` gains `ts`, `src_ip`, `dest_ip`, `evidence_status`,
`corroboration_score`, `corroborating_sources_json`. Applied automatically on
first start by the existing drift-healer — no manual migration. Additive only;
existing rows backfill to `observed`.

## 2. Capture stages no longer lose data

**PCAP label collision — silent data loss.** Files were staged as
`input/<label>.pcap`, but a phase label is deliberately shared across captures.
A job with three `during` PCAPs staged only the first and silently dropped the
other two, then reported success. Files are now staged as
`input/<label>-<ordinal>.pcap` with the label recorded in `input/pcaps.json`.
Jobs staged by earlier versions keep working unchanged.

**Fixed timeout killed healthy work.** Zeek and Suricata were hardcoded to
1200 s, ignoring the 1800 s their own config declared. Cost tracks connection
count, not file size — a 1.4 GB capture of a few large flows finishes in
~3 seconds while a 616 MB capture of ~190k short connections needs ~30 minutes —
so any fixed limit is either too tight or too slack. Replaced with a stall
watchdog: the process is killed only when it stops making progress (5 min), with
an absolute ceiling as backstop. Progress is logged each minute, so a long run
reads as slow rather than hung. Ceilings raised to 5400 s.

**A failed stage no longer aborts the job.** Zeek timing out discarded the
Suricata alerts, every uploaded log, and all downstream correlation. Suricata
does not depend on Zeek and neither does the log pipeline, so the job now
continues and reports `completed_with_errors`; only sensors declaring
`inputs_required` on the failed stage are skipped, with the reason recorded.
Partial Zeek output is preserved on disk for inspection but never promoted into
findings.

**Zeek result parsing streams.** Records went into memory as a list, twice, before
anything was written. Measured on 115,609 real records: peak Python memory drops
from 130 MB to 20 MB with identical output.

## 3. Log uploads bounded by size, not file count

Log correlation gets its value from stacking independent perspectives, and file
count limits were the thing preventing that.

| | before | after |
|---|---|---|
| log files per job (UI) | 5 | unlimited |
| files per archive | 5,000 | unlimited |
| size per log file | 2 GB | 512 MB |
| total logs per job | unbounded | 10 GB |

The per-job budget is checked before extraction, so a rejected job leaves no
partial staging. The generic log parser silently truncated every file at 5,000
events — a 512 MB syslog kept only its first 5,000 lines. Raised to 500,000 and
truncation is now logged rather than silent.

## 4. Smaller fixes

- **Host conversations** (`#14`, commit `9080bac`): a host's Streams tab listed
  only conversations where it was the source, omitting destination-side ones.
  *Already shipped as hot-patch `20260728`* — included here so the package is
  self-contained. If that hot-patch is applied, this is not a new change; if it
  was never applied, this package delivers it. Either order is safe.
- Job source-type detection tested for `c2_export` / `netflow`, but the enum
  values are `c2_bundle` / `netflow_bundle`, so those job types missed the
  telemetry stage except via an on-disk fallback.
- The telemetry stage progress message always read `parsed=0 correlated=0` — it
  read result keys that the pipeline does not return.
- `openapi.yaml`: the Findings section is resynced against the implementation —
  `FindingItem` documented 5 of its 17 fields; nine schemas and five endpoints
  were missing entirely.
- `vite.config.ts`: the dev-server API proxy target is overridable via
  `VITE_API_PROXY_TARGET` (default unchanged).

---

## Upgrade notes

Standard procedure — nothing special required:

```bash
cd ~/aipam-code-update
./update.sh --check-only     # diagnostics only, no changes
./update.sh                  # apply
```

- **Database migration is automatic** on first API start (additive columns only).
- **No model update** — this is a code-only package; the deployed model is unchanged.
- **Existing jobs are unaffected.** New `findings` columns backfill to `observed`;
  correlation rows are written during analysis, so previously-analysed jobs show
  no ground-truth badges until re-run.
- **Re-running a multi-PCAP job is worth it** if any of its captures shared a
  phase label — earlier versions analysed only the first of them.
