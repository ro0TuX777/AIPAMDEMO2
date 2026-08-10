# BlueScrub — Offline Provenance and Supply Chain (G10)

> **Gate item**: G10 · **Status**: proposed
> **Schema**: [`tool-manifest.schema.json`](../backend/app/bluescrub/contracts/tool-manifest.schema.json)
> **Plan reference**: [BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md](BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md) §12

Tool presence is not sufficient. A dependency scanner with a nine-month-old vulnerability database
produces a confidently clean report about an artifact full of known CVEs, and nothing in the output
distinguishes that from a genuinely clean result.

---

## 1. The manifest is the source of truth

`deploy/bluescrub/tool-manifest.json`, shipped with the offline bundle and validated at startup. Every
scanner the registry can invoke has exactly one entry. A registry entry with no manifest entry is a
startup error — that is how a tool gets into an air-gapped deployment without provenance.

Each entry carries: name, version, container image **digest** (never only a tag), binary checksum,
licence, redistribution status, ruleset version and checksum, vulnerability-database snapshot date and
checksum, and supported architectures.

### 1.1 Digest pinning

Images are referenced as `image@sha256:…`. A tag is mutable and, in an air-gapped bundle rebuilt six
months later, silently a different tool. `run_sensor`'s existing allowlist check is extended to compare
the digest of the locally loaded image against the manifest; a mismatch is `checksum_mismatch`, and the
scanner is not run.

### 1.2 Staleness without a network

Freshness cannot be checked against an upstream. It is computed from `db_snapshot_date` in the manifest
against `AIPAM_BLUESCRUB_DB_STALE_DAYS` (default 30):

```
age = now − db_snapshot_date
age > threshold          ⇒ database_stale
rule_pack_version older than the bundle's shipped version ⇒ rules_stale
```

`database_stale` does not disable the scanner. It runs, its findings are ingested, the pillar drops to
`degraded`, and the age appears in the report. A stale scanner that still finds real CVEs is useful; a
stale scanner presenting as authoritative is not.

---

## 2. Health states

`/api/v1/bluescrub/agent/health` returns one state per tool:

| State | Meaning | Effect on a job |
|---|---|---|
| `installed` | Present, digest matches, rules and DB current | Normal |
| `missing` | Not installed | Required ⇒ pillar `degraded`/`not_assessed`; optional ⇒ no effect |
| `unhealthy` | Present but a smoke invocation fails | Treated as `missing`, distinct in reporting |
| `incompatible` | Version outside the supported range | Treated as `missing` |
| `database_stale` | Vulnerability DB older than threshold | Runs; pillar `degraded` |
| `rules_stale` | Rule pack older than the bundle | Runs; pillar `degraded` |
| `checksum_mismatch` | Digest or binary checksum differs from manifest | **Refuses to run** — this is a supply-chain signal, not a degradation |

`checksum_mismatch` is the one state that blocks rather than degrades. Everything else has a benign
explanation; an unexpected binary does not.

### 2.1 Coverage of existing AIPAM sensors

Health reporting covers the existing sensors too, not only BlueScrub's. The precedent is concrete:
[`handle_capa`](../backend/app/pipeline/sensor_handlers.py) writes empty results and continues when
`AIPAM_CAPA_RULES_DIR` is missing, so a capa-less PCAP job today is indistinguishable from one where
capa found nothing.

**Implemented as read-only introspection.** The endpoint inspects the same paths and environment
variables the existing handlers inspect — `AIPAM_CAPA_RULES_DIR`, `AIPAM_CAPA_SIGNATURES_DIR`, the YARA
rules directory, Zeek and Suricata rule paths — and reports availability. It does **not** modify
`sensor_handlers.py`, which is outside the §5.4 allowlist and on the PCAP path that non-negotiable #1
protects.

Enriching the existing sensors to report their own degradation is the right eventual fix and is
explicitly deferred to separate work with its own regression gate.

---

## 3. Job-level distinctions

A job must be able to distinguish, per scanner:

```
ran and found nothing · skipped by profile · unavailable · failed ·
ran with stale rules · output truncated · completed with reduced capabilities
```

These map to `metrics_json.dacv.scanners[].status` and `.ruleset_state`. **"Empty findings" is never
proof of a clean result** — that inference is only valid when the scanner ran, with current rules,
without truncation.

---

## 4. Licence and redistribution

The manifest's `licence` and `redistribution` fields are populated per component, and the bundle build
fails if any entry is `unknown`.

Components needing individual attention:

| Component | Concern |
|---|---|
| **Semgrep** | The engine, the community registry rules, and Pro rules carry **distinct** terms. Semgrep is load-bearing here — the Sprint 1 vertical slice and the Co-Optability pack — so "Semgrep installed" does not establish that the intended *rules* may ship in the bundle. Resolve before Sprint 1, not before Sprint 4. |
| **CodeQL** | CLI terms restrict commercial use. Optional throughout; Semgrep + Joern are the baseline. |
| **Ghidra, FLOSS, Detect-It-Easy, rizin, RetDec** | Permissive but each requires notice retention. |
| **OSV, Grype DBs** | Data licensing distinct from tool licensing. |
| **YARA rule packs** | yara-forge and similar aggregate rules under mixed terms. |
| **Vendored BlueScrub** | Private source; copyright notices carried into `vendored/`, and `VENDOR.md` records the pinned commit. |

The offline bundle ships an SBOM and licence notices, and is signed or integrity-verified before
install.

---

## 5. Network-verification lockdown

Secret scanners offer online verification modes that call out to third-party APIs to check whether a
found credential is live. In this deployment that would be an egress channel carrying discovered
secrets out of an air-gapped network.

Verification is **hard-disabled**, and asserted by test rather than by configuration:

1. The container runner already sets `network_mode="none"`, so an attempt fails at the socket.
2. The scanner adapter additionally passes the tool's own disable flag, so a failed connection never
   even appears in output.
3. A test asserts that no scanner invocation includes a verification flag, and that the
   `repo_history` risk class carries no networking capability.

Defence in depth here is warranted: a future change that grants a scanner network access for a
legitimate reason must not silently re-enable credential exfiltration.

---

## 6. Acceptance

1. A registry entry with no manifest entry fails startup.
2. An image whose local digest differs from the manifest reports `checksum_mismatch` and does not run.
3. A vulnerability database older than the threshold reports `database_stale`, still runs, and drops the
   pillar to `degraded` with the age in the report.
4. `agent/health` reports capa rule availability on a deployment with `AIPAM_CAPA_RULES_DIR` unset,
   without any change to `sensor_handlers.py`.
5. No scanner invocation contains a network-verification flag.
6. A bundle build with an `unknown` licence field fails.
7. A job report distinguishes "scanner ran, no findings" from "scanner unavailable" in both the API and
   the UI.
