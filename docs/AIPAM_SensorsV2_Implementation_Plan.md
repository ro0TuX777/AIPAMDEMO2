# AIPAM Sensors V2 — Implementation Plan

## Working Approach

### Repo Strategy
- Use this repo
- Create a long-lived feature branch: `feature/telemetry-fusion-v1`

### Delivery Strategy
- Implement one phase at a time
- After each phase:
  - add/update tests
  - run targeted verification
  - only proceed if green

### Architectural Rule
Extend AIPAM's existing backbone, not replace it:
- `backend/app/api`
- `backend/app/connectors.py`
- `backend/app/parsers.py`
- `backend/app/pipeline/sensor_handlers.py`
- `backend/app/sensors/registry.py`
- `backend/app/normalize/correlate.py`
- `backend/app/models`
- `backend/app/services/evidence_graph.py`
- `backend/app/services/theory_engine.py`
- `backend/app/forensic_memory.py`
- frontend pages/hooks/api models

---

## Overall Objective

Transform AIPAM from:
- **PCAP-first analysis**

into:
- **multi-telemetry behavioral fusion**
- **zero-day-oriented anomaly detection**
- **adversary storyline reconstruction**
- **closed-loop learning using controlled C2/range telemetry**

---

## Telemetry Sources in Scope

### Core Sources
- PCAP
- Security Onion exports
- Arkime exports

### New Host/Network/Security Logs
- Windows Event Logs
- Sysmon
- Linux auditd
- Linux auth logs / syslog / journal exports
- firewall logs
- proxy logs
- DNS logs
- DHCP logs
- VPN logs
- NetFlow/IPFIX/sFlow
- web/app server logs
- identity/authentication logs

### Controlled-Environment / Custom Logs
- C2 server logs
- redirector logs
- listener logs
- operator task logs
- VSAT modem logs
- specialized appliance/device logs
- custom range infrastructure logs

---

## Design Principles

### 1. Not every source gets bespoke architecture
Everything should flow through:
- source adapters
- vendor-specific parsers
- normalized event types
- shared correlation/storyline logic

### 2. Keep core contracts centralized
The normalized schema and correlation logic stay in this repo.

### 3. Use plugin-style parsing
Especially for:
- vendor-specific firewall formats
- Windows/Sysmon variants
- VSAT/custom device logs
- C2 framework-specific exports

### 4. Verification is mandatory
Each phase must ship with:
- unit tests
- component tests where needed
- integration tests where meaningful
- explicit exit criteria

---

## Phase Plan

### Phase 0 — Program Foundation and Contracts ✅

**Goal:** Define the contracts so later phases don't become rework.

**Deliverables:**
- document telemetry source taxonomy
- define normalized event schema vNext
- define provenance/confidence/corroboration model
- define adapter/parser/sensor boundaries
- define phase test matrix
- define branch strategy and folder conventions

**Repo areas:**
- `docs/architecture/*`
- `backend/app/schemas/*`
- `backend/app/models/*`
- `tests/fixtures/*`

**New concepts defined:**
- `source_type`, `source_system`, `parser_name`, `parser_version`
- `raw_ref`, `exercise_id`, `corroboration_level`, `evidence_status`

**Evidence status model:** observed → inferred → corroborated → confirmed

**Exit criteria:**
- schema contract approved
- list of first-wave event types approved
- test fixture plan approved

**Verification:** schema contract tests, model import tests, fixture validation tests

---

### Phase 1 — Log-Native Ingestion Framework ✅

**Goal:** Make non-PCAP inputs first-class jobs.

**Deliverables:**
- Add new job source types: `log_bundle`, `netflow_bundle`, `c2_bundle`, `exercise_bundle`

**Repo areas to extend:**
- `backend/app/api/jobs.py`
- `backend/app/connectors.py`
- job/request schemas

---

### Phase 2 — Parser and Normalizer Framework ✅

**Goal:** Support many log families without turning the codebase into one-offs.

**Deliverables — Parser families:**
- **Host:** Windows Event Logs, Sysmon, Linux auditd, Linux auth/syslog
- **Network/security:** firewall, proxy, DNS, DHCP, VPN, NetFlow/IPFIX
- **Specialized/custom:** C2 exports, VSAT modem logs, custom appliance logs

**Normalized event families:** connection, netflow, dns, http, proxy, tls, alert, auth, process, file, config_change, asset_status, interface_event, c2, finding, ioc

**Modeling guidance:** Do not force odd logs into fake categories. Example: VSAT modem logs may map to `asset_status`, `interface_event`, `alert`, `config_change`.

**Exit criteria:**
- parsers exist for first-wave formats
- normalized output contract enforced
- invalid records safely dropped or marked

**Verification:** unit tests per parser, fixture-based normalization tests, schema validation tests, malformed-input tests, timestamp normalization tests

---

### Phase 3 — Database and API Expansion ✅

**Goal:** Persist and expose new telemetry cleanly.

**Deliverables — First-class models and endpoints for:**
- auth events, process events, proxy/http events, netflow events
- c2 events, asset/interface status events
- corroboration/provenance metadata

**API goals — Support:**
- list/detail for each major event family
- timeline filters by source/event type
- provenance visibility
- source-based filtering
- corroboration state filtering

**Exit criteria:**
- new evidence types queryable via API
- timeline includes log-native evidence
- pagination/search/filter patterns consistent with existing APIs

**Verification:** model table tests, migration tests, endpoint contract tests, pagination/filter tests, sample seeded DB tests

---

### Phase 4 — Correlator vNext ✅

**Goal:** Fuse events across PCAP, logs, and C2 truth.

**Existing base extended:** community_id, Zeek uid, Suricata flow_id, 5-tuple + time window

**New correlation keys added:**
- hostname / asset ID
- username / account
- session ID, request ID
- process GUID
- file hash
- JA3 / JA3S
- SNI
- cert fingerprint
- URI path / host header
- operator task timestamp
- exercise ID

**New capabilities:**
- multi-source event linking
- support-strength scoring
- provenance-aware confidence adjustment
- source conflict tracking

**Exit criteria:**
- same activity seen in multiple sources links into one coherent case
- correlator handles log-only jobs
- corroboration levels are persisted and visible

**Verification:** unit tests for correlation rules, fixture-based cross-source correlation tests, dedup tests, timeline consistency tests, false-link regression tests

---

### Phase 5 — Behavioral Detection Expansion

**Goal:** Detect zero-days via behavior, rarity, and role violations.

**Build on existing capability:** AIPAM already has anomaly detection for beaconing, DNS anomalies, temporal anomalies, TLS anomalies, lateral movement, port scanning, exfil patterns.

**New detectors:**
- role baseline sensor
- rare destination/service sensor
- identity/auth anomaly sensor
- netflow behavior sensor
- host/process execution anomaly sensor
- cross-source inconsistency detector
- sequence detector

**Example detections:**
- workstation using rare admin protocol
- account authenticating in new path pattern
- host showing callback-like netflow without signature hit
- proxy+DNS+TLS sequence consistent with staged malware
- Linux privilege escalation followed by suspicious outbound behavior
- Sysmon process tree matching suspicious delivery chain

**Repo areas:** `backend/app/anomaly_detector.py`, `backend/app/sensors/registry.py`, `backend/app/pipeline/sensor_handlers.py`, new sensors if split

**Exit criteria:**
- behavior-only findings appear without signature dependency
- detectors work on mixed-source and log-only jobs
- confidence scoring reflects corroboration

**Verification:** unit tests per detector, fixture-driven anomaly tests, threshold tuning tests, false-positive control tests, regression tests against existing PCAP behavior detection

---

### Phase 6 — C2 / Controlled-Range Telemetry Fusion

**Goal:** Use red-team infrastructure logs as near-ground truth.

**Deliverables — Support ingest and normalization for:**
- callback logs, operator task logs, redirector/access logs
- listener/session logs, staging/download logs

**Capabilities:**
- map observed network activity to C2-side confirmation
- tie task timing to host/network timeline
- identify callback cadence, jitter, staging behavior
- mark events as confirmed by attacker-side telemetry

**Exit criteria:**
- one exercise with C2 logs can be fused end-to-end
- confirmed vs inferred events are clearly differentiated
- analysts can pivot from AIPAM finding to C2 confirmation path

**Verification:** synthetic or sanitized C2 fixture tests, end-to-end correlation tests, confidence uplift tests, UI/API smoke checks for confirmed evidence

---

### Phase 7 — Storyline Reconstruction and Theory Expansion

**Goal:** Turn evidence into attack narratives.

**Existing base to extend:** `evidence_graph.py`, `theory_engine.py`, reporting/narrative layers

**New graph node types:** auth event, process, netflow, HTTP/proxy request, c2 callback, operator task, asset/interface events

**New edge types:** `authenticated_as`, `downloaded_from`, `executed_on`, `beaconed_to`, `confirmed_by`, `occurred_before`, `caused_by`, `same_session`, `same_operator_pattern`

**Storyline outputs:** attack stages, supporting/contradicting evidence, confidence/rationale, per-host and per-exercise narratives

**Exit criteria:**
- storyline generated from mixed telemetry
- evidence graph meaningfully expanded
- theory engine reflects host/log/C2 evidence

**Verification:** graph node/edge tests, theory ranking tests, narrative consistency tests, API tests for graph/storyline endpoints

---

### Phase 8 — Memory and Cross-Exercise Learning

**Goal:** Convert completed, confirmed investigations into reusable intelligence.

**Existing base to extend:** `forensic_memory.py`, `services/correlation.py`

**New memory content — Store confirmed:**
- beacon profiles, JA3/SNI/cert combinations, sequence motifs
- auth abuse patterns, process trees, operator timing patterns
- exercise tags, infrastructure fingerprints

**Capabilities:**
- find similar prior exercises
- compare current case to known confirmed behavior
- cluster behavior beyond IOC overlap
- distinguish signature-driven vs behavior-driven wins

**Exit criteria:**
- memory query returns behaviorally similar prior cases
- campaign correlation uses more than just hosts/IOCs/MITRE
- only confirmed evidence enters long-term memory

**Verification:** memory indexing tests, semantic retrieval tests, campaign clustering tests, contamination/false-memory guard tests

---

### Phase 9 — Frontend Fusion UI

**Goal:** Expose all of this in an analyst-usable way.

**Deliverables — Add or extend pages/components for:**
- source manifest / provenance view
- enriched timeline filters
- host + identity + process views
- event family tabs
- corroboration badges
- C2 confirmation markers
- storyline panel
- expanded evidence graph controls

**UI principles:**
- do not bury analysts in raw logs
- summarize first, drill down second
- show source/provenance everywhere
- clearly distinguish: inferred, corroborated, confirmed

**Exit criteria:**
- analyst can investigate a mixed-source job end-to-end
- UI can pivot across host, finding, graph, timeline, source
- storyline visible and understandable

**Verification:** frontend unit/component tests, e2e workflow tests, smoke tests for mixed-source jobs

---

### Phase 10 — Operational Hardening

**Goal:** Make it safe and maintainable for offline production use.

**Deliverables:**
- fixture packs for offline regression
- parser failure isolation
- import size/resource guardrails
- retention rules for raw telemetry
- support bundle improvements
- telemetry ingest diagnostics
- benchmark baselines

**Exit criteria:**
- malformed vendor logs do not break jobs
- large bundles degrade gracefully
- benchmark regression gates exist

**Verification:** performance tests, large-bundle smoke tests, failure-mode tests, recovery tests


---

## Source-by-Source Priority Matrix

### Phase 1/2 First-Wave Sources (implement first)
Windows Event Logs, Sysmon, Linux auditd, Linux auth/syslog, firewall logs, proxy logs, DNS logs, NetFlow/IPFIX, C2 logs

### Phase 2/3 Second-Wave Sources
DHCP, VPN, web/app logs, WAF, load balancer, identity provider logs

### Plugin-Driven Third Wave
VSAT modem logs, custom appliance logs, OT/ICS device logs, lab/range-specific telemetry

---

## Folder/Code Organization

### Core contracts in this repo
schemas, models, correlator, API, graph, theory, memory

### Parser organization by source family
```
backend/app/parsers/windows/
backend/app/parsers/linux/
backend/app/parsers/network/
backend/app/parsers/c2/
backend/app/parsers/custom/
```

### Adapter organization
`backend/app/connectors/` or adapter modules for: log bundle, c2 bundle, netflow bundle, exercise bundle

### Optional later split
Only later, if needed: separate repo for collectors/forwarders, external plugin SDK, community/vendor parser packs. **Not now.**

---

## Test and Verification Policy

### Minimum Gating Rule
Do not advance phases unless:
- targeted tests pass
- regression tests for touched areas pass
- sample workflow for that phase succeeds

### Test Types
| Type | For |
|---|---|
| **Unit** | parsers, normalizers, correlation rules, anomaly rules, graph logic, theory ranking |
| **Component** | job staging, adapter behavior, DB writes, end-to-end parser→correlator flow with temp DB |
| **Integration** | mixed-source jobs, PCAP + logs + C2 fused workflows |
| **E2E** | analyst workflow in UI |

### Verification Gates
| Gate | Scope |
|---|---|
| **A — contracts** | schema/model tests pass |
| **B — ingestion** | new source job creation works |
| **C — normalization** | raw inputs produce valid normalized events |
| **D — correlation** | multi-source evidence links correctly |
| **E — behavior** | zero-day-style detections appear without signatures |
| **F — storyline** | graph and theory output are coherent |
| **G — regression** | existing PCAP workflows still work |

---

## Sprint Plan

| Sprint | Phases | Key Deliverables |
|---|---|---|
| **1** | Phase 0 + start Phase 1 | branch, contracts, source taxonomy, job source models, log bundle scaffold, fixtures |
| **2** | Finish Phase 1 + begin Phase 2 | bundle ingestion, parser framework, first parsers (Windows, Sysmon, Linux auth, firewall, proxy, DNS) |
| **3** | Continue Phase 2 + Phase 3 | DB model expansion, event family APIs, timeline enhancements |
| **4** | Phase 4 | correlator vNext, new correlation keys, corroboration model |
| **5** | Phase 5 | role baseline, auth anomaly, netflow behavior, sequence detector |
| **6** | Phase 6 | C2 bundle adapter, C2 parsers, C2 fusion sensor |
| **7** | Phase 7 + 9 | expanded evidence graph, storyline outputs, theory engine enhancements, frontend views |
| **8** | Phase 8 + 10 | forensic memory expansion, campaign correlation, benchmarks, ops hardening |

---

## Definition of Done (per phase)

A phase is done only when **all** are true:
1. code is merged on branch
2. tests for that phase pass
3. regression checks pass
4. minimal analyst workflow works
5. results are inspectable via API or UI
6. no blocking schema ambiguity remains

---

## Biggest Risks to Control

| Risk | Mitigation |
|---|---|
| **Schema sprawl** | enforce normalized contracts early |
| **Vendor parser chaos** | parser family structure + fixtures + plugin pattern |
| **False-positive explosion** | corroboration scoring + role baselines + staged rollout |
| **Breaking current PCAP workflows** | regression gate every phase |
| **Overbuilding UI too early** | backend/schema/correlation first, UI after evidence quality is solid |