# AIPAM — Technical Explanation

> **The Lead Architect's Final Case File: The AIPAM Rebuild**
>
> A comprehensive discussion of the design principles, reasoning, and internal mechanics of the AI PCAP Analysis Module — from its original prototype to the Tiered Specialist Platform it is today.
>
> **Audience**: Developers, security engineers, and reviewers seeking to understand *why* AIPAM is built the way it is.
> **Type**: Conceptual Guide / Architectural Record

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [The Foundation: DAWN Determinism](#2-the-foundation-dawn-determinism)
3. [The Cognitive Engine: The Specialist Pyramid](#3-the-cognitive-engine-the-specialist-pyramid)
4. [Chain-of-Thought Forensic Reasoning](#4-chain-of-thought-forensic-reasoning)
5. [The Anti-Hallucination System](#5-the-anti-hallucination-system)
6. [Heuristic–LLM Fusion](#6-heuristicllm-fusion)
7. [Evidence-First Data Architecture](#7-evidence-first-data-architecture)
8. [The Memory: Long-Term Forensic Context](#8-the-memory-long-term-forensic-context)
9. [The Shield: Actionable & Proactive Defense](#9-the-shield-actionable--proactive-defense)
10. [Pipeline Resilience & Checkpointing](#10-pipeline-resilience--checkpointing)
11. [Pluggable Architecture & Extension Points](#11-pluggable-architecture--extension-points)
12. [Configuration Resolution Strategy](#12-configuration-resolution-strategy)
13. [Cross-Job Campaign Detection](#13-cross-job-campaign-detection)
14. [Trade-offs & Known Limitations](#14-trade-offs--known-limitations)
15. [Continuous Improvement: The Self-Healing Training Loop](#15-continuous-improvement-the-self-healing-training-loop)

---

## The "New" AIPAM Architecture

> **Implementation Note**  
> This document captures the intended DAWN-centric design. The current runtime
> implementation in this repo uses a Celery pipeline (`backend/app/tasks.py`),
> with a decoupled variant in `backend/app/pipeline.py`. The full
> `aipam_forensic.yaml` DAWN contract is not present here, and only selected
> DAWN link logic is invoked (e.g., simulation generation).

```
[ SOURCE AGNOSTIC INGEST ]
      (PCAP / SO / Arkime)
               │
               ▼
[ DAWN DETERMINISTIC PIPELINE ]
               │
    ┌──────────┴──────────┐
    │  LEVEL 1: TRIAGE    │ ◄─── (Generalist Llama 3.1)
    └──────────┬──────────┘
               │
    ┌──────────┴──────────┐
    │  LEVEL 2: REASONING │ ◄─── (Forensic Llama / COT)
    └──────────┬──────────┘
               │
    ┌──────────┴──────────┐
    │  LEVEL 3: EXPERT    │ ◄─── (Mc4minta Malware ID)
    └──────────┬──────────┘
               │
    ┌──────────┴──────────┐
    │  HUMAN-IN-THE-LOOP  │ ◄─── (Stale-Safe Verification)
    └──────────┬──────────┘
               │
    ┌──────────┴──────────┬──────────────────────────┐
    │ [CAMPAIGN MEMORY]    │ [ACTIONABLE DEFENSE]     │
    │ - Global RAG         │ - Suricata/Sigma Rules   │
    │ - Correlation Index  │ - Scapy Simulations      │
    └──────────────────────┴──────────────────────────┘
```

---

## 1. Design Philosophy

AIPAM was designed around a core tension in LLM-assisted security tooling: **LLMs are excellent at reasoning about network behavior but prone to fabricating evidence**. Every architectural decision flows from this insight.

We transformed AIPAM from a fragile collection of scripts into a **Tiered Specialist Platform**. The five guiding principles remain, but are now enforced by infrastructure rather than convention:

### Guiding Principles

1. **Evidence before inference** — The system always persists raw network evidence (flows, alerts, packets) *before* invoking any LLM. Analysis operates against verified data, never against the LLM's memory. DAWN's artifact store enforces this ordering declaratively.

2. **Trust but verify** — LLM outputs pass through guardrails that validate cited evidence against the database. A finding that references a flow ID that doesn't exist is flagged, not silently accepted. The HITL gate ensures no finding reaches downstream stages without review.

3. **Fail gracefully, never silently** — Each pipeline stage checkpoints its output via DAWN's immutable ledger. If stage 3 crashes, stage 2's work is preserved. If the LLM hallucinates, guardrails annotate rather than discard — an analyst can still review.

4. **Modularity over monolith** — Every analysis capability is a self-contained DAWN Link with a `link.yaml` contract and a `run.py` implementation. Links can be added, reordered, or conditionally skipped without modifying the core pipeline.

5. **Human-in-the-loop by default** — Findings start as `"unverified"`. The HITL gate (`hitl.findings_review`) provides a formal review checkpoint where findings above a confidence threshold can be auto-confirmed, but manual review is always possible. Rule export and memory indexing are gated behind confirmed findings.

---

## 2. The Foundation: DAWN Determinism

The application no longer "just runs." It executes via a **Deterministic Auditable Workflow Network** (DAWN). Every forensic conclusion is backed by three guarantees:

### 2.1 Immutable Ledger

Every DAWN Link logs events to a JSONL audit trail via `context["ledger"].log_event()`:

```json
{
  "project_id": "case-001",
  "pipeline_id": "aipam_forensic",
  "link_id": "analyze.forensic_cot",
  "run_id": "run-20260215-001",
  "step_id": "forensic_analysis",
  "status": "OK",
  "inputs": { "flow_ir": "flow_ir.json", "sensitivity": "HIGH" },
  "outputs": { "findings_count": 4, "mitre_techniques": ["T1071.001", "T1041"] },
  "metrics": { "l2_findings": 4, "confidence_avg": 0.87 }
}
```

This creates a complete forensic provenance chain: from the raw PCAP bytes, through every model decision, to the final report.

### 2.2 Cryptographic Binding

The ingest links compute a `bundle_sha256` from the canonical representation of all input files:

```python
canonical = "\n".join(f"{f['path']}:{f['sha256']}:{f['bytes']}" for f in files)
bundle_sha = hashlib.sha256(canonical.encode()).hexdigest()
```

Findings are locked to this hash. If the input data changes, the findings expire. Deterministic flow IDs are derived from the bundle hash, ensuring that re-analyzing the same PCAP produces identical identifiers.

### 2.3 Meaning Gates (Pipeline Contract)

The `aipam_forensic.yaml` pipeline defines a formal contract before the AI starts:

```yaml
pipelineId: aipam_forensic
description: >-
  Sensitivity-Based Model Pyramid for AIPAM forensic analysis.
  Source-agnostic ingest → Chain-of-Thought analysis →
  conditional deep malware ID (HIGH only) → narrative synthesis →
  analyst review → campaign correlation → detection rule export → final audit.

# Sensitivity Contract:
#   LOW  → L1 + L2 + Narrative  (skip Level 3)
#   HIGH → L1 + L2 + L3 (Mc4minta) + Narrative
```

Overrides enforce execution ordering with explicit conditions:

```yaml
overrides:
  analyze.deep_malware:
    spec:
      when:
        condition: "on_success(analyze.forensic_cot) AND sensitivity == 'HIGH'"
```

This makes the pipeline's behavior predictable and auditable — no implicit dependencies, no hidden execution paths.

### 2.4 DAWN Link Architecture

Each link is a self-contained unit:

| File | Purpose |
|------|---------|
| `link.yaml` | Contract: inputs, outputs, config schema, model requirements |
| `run.py` | Implementation: receives `context` + `link_config`, returns status + metrics |

Links communicate exclusively through the artifact store (`context["artifact_store"]`) and sandbox (`context["sandbox"]`). There are no shared globals or implicit imports.

### 2.5 The Full Pipeline

The current `aipam_forensic.yaml` defines 11 stages:

| Stage | DAWN Link | Purpose |
|-------|-----------|---------|
| 0 | `aipam.ingest.pcap` / `.security_onion` / `.arkime` | Source-agnostic ingest to unified Flow IR |
| 1+2 | `analyze.forensic_cot` | Chain-of-Thought forensic reasoning (L1 triage + L2 deep analysis) |
| 3 | `analyze.deep_malware` | Mc4minta malware family ID (**HIGH sensitivity only**) |
| 4 | `report.narrative` | LLM-synthesized forensic storyline |
| 5 | `hitl.findings_review` | Human-in-the-loop review gate |
| 6 | `memory.vector_index` | Vectorize confirmed findings into global ChromaDB |
| 7 | `correlate.campaign` | Cross-project campaign detection |
| 8 | `simulate.traffic_pattern` | Purple Team adversary emulation script generation |
| 9 | `export.detection_rules` | Suricata/Sigma rule generation |
| 10 | `quality.release_verifier` | Final audit and trust receipt |

---

## 3. The Cognitive Engine: The Specialist Pyramid

We replaced the "one model fits all" approach with a three-tier hierarchy. Each tier has a specific cognitive role, and the sensitivity setting determines which tiers execute.

### Level 1: Generalist (Triage)

- **Model**: Llama 3.1 8B (general-purpose)
- **Role**: UI interaction, report generation, fast triage, chatbot responses
- **Temperature**: 0.1–0.3
- **Context**: Operates on aggregated flow summaries
- **Always executes**: Yes

### Level 2: Forensic Specialist (Reasoning)

- **Model**: Llama 3.1 8B (fine-tuned forensic prompt)
- **Role**: Chain-of-Thought reasoning, MITRE ATT&CK mapping, attack chain reconstruction, confidence scoring
- **Temperature**: 0.1
- **Context**: Full flow records for triage-selected suspicious flows
- **Always executes**: Yes
- **DAWN Link**: `analyze.forensic_cot`

### Level 3: Task Specialist (Expert)

- **Model**: Mc4minta (fine-tuned on malware traffic datasets)
- **Role**: Deep malware family identification using packet-level classification
- **Confidence threshold**: 0.6
- **Max samples**: 100 flows
- **Executes**: **Only when `sensitivity == 'HIGH'`**
- **DAWN Link**: `analyze.deep_malware`

### Level 2-Edge: Student Specialist (Phase 6.3)

- **Model**: Llama 3.2 1B (distilled from 8B Teacher via ORPO)
- **Role**: Edge-sensor forensic reasoning at 1/8th parameter count
- **Training**: Teacher-generated preference pairs via `distill_generate_labels.py`
- **Retention Gate**: Must achieve ≥90% of Teacher accuracy to deploy
- **Export**: GGUF Q4_K_M for Ollama edge deployment

### Why Three Tiers?

The separation exists because these are fundamentally different cognitive tasks:

**Triage** is a *rapid scanning* problem where the model needs to identify which of thousands of flows deserve attention. Speed matters more than depth.

**Forensic reasoning** is a *chain-of-thought inference* problem where the model must weigh multiple evidence types — flow patterns, alert correlations, temporal anomalies — and produce a coherent attack narrative with MITRE ATT&CK mappings.

**Malware identification** is a *pattern recognition* problem where a model trained on known malware families excels. It needs domain-specific training data (Mc4minta dataset) and packet-level features that a general-purpose LLM cannot reliably extract.

### Sensitivity-Based Routing

```
                                    ┌─────────────┐
                                    │ Sensitivity  │
                                    │   Setting    │
                                    └──────┬──────┘
                                           │
                              ┌────────────┴────────────┐
                              │                         │
                         LOW / DEFAULT                 HIGH
                              │                         │
                    ┌─────────┴─────────┐     ┌────────┴─────────┐
                    │ L1+L2 → Narrative │     │ L1+L2+L3 →       │
                    │ (skip L3)         │     │ Narrative         │
                    └───────────────────┘     └──────────────────┘
```

The conditional routing is enforced by DAWN's `when` overrides in the pipeline YAML. This is not application logic — it's infrastructure-level routing that the links themselves are unaware of.

### TrafficLLM (Legacy Integration)

The original TrafficLLM (ChatGLM2-6B with LoRA adapters) remains available as an optional classification service:

| Task Code | Full Name | Target |
|-----------|-----------|--------|
| MTD | Malware Traffic Detection | Malware families |
| EVD | Encrypted VPN Detection | VPN protocol detection |
| TBD | Tor Browsing Detection | Tor traffic |
| BND | Botnet Detection | C2 infrastructure |
| WAD | Web Attack Detection | SQL injection, XSS |
| AAD | APT Attack Detection | Advanced persistent threats |

TrafficLLM runs as an independent Docker service (`aipam-trafficllm`) requiring an NVIDIA GPU. Its classifications are injected as *advisory* context into the forensic LLM's prompt. The Specialist Pyramid supersedes TrafficLLM for core analysis but retains it for specialized packet-level classification tasks.

---

## 4. Chain-of-Thought Forensic Reasoning

The `analyze.forensic_cot` DAWN link implements a deliberate two-stage reasoning pattern modeled after how human forensic analysts work.

### Stage 1: Triage

**Problem**: A PCAP capture may contain thousands of flows. Sending all of them to the LLM would exceed context limits, introduce noise, and waste compute.

**Solution**: First, send *lightweight summaries* of all flows (IP pairs, ports, protocols, byte counts, connection states) and ask the LLM: *"Which 3 flows are most suspicious and why?"*

The LLM responds with a ranked list of flow IDs and justifications. Flow IDs are validated against the actual dataset — hallucinated flow references are dropped with audit logging.

### Stage 2: Deep Analysis

**Problem**: Summaries lack the detail needed for MITRE ATT&CK mapping. The LLM needs full flow context — packet counts, TCP flags, timing jitter, associated alerts.

**Solution**: Fetch *complete* flow records for only the triage-selected flows and ask: *"Map each flow to its MITRE ATT&CK technique, explain the evidence, and assess confidence."*

### Why Two Stages?

This mirrors the cognitive process of an experienced SOC analyst:

1. **Scan 500 flows in 30 seconds** — identify the 3 that look wrong
2. **Spend 20 minutes on those 3** — examine packet details, cross-reference alerts

The two-stage approach reduces LLM input by ~99% while focusing attention where it matters most. The triage stage's output (suspicious flow IDs and rationale) becomes evidence in the final report, providing an audit trail of *why* the system focused on specific flows.

### Artifact Flow

```
aipam.flow.ir → [L1 Triage] → suspicious_flow_ids
                                       │
                                       ▼
               full_flow_records → [L2 Deep Analysis] → aipam.findings.ir
                                                              │
                                                              ▼
                                                    aipam.forensic.narrative
```

---

## 5. The Anti-Hallucination System

LLM hallucination is the primary threat model for any AI-assisted forensic tool. A fabricated flow ID could lead an analyst to waste hours investigating non-existent evidence. AIPAM addresses this through a layered defense.

### Layer 1: Structured Output Contracts

Every LLM response is expected as JSON conforming to strict Pydantic schemas. The parser first tries `json.loads()`, and only falls back to natural language extraction if JSON parsing fails.

### Layer 2: Input-Side Validation

The triage stage validates flow IDs against `known_ids` before they enter the deep analysis pipeline. Hallucinated flow IDs are dropped with a warning.

### Layer 3: `FlowExistenceGuardrail`

After findings are produced, the guardrail validates every `cited_flow_id` against `FlowDB`:

```
Finding.cited_flow_ids → SELECT id FROM flowdb WHERE id IN (...)
                                      │
                            ┌─────────┴──────────┐
                            ▼                    ▼
                       All exist            Some missing
                            │                    │
                            ▼                    ▼
                    Finding passes     Finding.requires_review = True
                                       Finding.review_reason = "..."
```

**Fail-open design**: If no database session is available, the guardrail passes findings through unmodified rather than rejecting them.

### Layer 4: LLM Response Refinement

The `_refine_classification()` method cross-checks the LLM's malware classification against independent evidence:
- **Alert metadata**: Suricata alerts mentioning "IcedID" override an LLM claiming "Zeus"
- **PCAP filename hints**: CTF exercise PCAPs often contain the malware family
- **TLS markers**: Specific TLS SNI patterns correlate with known families

### Layer 5: HITL Gate

The `hitl.findings_review` DAWN link serves as the formal review checkpoint. Findings above the `auto_confirm_threshold` (default 0.9) can be auto-approved; everything else requires human review. **Only confirmed findings flow to memory indexing, correlation, and rule export.**

> **Runtime Gap**  
> In the current API implementation, rule export endpoints do not enforce
> `analyst_status` gating before generation. If strict HITL gating is required,
> the API should enforce `analyst_status == confirmed` before export.

### Layer 6: DAWN Provenance

Every model decision is logged to the DAWN ledger with inputs, outputs, and metrics. If a finding is later questioned, the full chain of evidence can be reconstructed from the audit trail.

### Layer 7: Hallucinated Citation Rate — HCR (Phase 6.1+)

Phase 6.1 introduces a **quantitative hallucination metric** that goes beyond the binary pass/fail of the FlowExistenceGuardrail:

- **IP hallucination**: IPs cited in the response that are absent from the input prompt
- **MITRE hallucination**: Fabricated technique IDs (e.g., `T9xxx` range)
- **Novel MITRE**: Valid technique IDs cited but not present in source data

The HCR is computed by `verify_model_bias.py` and is enforced as a constitutional invariant: HCR must remain below 5%. ORPO preference training actively suppresses hallucination by training the model on preference pairs where the "rejected" response contains corrupted evidence.

### Layer 8: Reasoning Entropy — RE (Phase 6.5+)

Entropy tracking ensures the model doesn't become "narrow-minded" from sequential LocFT updates:

```
RE = −Σ p(x) · log₂(p(x))    (Shannon entropy in bits)
```

If RE drops below the configured threshold (default 1.5 bits), an Entropy Collapse warning triggers, recommending a breadth-first refresh from the v6 base model. This prevents the model from over-specializing on recently trained families at the expense of older ones.

---

## 6. Heuristic–LLM Fusion

AIPAM does not rely solely on LLM reasoning. The `AnomalyDetector` runs 10+ heuristic detectors that identify suspicious patterns using statistical and behavioral analysis — no LLM involved.

### Why Heuristics Alongside LLMs?

1. **Zero-day detection**: LLMs are trained on known patterns. Heuristics catch statistical anomalies that don't match any known signature — exactly where zero-days live.
2. **LLM context enrichment**: Heuristic findings are injected into the LLM prompt as the `## ZERO-DAY ANOMALY DETECTION REPORT` section.
3. **Speed**: Heuristics run in milliseconds. The LLM takes seconds to minutes.
4. **Determinism**: Heuristic detectors always produce the same output for the same input.

### The Heuristic Detectors

| Detector | Technique | Key Signal |
|----------|-----------|------------|
| Beacon detection | Inter-arrival time analysis | Low jitter in periodic connections |
| Volume anomalies | Statistical outlier detection | Byte counts exceeding N standard deviations |
| Connection anomalies | Protocol-port mapping | HTTP on port 53, SSH on port 80 |
| Port scanning | Fan-out analysis | Source → many destination ports |
| Lateral movement | Internal graph traversal | Source contacts many internal hosts |
| Temporal anomalies | Time-series analysis | Activity outside business hours |
| DNS anomalies | Domain analysis | Long random subdomains (DGA) |
| DNS beaconing | Periodic DNS query analysis | Regular intervals to same domain |
| TLS anomalies | Certificate/port analysis | TLS on non-standard ports |
| Entropy anomalies | Shannon entropy analysis | High-entropy payloads |
| Graph anomalies | Network topology | Hub nodes, unusual fan-in/fan-out |

### Fusion Strategy

The anomaly report feeds into the forensic LLM's prompt with a classification priority order:
1. If traffic matches a **known** malware family → use that classification
2. If traffic shows **known behavioral patterns** but doesn't match signatures → use behavioral descriptions
3. If traffic is **genuinely novel** → classify as potential zero-day with the strongest evidence

---

## 7. Evidence-First Data Architecture

AIPAM's database design enforces a strict temporal and causal ordering of evidence.

### Write Ordering

```
 Time ──────────────────────────────────────────────────►

 ┌────────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐
 │  FlowDB    │   │  AlertDB  │   │ FindingDB│   │ ResultDB │
 │  (raw)     │──►│  (raw)    │──►│ (derived)│──►│ (summary)│
 └────────────┘   └───────────┘   └──────────┘   └──────────┘
      ▲                                │
      │            ┌──────────┐        │
      └────────────│EvidenceDB│◄───────┘
                   │ (links)  │
                   └──────────┘
```

Raw evidence is always persisted **before** derived artifacts. The `EvidenceDB` table creates many-to-many links between findings and supporting flows:
- **No finding can exist without corresponding raw evidence** (enforced by guardrails)
- **Raw evidence is never deleted when findings are invalidated** (forward-only audit trail)
- **Any finding can be traced back to specific packets** through FlowDB → PCAP file mapping

### ID Design

- **Flow IDs**: `{job_id}:{zeek_uid}` — deterministic from PCAP content
- **Alert IDs**: `{job_id}:{alert_id}` — job-scoped
- **Finding IDs**: UUIDs — system-generated
- **DAWN artifact IDs**: Deterministic hashes derived from `bundle_sha256`

---

## 8. The Memory: Long-Term Forensic Context

AIPAM now has **forensic experience**. Through a two-tier memory system, the chatbot can correlate current threats with historical cases.

### 8.1 Per-Job RAG (LanceDB)

After pipeline completion, `build_documents_from_job_result()` decomposes the `JobResult` into discrete `RAGDocument` chunks:

| Document Type | Content | Metadata |
|---------------|---------|----------|
| `host_summary` | Per-host finding narrative | `ip`, `role`, `severity` |
| `finding` | Finding title + description + evidence | `mitre_id`, `confidence` |
| `alert_summary` | Alert signature + context | `alert_source`, `severity` |
| `flow_summary` | Flow characteristics | `protocol`, `duration`, `bytes` |

Each chunk is embedded using `sentence-transformers/all-MiniLM-L6-v2` and stored in a per-job LanceDB table. This provides isolated, high-relevance retrieval for in-job analyst queries.

### 8.2 Global Forensic Memory (ChromaDB)

The `memory.vector_index` DAWN link writes confirmed findings to a persistent, global ChromaDB instance at `~/.aipam/forensic_memory`.

**Input**: `aipam.findings.reviewed` (only confirmed findings pass the HITL gate)

**Process**:
1. Extracts rationale and evidence from each finding
2. Uses the L1 model for embedding generation
3. Stores vectors with metadata (MITRE technique, severity, case ID, timestamp)

**Result**: The chatbot can now say: *"I've seen this before in Case-002 — it's a T1071.001 beacon pattern matching IcedID C2 infrastructure we analyzed last week."*

### 8.3 Three-Source Chat Context

The chat service (`chat_service.py`) injects a three-source context window into every conversation:

| Source | Content | Citation Format |
|--------|---------|-----------------|
| Current Case Narrative | `aipam.forensic.narrative` from the current job | `[Current Case]` |
| Campaign Correlations | `aipam.campaign.correlation` cross-job matches | `[Campaign Correlation]` |
| Forensic Memory | Global ChromaDB similarity search | `[Forensic Memory]` |

The system prompt positions the L1 model as a **"Lead Forensic Investigator"** who synthesizes current analysis with institutional memory to provide contextualized, source-cited responses.

---

## 9. The Shield: Actionable & Proactive Defense

The system doesn't just produce a PDF report. It produces **operational outputs** that directly strengthen your defenses.

### 9.1 Detection-as-Code

The `export.detection_rules` link generates ready-to-deploy detection rules:

**Suricata Rules**:
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"AIPAM: IcedID C2 Beacon (T1071.001)";
  flow:to_server,established;
  content:"|16 03|"; depth:2;
  threshold:type both,track by_src,count 5,seconds 300;
  sid:9000001; rev:1;
  metadata:mitre T1071.001, confidence 0.92;
)
```

**Sigma Rules**:
```yaml
title: IcedID C2 Beacon (T1071.001)
logsource:
    category: network_connection
    product: zeek
detection:
    selection:
        dst_ip: '185.220.101.42'
        dst_port: 443
    condition: selection | count() by src_ip > 5
```

### 9.2 Adversary Emulation (Purple Team Loop)

The `simulate.traffic_pattern` DAWN link generates **Scapy-based Python scripts** that replicate detected adversary behavior for testing your own defenses:

**Input**: `aipam.findings.reviewed` (confirmed findings)

**Output**: `aipam.simulation.py` — an executable script with:
- MITRE-specific traffic templates (T1071 C2 beacon, T1041 exfiltration, T1566 phishing, T1190 exploit traffic, T1048 alt-protocol exfil)
- LLM-enhanced generation for unmapped techniques
- Safe detonation only — benign packets that mimic timing and structure, no actual payloads

**Templates**:

| MITRE Technique | Simulation |
|-----------------|------------|
| T1071 (Application Layer Protocol) | Periodic TLS beacon with configurable jitter |
| T1041 (Exfiltration Over C2) | Chunked outbound data transfer |
| T1566 (Phishing) | SMTP-like traffic with attachment simulation |
| T1190 (Exploit Public-Facing App) | HTTP exploit probe sequence |
| T1048 (Exfiltration Over Alt Protocol) | DNS/ICMP tunneling patterns |

**Usage**:
```bash
sudo python aipam_simulation_<job>.py --interface eth0 --pcap output.pcap
```

### 9.3 The Closed-Loop Purple Team Cycle

The closed-loop test (`scripts/closed_loop_test.py`) validates that AIPAM can **detect its own generated simulation traffic**:

```
Phase A: Real PCAP → Pipeline → 2 MITRE techniques (T1071.001, T1041)
                                         │
Phase B: Findings → simulate.traffic_pattern → 5225-char Scapy script
                                         │
Phase C: Scapy script → Synthetic PCAP
                                         │
Phase D: Synthetic PCAP → Pipeline → Same 2 MITRE techniques detected
                                         │
                                    ✅ 100% Match Rate
```

This creates a virtuous feedback loop: every finding that AIPAM produces can also be used to validate the defensive posture against that exact threat pattern.

### 9.4 WebUI Integration

The "Download Simulation Script" button appears in the Job Detail header for completed jobs. The backend endpoint `POST /api/v1/jobs/{job_id}/simulation` extracts findings from the job result, runs the `simulate.traffic_pattern` link, and returns the generated Python script as a downloadable file.

---

## 10. Pipeline Resilience & Checkpointing

The pipeline is designed to survive failures at any stage without losing completed work.

### DAWN-Level Checkpointing

Each DAWN Link stage publishes artifacts to the sandbox on completion. On retry, the pipeline checks for existing artifacts before re-executing a link. The ledger provides a complete record of success/failure per stage.

### Stage-Level Checkpointing

Within the legacy Celery pipeline, each stage writes a `PipelineCheckpointDB` row on successful completion:

```
{job_id}:ingest   → { pcap_paths: [...] }
{job_id}:extract  → { flow_ids: [...], alert_ids: [...] }
{job_id}:analyze  → { findings: [...], llm_raw: { classification: "IcedID" } }
{job_id}:report   → { report_urls: { html: "/reports/job-1.html" } }
```

### Why Not Database Transactions?

1. **LLM inference takes minutes** — holding a write lock would block the API
2. **Partial progress is valuable** — extracted flows are useful even if the LLM crashes
3. **Checkpoints are more granular than transactions** — they capture output per stage

---

## 11. Pluggable Architecture & Extension Points

AIPAM uses two levels of pluggability:

### DAWN Link Extension

Adding a new capability requires only:
1. Create `dawn/links/my.new.capability/link.yaml` (contract)
2. Create `dawn/links/my.new.capability/run.py` (implementation)
3. Add the link to `aipam_forensic.yaml` with appropriate `when` conditions

No core code changes required.

### Core Interface Extension

| Interface | Purpose | Implementations |
|-----------|---------|-----------------|
| `ForensicAnalyzer` | Produces findings from context | `ChainOfThoughtAnalyzer` |
| `ValidationStep` | Validates findings pre-commit | `FlowExistenceGuardrail` |
| `LLMProvider` | Sends prompts, returns responses | `OllamaProvider` |
| Exporters | Generates detection rules | `SuricataExporter`, `SigmaExporter` |
| Connectors | Retrieves PCAPs from sources | `SecurityOnionConnector`, `ArkimeConnector` |
| DAWN Links | Self-contained pipeline stages | 11 implemented links |

---

## 12. Configuration Resolution Strategy

Settings are resolved in three-tier priority order:

```
[ SettingsDB row ] ─── highest priority
        │
        ▼
[ Environment vars ] ─── medium priority
        │
        ▼
[ Hard-coded defaults ] ─── lowest priority
```

This allows runtime configuration via the API without restarting containers, standard Docker Compose environment variables for deployment, and sane defaults for development.

---

## 13. Cross-Job Campaign Detection

The `correlate.campaign` DAWN link detects shared campaigns across independent analysis jobs:

1. **Load** all confirmed findings with MITRE technique IDs across all jobs
2. **Build** an inverted index keyed by `(mitre_technique_id, affected_ip)`
3. **Filter** to entries spanning ≥ 2 distinct job IDs
4. **Emit** `CorrelationGroup` objects with deterministic IDs and confidence scores

Confidence increases with more distinct jobs sharing the same indicator, higher individual finding confidence scores, and more diverse MITRE techniques per group.

---

## 14. Trade-offs & Known Limitations

### LLM Latency

A full analysis with the Specialist Pyramid takes 30–120 seconds depending on PCAP size and sensitivity setting. HIGH sensitivity adds the L3 Mc4minta stage, which can add 20–40 seconds for large sample sets.

### SQLite Concurrency

SQLite's write-lock semantics are acceptable for AIPAM's single-pipeline-per-job workload but would become a bottleneck at scale. SQLModel supports PostgreSQL migration with minimal code changes.

### Context Window Constraints

Large PCAPs with 10,000+ flows are mitigated by the two-stage triage approach, which reduces LLM input by ~99%. A future improvement would be hierarchical summarization.

### Sensitivity Setting Tradeoff

The `LOW/HIGH` sensitivity routing is binary. A future improvement could add a `MEDIUM` tier or make the decision adaptive based on the L2 analysis results.

### Simulation Script Fidelity

The Purple Team scripts generate structurally similar traffic but cannot perfectly replicate encrypted payload content. They are designed for sensor validation, not adversary simulation training.

### Embedding Model Size vs. Quality

The chosen embedding model (`all-MiniLM-L6-v2`, 22M parameters, 384 dimensions) prioritizes inference speed over retrieval quality. Larger models would improve RAG accuracy but increase compute requirements.

### ChromaDB Scale

The global forensic memory grows linearly with confirmed findings. At very large scale (100,000+ findings), ChromaDB may require index optimization or migration to a distributed vector store.

---

## 15. Continuous Improvement: The Self-Healing Training Loop

The Specialist Pyramid is not static — Phase 6 introduces a closed-loop system that continuously improves the forensic model's capabilities without degrading existing knowledge.

### 15.1 ORPO Contrastive Training (Phase 6.1)

Traditional SFT teaches the model *what to say*. ORPO (Odds Ratio Preference Optimization) teaches it *what not to say*:

- **Chosen responses**: Correct classification with verified evidence
- **Rejected responses**: Same classification but with corrupted evidence (swapped IPs, fabricated MITRE IDs)

This trains the model to understand that *correct classification + wrong evidence = failure*, directly suppressing hallucination at the training level rather than relying solely on runtime guardrails.

### 15.2 Localized Fine-Tuning — LocFT (Phase 6.5)

The key innovation enabling sustainable model updates:

- **Target**: Only the `down_proj` MLP matrices (the "Locus of Factual Knowledge")
- **Layer Masking**: Freeze Grammar Layers (0–15 for 8B, 0–7 for 1B), train only Knowledge Layers (16–30 for 8B, 8–15 for 1B)
- **Breadth-First Buffer**: Never train on fewer than 3 distinct malware families per run

This allows sequential knowledge edits (adding new malware families) without catastrophic forgetting of previously learned families or degradation of core reasoning ability.

### 15.3 The Self-Healing Loop (Phase 6.4+6.5)

Orchestrated by `run_v6_self_heal.sh`:

```
[Deployed v6 Model] → verify_model_bias.py → Failing families?
                                                    │
                              ┌──────────────────────┤
                              ▼                      ▼
                         No failures            Failures found
                         (exit clean)                │
                                                     ▼
                                        purple_team_augment.py
                                        (synthetic PCAPs)
                                                     │
                                                     ▼
                                        Breadth-First Buffer
                                        (≥3 families? → train)
                                                     │
                                                     ▼
                                        finetune_llama_orpo.py
                                        (--locft-mode delta LoRA)
                                                     │
                                                     ▼
                                        verify_model_bias.py
                                        (confirm improvement)
```

### 15.4 Entropy Monitoring

Reasoning Entropy (RE) tracks model diversity across the self-healing cycle. If entropy collapses below the threshold, the system recommends a full refresh from the v6 base model rather than continuing delta updates.

### 15.5 Student Distillation (Phase 6.3)

The 8B Teacher's forensic knowledge is distilled into a 1B Student for edge deployment:

1. Teacher generates high-quality labels via `distill_generate_labels.py`
2. Student trains on Teacher-generated ORPO pairs via `finetune_llama_distill.py`
3. Retention gate validates ≥90% accuracy parity
4. Student exported as GGUF Q4_K_M for Ollama edge sensors

### 15.6 DAWN Training Ledger

Every training event (start, complete, fail) produces an immutable JSONL entry in `dawn_training_ledger.jsonl` with a SHA-256 config hash. This satisfies the DAWN V1 (Audit Integrity) constitutional requirement and ensures training reproducibility.

---

## Appendix: Key Source Files

### DAWN Links

| Link | Purpose |
|------|---------|
| [aipam.ingest.pcap](file:///Users/vinsoncornejo/DAWN/dawn/links/aipam.ingest.pcap/run.py) | PCAP validation, Zeek/Suricata extraction, Flow IR generation |
| [analyze.forensic_cot](file:///Users/vinsoncornejo/DAWN/dawn/links/analyze.forensic_cot/run.py) | L1 triage + L2 Chain-of-Thought forensic reasoning |
| [analyze.deep_malware](file:///Users/vinsoncornejo/DAWN/dawn/links/analyze.deep_malware/run.py) | L3 Mc4minta malware family identification |
| [report.narrative](file:///Users/vinsoncornejo/DAWN/dawn/links/report.narrative/run.py) | LLM-synthesized forensic storyline |
| [memory.vector_index](file:///Users/vinsoncornejo/DAWN/dawn/links/memory.vector_index/run.py) | ChromaDB global forensic memory indexing |
| [simulate.traffic_pattern](file:///Users/vinsoncornejo/DAWN/dawn/links/simulate.traffic_pattern/run.py) | Purple Team Scapy script generation |

### Pipeline

| File | Purpose |
|------|---------|
| [aipam_forensic.yaml](file:///Users/vinsoncornejo/DAWN/dawn/pipelines/aipam_forensic.yaml) | Complete pipeline contract with sensitivity routing |

### Backend

| File | Purpose |
|------|---------|
| [main.py](file:///Users/vinsoncornejo/AIPAM/backend/app/main.py) | FastAPI API server (35+ endpoints) |
| [chat_service.py](file:///Users/vinsoncornejo/AIPAM/backend/app/chat_service.py) | Three-source RAG chat with forensic memory |
| [forensic_memory.py](file:///Users/vinsoncornejo/AIPAM/backend/app/forensic_memory.py) | Global ChromaDB interface |
| [engine.py](file:///Users/vinsoncornejo/AIPAM/backend/app/core/engine.py) | ForensicEngine + ChainOfThoughtAnalyzer |
| [llm_client.py](file:///Users/vinsoncornejo/AIPAM/backend/app/llm_client.py) | Dual LLM client, prompt construction |
| [anomaly_detector.py](file:///Users/vinsoncornejo/AIPAM/backend/app/anomaly_detector.py) | 10+ heuristic detectors |
| [correlation.py](file:///Users/vinsoncornejo/AIPAM/backend/app/core/correlation.py) | Cross-job campaign detection |
| [settings_runtime.py](file:///Users/vinsoncornejo/AIPAM/backend/app/settings_runtime.py) | Three-tier configuration resolution |

### Verification Scripts

| File | Purpose |
|------|---------|
| [verify_pyramid.py](file:///Users/vinsoncornejo/AIPAM/scripts/verify_pyramid.py) | Golden Scenario test harness (3 deterministic tests) |
| [closed_loop_test.py](file:///Users/vinsoncornejo/AIPAM/scripts/closed_loop_test.py) | Purple Team closed-loop validation |

### Frontend

| File | Purpose |
|------|---------|
| [JobDetailPage.tsx](file:///Users/vinsoncornejo/AIPAM/frontend/src/pages/JobDetailPage.tsx) | Job results, MITRE display, download simulation button |
| [api.ts](file:///Users/vinsoncornejo/AIPAM/frontend/src/api.ts) | Typed API client with simulation endpoint |
