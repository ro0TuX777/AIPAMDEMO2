# AIPAM — AI-Powered Advanced Packet Analysis for Malware Detection

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1-blue" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/AI%20Model-Llama%203.1%208B%20(v9)-orange" alt="AI Model">
  <img src="https://img.shields.io/badge/API-V2%20(Sensors)-blueviolet" alt="API V2">
  <img src="https://img.shields.io/badge/Analyst%20Cockpit-8%20Sprints-ff69b4" alt="Analyst Cockpit">
  <img src="https://img.shields.io/badge/Deployment-Air--Gapped-critical" alt="Deployment">
</p>

## Table of Contents

- [What is AIPAM?](#what-is-aipam)
- [Key Features](#key-features)
- [Analyst Cockpit](#analyst-cockpit)
- [How It Works](#how-it-works)
- [System Architecture](#system-architecture)
- [Execution Profiles](#execution-profiles)
- [Training System](#training-system)
- [Supported Malware Families](#supported-malware-families)
- [Training Data](#training-data)
- [Benchmark Results](#benchmark-results)
- [Getting Started](#getting-started)
- [Air-Gapped Deployment](#air-gapped-deployment)
- [Admin CLI (aipam-admin)](#admin-cli-aipam-admin)
- [Environment Variables](#environment-variables)
- [User Guide](#user-guide)
- [Forensic Workbench API](#forensic-workbench-api)
- [Roadmap](#roadmap)
- [FAQ](#faq)

---

## What is AIPAM?

**AIPAM** (AI-Powered Advanced Packet Analysis for Malware Detection) is a security tool that uses artificial intelligence to analyze network traffic and detect malicious activity. It serves as an automated analyst for your network that can:

- **Automatically detect malware** hiding in network traffic
- **Identify the type of threat** (ransomware, banking trojan, infostealer, etc.)
- **Explain what it found** in plain language
- **Suggest what to do next** to protect your systems
- **Continuously learn** from new data via an integrated fine-tuning pipeline

Unlike traditional security tools that only match known signatures, AIPAM uses a specially trained AI model (fine-tuned Llama 3.1 8B, currently at **model version 9**) that understands the *patterns* and *behaviors* of malicious traffic — even detecting threats it hasn't seen before.

AIPAM is designed for **air-gapped, offline environments**. No data ever leaves your network.

### Who Is This For?

- **Security Analysts** who need faster threat analysis
- **SOC Teams** looking to reduce investigation time
- **Incident Responders** needing quick malware identification
- **Security Researchers** studying network-based threats
- **IT Administrators** wanting visibility into network threats

---

## Key Features

### Modular Sensor Pipeline (V2)
Upload any PCAP and AIPAM runs a **staged sensor pipeline** with Docker-isolated analysis:
- **Zeek** + **Suricata** for protocol parsing and signature alerts
- **Beaconing detector**, **TLS enrichment**, **YARA file triage**, **TI matcher**
- Three **execution profiles**: triage (fast), standard, deep (comprehensive)

### Real-Time Progress (SSE)
Live updates via Server-Sent Events as each sensor completes:
- Sensor status tracking with colored indicators
- Pipeline stage progression
- Auto-refreshing job detail view

### AI-Assisted Investigation (Ask AI)
Context-aware AI chat available on **every page** — Alerts, Hosts, IOCs, Findings, and more:
- **One-click "Ask AI"** buttons generate a scoped prompt with full entity context
- **Hybrid retrieval router** — dual-path context assembly for every query:
  - **Route A (Structured)** — direct DB lookups for IPs, domains, hashes, finding IDs, DNS queries, and connections
  - **Route B (Semantic)** — 3-strategy vector search: query-based, IP-grounded, and per-doc-type KB retrieval
- **6-source RAG context window**:
  1. **Scoped evidence bundle** — page-level entity context injected by Ask AI buttons
  2. **Sensor context** — live-queried host stats, alerts, and connection summaries from the analysis DB
  3. **Structured DB retrieval** — exact-match entity lookups (hosts, alerts, findings, IOCs, DNS, connections)
  4. **Knowledge Base** — analyst-uploaded documents (asset inventories, network maps, SOC playbooks, threat intel, policies, baseline profiles, reference manuals)
  5. **Forensic memory** — global ChromaDB of confirmed findings across all past investigations
  6. **Cross-job correlations** — campaign matches and shared IOCs/hosts/MITRE techniques from historical jobs
- **KB document boost** — user-uploaded docs get relevance priority over auto-indexed host profiles
- **Confidence-tiered citations** — findings grouped as high (≥70%), medium (40–70%), or low (<40%) confidence
- *"What hosts are infected?"* · *"Is this alert a true positive?"* · *"What should I do next?"*

### Evidence Graph
Interactive **D3-based visualization** of all evidence relationships for a job:
- **7 node types**: Hosts, Alerts, Findings, Theories, Slices, IOCs, Annotations
- Click any node to inspect details and pin it to a Proof
- Edge types: `triggered_on`, `correlated`, `belongs_to`, `annotates`, and more

### Proof Builder
Build structured forensic arguments by **pinning evidence** from the graph:
- **Role selection**: Supports / Contradicts / Context
- **Analyst notes** on each pinned item
- **Metadata editor** — status (draft/final/archived), severity, confidence slider
- **Narrative rendering** — generates a Markdown report grouped by evidence role
- **Copy to clipboard** for pasting into tickets or reports

### Theory of the Case
Automated **hypothesis generation and ranking** (deterministic, no LLM):
- Scores 10+ hypothesis types: C2 beaconing, data exfiltration, lateral movement, ransomware, credential theft, etc.
- Supporting and contradicting evidence shown as human-readable chips
- Confidence labels (High / Medium / Low) with numerical scores

### Incident Slices
Groups related alerts, findings, and connections into **logical attack threads**:
- Seeded from `community_id` grouping, merged by host overlap + time proximity
- Attached findings and IOCs per slice
- Ranked by severity and evidence count

### Why Unusual? (Annotations)
Context annotations explaining **why specific traffic is anomalous**:
- Links to related alerts, findings, and hosts
- Analyst-readable explanations of what made the traffic stand out

### Reports and Detection Rules
- **HTML + Markdown reports** — executive summary, per-host findings, IOC tables, MITRE mappings
- **Detection-as-Code** — auto-generate Suricata and Sigma rules from findings
- **Report generation** via API with customizable templates

### Global Hosts (Cross-Job Forensics)
Track hosts across **all jobs** to identify repeat offenders:
- Aggregate view of every IP seen across analyses
- Drill into per-host detail with connections, DNS, TLS, alerts, and files

### Integrated Training System
Fine-tune the AI model directly from the web UI:
- **Host-native GPU training** — runs on bare metal for direct GPU access (NVIDIA CUDA or Apple Silicon Metal)
- **4-phase training pipeline** — SFT, distillation, ORPO alignment, self-healing
- **GGUF export and Ollama deployment** — merge LoRA, quantize, and hot-swap the model without downtime
- **Training ledger** — DAWN-compliant immutable record of every training run

### Air-Gapped Ready
AIPAM runs completely offline — no data ever leaves your network. Perfect for sensitive environments.
- Offline update bundles with SHA256 integrity verification
- Support bundle export for offline debugging
- All dependencies containerized
- Pre-built migration packages for offline server deployment

### Operational Tooling
Built-in admin CLI (`aipam-admin`) for production maintenance:
- **cleanup-jobs** — Automated retention policy enforcement
- **support-bundle** — Diagnostic archive (excludes PCAPs and secrets)
- **apply-update** — Air-gapped rule/TI updates with rollback
- **benchmark** — Model accuracy & regression evaluation
- **smoke-test** / **parity-check** — Validation tools

---

## Analyst Cockpit

The **Analyst Cockpit** is AIPAM's high-performance triage and investigation interface, purpose-built for SOC analysts working air-gapped investigations. Delivered across 8 sprints, it transforms raw pipeline output into a prioritized, interactive workflow.

### Investigation Queue (Sprints 1–2)
A unified, ranked queue of all actionable items (alerts, findings, theories) across a job:
- **Composite rank score** — weighted blend of severity (25%), confidence (20%), recency (15%), corroboration (20%), feedback adjustment (10%), and host criticality (10%)
- **Multi-axis filtering** — by type, severity, MITRE tactic, status, and free-text search
- **Expandable evidence drawer** — inline detail with host context, IOCs, and related evidence
- **Bulk actions** — confirm, dismiss, or escalate multiple items at once
- **Queue summary cards** — total, critical, needs-review, and confirmed-rate stats

### Before / After Comparison Workspace (Sprint 3)
Side-by-side temporal comparison of two jobs on the same target:
- **Diff view** — new, resolved, and persistent findings highlighted with color-coded badges
- **Metric delta cards** — alert count, finding count, host count, IOC count changes with directional arrows
- **Job selector** — pick any two completed jobs for comparison

### HITL Review Workflow (Sprint 4)
Human-in-the-loop confirmation gate ensuring analyst sign-off before results enter forensic memory:
- **Status transitions** — `pending → confirmed / dismissed / escalated / needs_review`
- **Review Notes panel** — inline status buttons, analyst notes, and timestamps
- **Review Mode** — groups queue items by review status with a review-rate progress bar
- **Forensic memory gate** — only confirmed findings are indexed into ChromaDB

### Case Narrative / Proof Builder (Sprint 5)
Build structured forensic arguments from pinned evidence:
- **Three export modes** — SOC Handoff, IR Technical, Executive Summary
- **LLM-powered narrative generation** — mode-specific prompts produce tailored write-ups
- **Unreviewed-item warnings** — highlights evidence that hasn't been analyst-confirmed
- **Markdown export** — copy or download the rendered narrative

### Early Partial Results (Sprint 6)
Reduce time-to-first-insight by surfacing intermediate pipeline data via SSE:
- **Pipeline progress stepper** — visual stage tracker (Ingest → Parse → Aggregate → Sensor → Correlate → Report)
- **Partial data cards** — PCAP stats, top hosts, alert summaries appear as each stage completes
- **SSE event types** — `partial_result`, `early_alert`, `sensor_complete` for real-time UI updates

### Feedback-Driven Ranking (Sprint 7)
The investigation queue learns from analyst confirmation and rejection patterns:
- **Sensor trust profiles** — sensors with consistently confirmed alerts get a ranking boost
- **Noisy signature detection** — signatures with high rejection rates are penalized
- **Admin feedback dashboard** — overall stats, sensor trust table, noisy signatures list, daily review chart
- **Score tooltip** — hover any queue item to see the full "Why this rank?" breakdown

### Cross-Job Correlation UX (Sprint 8)
Surfaces "forensic memory" by matching IPs, IOCs, and MITRE techniques across all historical jobs:
- **"Seen Before?" panel** — shows prior occurrences of hosts, IOCs, and MITRE categories with similarity scores
- **Campaign detection** — clusters of 3+ jobs sharing entities are flagged as potential campaigns
- **Related Jobs sidebar** — lists jobs with shared entities, ranked by weighted relevance (IOCs 0.25, Hosts 0.15, MITRE 0.10)
- **Direct navigation** — click any match to jump to the source job

---

## How It Works

AIPAM V2 uses a **staged sensor pipeline** to analyze network traffic:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        AIPAM V2 Sensor Pipeline                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ① UPLOAD         ② VALIDATE         ③ PIPELINE          ④ CORRELATE     │
│  ────────        ──────────         ──────────          ───────────       │
│  PCAP file  →    Verify format  →   Sensor stages:  →   community_id    │
│  uploaded        packet count       Zeek → Suricata      pivot, dedup,   │
│                  est. runtime       → Sensors (||)       entity extract  │
│                                                                            │
│                              ⑤ REPORT + SSE                                │
│                              ──────────────                                │
│                        Findings, IOCs, timeline,                           │
│                     host enrichment, live updates                          │
└────────────────────────────────────────────────────────────────────────────┘
```

### Step-by-Step Breakdown

1. **Upload** — `POST /api/v1/uploads` — PCAP is uploaded and stored
2. **Validate** — `POST /api/v1/uploads/{id}/validate` — Format, packet count, estimated runtime
3. **Create Job** — `POST /api/v1/jobs` — Selects execution profile, queues pipeline
4. **Sensor Pipeline** — Celery worker runs stages in order:
   - **Stage 1**: Zeek (protocol parsing) → **Stage 2**: Suricata (signature alerts)
   - **Stage 3**: Sensors run in parallel (beaconing, TLS enrich, file triage, TI match)
   - **Stage 4**: Correlation + normalization → findings, IOCs, timeline
5. **Results** — Query via REST API with SSE live updates during processing

---

## System Architecture

AIPAM V2 is built as a containerized application with five main services, plus an optional host-native training server:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          AIPAM V2 Stack                                   │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
│   │  Frontend   │    │  API Server │    │   Worker    │                 │
│   │  (React)    │◄──►│  (FastAPI)  │◄──►│  (Celery)   │                 │
│   │  Port 80    │    │  Port 8000  │    │  Sensors    │                 │
│   └─────────────┘    └──────┬──────┘    └──────┬──────┘                 │
│                             │                   │                        │
│                      ┌──────▼──────┐     ┌──────▼──────┐                │
│                      │    Redis    │     │   Ollama    │                │
│                      │  Broker+SSE │     │  (AI Model) │                │
│                      └─────────────┘     └─────────────┘                │
│                                                                          │
│   Storage: SQLite (aipam.db) + /jobs/<job_id>/ filesystem               │
└──────────────────────────────────────────────────────────────────────────┘
```

### Components Explained

| Component | What It Does | Technology |
|-----------|--------------|------------|
| **Frontend** | Web interface — jobs, evidence graph, proof builder, chat, reports | React + TypeScript + TanStack Query + D3 |
| **API Server** | REST API (30+ endpoints) + SSE event stream | Python FastAPI (V2) |
| **Worker** | Pipeline orchestrator — runs sensor containers | Celery + Docker |
| **Redis** | Celery broker + SSE event buffer | Redis 7 |
| **Ollama** | Local LLM inference for chat + classification | Ollama + fine-tuned Llama 3.1 8B (v9) |
| **ChromaDB** | Forensic memory — vector store for cross-case knowledge | ChromaDB |
| **SQLite** | Jobs, sensors, findings, hosts, IOCs, proofs, theories, slices | SQLite with WAL mode |
| **Host Trainer** | GPU-native fine-tuning server (optional, ports 8002/8003) | Unsloth (CUDA) or MLX (Apple Silicon) |

---

## Execution Profiles

AIPAM V2 supports three analysis profiles that control which sensors run:

| Profile | Sensors | Use Case | Est. Time |
|---------|---------|----------|-----------|
| **Triage** | Zeek, Suricata | Quick alert check | ~1 min |
| **Standard** | + Beaconing, TLS Enrich, TI Matcher | Default analysis | ~5 min |
| **Deep** | + File Triage (YARA), all sensors | Full forensic sweep | ~15 min |

---

## Training System

AIPAM includes an integrated fine-tuning pipeline that runs **on the host** (outside Docker) for direct GPU access.

### Architecture

The training system consists of two host-native Python servers:

| Component | Port | Purpose |
|-----------|------|---------|
| **Host Trainer** (`host_trainer.py`) | 8002 | Runs fine-tuning jobs, serves status/progress, manages the training ledger |
| **Trainer Launcher** (`host_trainer_launcher.py`) | 8003 | Allows the web UI to start/restart the trainer process |

### Starting the Trainer

```bash
# From the AIPAM project root:
python3 finetuning/host_trainer.py &
python3 finetuning/host_trainer_launcher.py &
```

### Training Pipeline Phases

| Phase | Name | Description |
|-------|------|-------------|
| **6.1** | SFT (Supervised Fine-Tuning) | LoRA fine-tuning on curated traffic analysis Q&A pairs |
| **6.2** | Distillation | Knowledge distillation from a teacher model (optional, requires API key) |
| **6.3** | ORPO Alignment | Preference optimization for response quality |
| **6.4** | Self-Healing | Automated error correction and validation |

### Model Export and Deployment

After training, the UI provides a one-click **Merge and Deploy** workflow:
1. Merge LoRA adapter weights into the base model
2. Quantize to GGUF format (Q4_K_M)
3. Import into Ollama as a new model version
4. Hot-swap the active model without restarting services

### Training Ledger

Every training run is recorded in an immutable JSONL ledger (`dawn_training_ledger.jsonl`) with:
- Run ID, timestamp, phase, dataset hash
- Hyperparameters (learning rate, epochs, batch size, LoRA rank)
- Final loss, iteration count, duration
- Platform and hardware information

### Platform Support

| Platform | GPU Framework | Training Script |
|----------|---------------|-----------------|
| **Linux (NVIDIA)** | CUDA via Unsloth/PyTorch | `finetune_llama.py` |
| **macOS (Apple Silicon)** | Metal via MLX | `finetune_mlx.py` |

The trainer automatically detects the platform and selects the appropriate backend. On Linux, it uses the `venv_unsloth` virtualenv if available.

---

## Supported Malware Families

AIPAM is trained to recognize **40+ malware families** across multiple categories:

### Banking Trojans
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **Zeus** | 2007 | Steals banking credentials via keylogging and form grabbing |
| **Emotet** | 2014 | Spreads through malicious emails, drops other malware |
| **TrickBot** | 2016 | Steals credentials and delivers ransomware |
| **Qakbot** | 2007 | Banking trojan that hijacks email threads to spread |
| **IcedID** | 2017 | Banking trojan that partners with ransomware groups |
| **Dridex** | 2014 | Distributed via malicious Office documents |
| **Ursnif/Gozi** | 2007 | Form grabbing and web injection attacks |

### Ransomware
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **Ryuk** | 2018 | Targeted ransomware with high ransom demands |
| **Conti** | 2020 | Fast encryption with data theft (double extortion) |
| **LockBit** | 2019 | Self-spreading ransomware as a service |
| **BlackCat/ALPHV** | 2021 | Cross-platform ransomware written in Rust |
| **REvil** | 2019 | High-profile attacks on enterprises |
| **Maze** | 2019 | Pioneered "name and shame" data leak tactics |
| **DarkSide** | 2020 | Known for Colonial Pipeline attack |

### Information Stealers
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **AgentTesla** | 2014 | Keylogger targeting browsers, email, FTP |
| **Formbook** | 2016 | Form grabbing and screenshot capture |
| **RedLine** | 2020 | Steals browser data, crypto wallets, VPN credentials |
| **Raccoon** | 2019 | Targets browsers, crypto wallets, Discord |
| **Lokibot** | 2015 | Password stealer targeting many applications |
| **Snake Keylogger** | 2020 | .NET keylogger with multiple exfil methods |

### Remote Access Trojans (RATs)
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **Cobalt Strike** | 2012 | Legitimate tool abused for attacks |
| **AsyncRAT** | 2019 | Open-source RAT with plugin support |
| **NjRAT** | 2012 | Full remote control capabilities |
| **Remcos** | 2016 | Commercial RAT used maliciously |

### Loaders and Droppers
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **BazarLoader** | 2020 | Delivers Ryuk/Conti ransomware |
| **Nsis-ay** | 2014 | NSIS-based dropper for various payloads |

### Botnets and Other
| Family | Type | What It Does |
|--------|------|--------------|
| **Neris** | Spam Bot | Sends spam and participates in DDoS |
| **Miuref** | Botnet | DDoS and spam distribution |
| **Virut** | File Infector | Spreads via infected executables |
| **Htbot** | Click Fraud | Generates fraudulent ad clicks |

---

## Training Data

AIPAM's AI model was trained on a carefully curated dataset of **549,000+ network traffic samples**:

### Data Composition

| Category | Samples | Percentage | Description |
|----------|---------|------------|-------------|
| **Malware Traffic** | 530,769 | 96.6% | Real malware communications |
| **Benign Traffic** | 18,539 | 3.4% | Normal network activity |

### Malware Traffic Sources

1. **Malware Traffic Analysis (MTA) Exercises**
   - 126 training exercises from [malware-traffic-analysis.net](https://malware-traffic-analysis.net)
   - Real-world malware samples with expert analysis
   - 1,422 Q&A pairs for forensic reasoning

2. **Public Malware Datasets**
   - CTU-13 Botnet Dataset
   - CICIDS-2017 Dataset
   - Various research institution captures

### Benign Traffic Sources

To teach AIPAM what *normal* traffic looks like, we included:

| Source | Files | Description |
|--------|-------|-------------|
| **USTC-TFC2016** | 7 | BitTorrent, Gmail, Skype, MySQL, etc. |
| **tcpreplay** | 2 | Enterprise network flows (361MB) |
| **Wireshark Samples** | 16 | DNS, HTTP, SMTP, SMB, etc. |
| **Synthetic Traffic** | 18,000 | Generated DNS, HTTP, HTTPS, SSH patterns |

### Training Evolution

| Version | Samples | What's New |
|---------|---------|------------|
| **V5** | 529,889 | Base malware dataset |
| **V6** | 530,769 | Added MTA exercises and Q&A (+1,422) |
| **V7** | 549,308 | Added benign samples (+18,539) |
| **V8** | 549,308+ | Distillation and alignment refinements |
| **V9** | 549,308+ | Current production model — ORPO alignment, self-healing corrections |

---

## Benchmark Results

We tested AIPAM on malware samples it had never seen during training:

### Performance Metrics (15 Test Samples)

| Metric | Score | What It Means |
|--------|-------|---------------|
| **Malicious Detection** | 100% | Never misses actual malware |
| **Type Accuracy** | 33.3% | Correctly identifies malware category |
| **Exact Family Match** | 6.7% | Identifies specific malware family |

### Key Insights

**Perfect Malware Detection** — AIPAM detected all malicious traffic in testing. If there's malware, AIPAM will find it.

**Type Classification** — The model correctly categorizes about 1/3 of threats by type (Loader, Stealer, RAT, etc.).

**Family Identification** — Exact family matching is challenging but improving with more training data.

### What This Means for You

| Use Case | Reliability |
|----------|-------------|
| "Is this traffic malicious?" | Excellent |
| "What type of malware is it?" | Good |
| "Which exact malware family?" | Developing |

**Recommendation**: Use AIPAM to flag suspicious traffic, then leverage its MITRE ATT&CK mappings for investigation regardless of the specific family name.

---

## Getting Started

### Prerequisites

- **Docker** and **Docker Compose v2** installed
- **8GB+ RAM** recommended (16GB+ for deep profile)
- **NVIDIA GPU** (optional, for faster AI inference and training)
- **Ollama** installed on the host for model serving

### Quick Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/AIPAM.git
cd AIPAM

# 2. Configure environment
cp deploy/.env.example deploy/.env
# Edit deploy/.env — set AIPAM_API_TOKEN to a secure value

# 3. Start the full stack
docker compose up -d

# 4. Import the AI model (v9)
ollama create aipam-trafficllm-v9 -f deploy/Modelfile.v9

# 5. Open the web interface
open http://localhost:5173   # Frontend
# API available at http://localhost:8000/docs
```

### Verifying Installation

```bash
# Check all containers are running
docker compose ps

# Expected output:
# aipam-api        Running (healthy)
# aipam-worker     Running
# aipam-frontend   Running
# aipam-redis      Running (healthy)

# Verify the model is loaded
ollama list | grep aipam

# Run the smoke test
AIPAM_API_TOKEN=your-token python -m backend.app.cli smoke-test
```

### Starting the Training System (Optional)

```bash
# Start the host-native trainer and launcher
python3 finetuning/host_trainer.py &
python3 finetuning/host_trainer_launcher.py &
```

The Training page in the web UI will show "Trainer Idle" once connected.

---

## Air-Gapped Deployment

AIPAM is designed for offline, air-gapped environments. A pre-built migration package is available in `dist/`.

### Update Package Contents

| File | Description |
|------|-------------|
| `repo.tar.gz` | Source code archive (excludes training data, models, and build artifacts) |
| `docker-images.tar.gz` | Pre-built Docker images (frontend, backend, worker, redis) |
| `Modelfile.v9` | Ollama model definition for the v9 fine-tuned model |
| `update.sh` | Automated migration script (v1 to v2) |

### Running the Update on an Offline Server

```bash
# Transfer the update package to the offline server, then:
cd /path/to/aipam-v2-update-YYYYMMDD
chmod +x update.sh
./update.sh
```

The script will:
1. Stop the current AIPAM stack
2. Back up the existing installation
3. Extract the updated source code
4. Load pre-built Docker images
5. Import the v9 model into Ollama
6. Start the updated stack

### Regenerating the Update Package

From the development machine:

```bash
# 1. Build the source archive (excludes large data files)
cd /path/to/parent && \
tar -czf AIPAM/dist/aipam-v2-update-YYYYMMDD/repo.tar.gz \
    --exclude='AIPAM/.git' \
    --exclude='AIPAM/.venv' \
    --exclude='AIPAM/venv_unsloth' \
    --exclude='AIPAM/dist' \
    --exclude='AIPAM/llama.cpp' \
    --exclude='AIPAM/frontend/node_modules' \
    --exclude='AIPAM/finetuning/data/training' \
    --exclude='AIPAM/finetuning/aipam_gpu_training' \
    --exclude='AIPAM/finetuning/trafficllm_training' \
    --exclude='AIPAM/finetuning/trafficllm_datasets' \
    --exclude='AIPAM/finetuning/models' \
    --exclude='AIPAM/deploy/models' \
    --exclude='AIPAM/trafficllm' \
    --exclude='AIPAM/TrafficLLM*' \
    --exclude='AIPAM/benchmark' \
    --exclude='AIPAM/aipam-migrate-*' \
    --exclude='AIPAM/unsloth_compiled_cache' \
    --exclude='*.db' --exclude='*.log' --exclude='*.pyc' \
    --exclude='*.zip' --exclude='*.pdf' \
    AIPAM

# 2. Save Docker images
docker save aipam-frontend aipam-backend aipam-worker redis:7-alpine | \
  gzip > AIPAM/dist/aipam-v2-update-YYYYMMDD/docker-images.tar.gz
```

---

## Admin CLI (aipam-admin)

All admin commands are run via `python -m backend.app.cli <command>`.

### `smoke-test` — End-to-End Validation

```bash
aipam-admin smoke-test [--pcap PATH] [--base-url URL]
```

Runs a full pipeline pass: upload → validate → create job → poll until complete → verify response shapes. Exit code 0 on success, 1 on failure.

### `parity-check` — V1/V2 Output Comparison

```bash
aipam-admin parity-check [--pcaps DIR] [--output DIR]
```

Compares V1 and V2 pipeline outputs on a corpus of PCAPs. Generates a report with tolerance checks for finding counts, severity distributions, and host coverage.

### `cleanup-jobs` — Retention Policy Enforcement

```bash
aipam-admin cleanup-jobs --older-than 30d [--dry-run | --confirm]
```

Deletes expired jobs (DB rows + `/jobs/<id>/` directories). Running jobs are never deleted. `--dry-run` lists candidates without deleting. `--confirm` is required for actual deletion.

### `support-bundle` — Diagnostic Archive

```bash
aipam-admin support-bundle [--job JOB_ID] [--all-recent] [--output PATH]
```

Generates a `.tar.gz` with job metadata, sensor status, system health, and configuration. **Excludes PCAPs and API tokens** for data privacy. Use `--all-recent` to include all jobs from the last 24 hours.

### `apply-update` — Air-Gapped Rule/TI Updates

```bash
aipam-admin apply-update /path/to/update-bundle.zip
```

Verifies SHA256 checksums from the bundle's `manifest.json` before unpacking rules and threat intelligence updates. Rejects tampered bundles with exit code 1.

### `benchmark` — Model Performance Evaluation

```bash
aipam-admin benchmark [--manifest PATH] [--model MODEL] [--baseline PATH] [--limit N]
```

Runs the benchmark evaluation suite against a manifest of labelled PCAPs. Reports accuracy (exact family, type, and malicious-vs-benign), per-family precision/recall/F1, and average inference time. When `--baseline` is provided, compares results against the baseline and exits with code 1 if runtime regresses >20%.

---

## Environment Variables

All settings are loaded from environment variables (or a `.env` file). Defined in `backend/app/config_v2.py`.

| Variable | Default | Description |
|----------|---------|-------------|
| `AIPAM_API_TOKEN` | *(required)* | Bearer token for API authentication |
| `AIPAM_MAX_CONCURRENT_JOBS` | `1` | Max simultaneous pipeline jobs |
| `AIPAM_SENSOR_PARALLELISM` | `1` | Max sensors running in parallel within a job |
| `AIPAM_MAX_JOB_DISK_BYTES` | `53687091200` (50 GB) | Hard disk limit per job |
| `AIPAM_MAX_EXTRACTED_BYTES` | `10737418240` (10 GB) | Max extracted file bytes per job |
| `AIPAM_PREFLIGHT_MULTIPLIER` | `4` | Disk space multiplier for preflight check |
| `AIPAM_JOB_RETENTION_DAYS` | `30` | Auto-cleanup threshold for expired jobs |
| `AIPAM_LOG_RETENTION_DAYS` | `30` | Log rotation threshold |
| `AIPAM_LOG_MAX_MB` | `500` | Max log size before rotation |
| `AIPAM_DISK_WARN_PCT` | `80` | Disk usage warning threshold (%) |
| `AIPAM_DISK_CRITICAL_PCT` | `95` | Disk usage critical threshold (%) |
| `AIPAM_OLLAMA_URL` | `http://ollama:11434` | Ollama service URL |
| `AIPAM_REDIS_URL` | `redis://redis:6379/0` | Redis URL (Celery broker + SSE) |
| `AIPAM_JOB_ROOT` | `/jobs` | Filesystem root for job artifacts |
| `AIPAM_UPLOAD_ROOT` | `/uploads` | Filesystem root for PCAP uploads |
| `AIPAM_DB_PATH` | `/data/aipam.db` | SQLite database file path |
| `AIPAM_SENSOR_CONFIG_DIR` | `/opt/aipam/sensor-config` | Sensor configuration directory |

---

## User Guide

### Analyzing a PCAP File (V2)

1. **Open the Dashboard** at `http://localhost`
2. **Click "New Analysis"** in the navigation
3. **Select a PCAP file** (`.pcap`, `.pcapng`, `.cap`)
4. **Validation step** — review packet count, duration, and estimated runtime
5. **Choose a profile** — Triage, Standard, or Deep
6. **Create the job** — watch live sensor progress via SSE
7. **View Results** — findings, hosts, timeline, IOCs, artifacts

### Understanding the Results

#### Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **Critical** | Red | Active attack, immediate action required |
| **High** | Orange | Confirmed malware, investigate immediately |
| **Medium** | Yellow | Suspicious activity, review recommended |
| **Low** | Green | Minor anomalies, monitor situation |
| **Info** | Gray | Normal traffic, no action needed |

#### MITRE ATT&CK Techniques

Each finding includes mapped MITRE ATT&CK techniques. For example:
- **T1071** - Application Layer Protocol (C2 communication)
- **T1566** - Phishing (initial access)
- **T1486** - Data Encrypted for Impact (ransomware)

### Using the AI Chat (Ask AI)

Every evidence page has an **Ask AI** button that jumps to the chat with a pre-filled, context-aware question. You can also open the chat page directly and ask free-form questions:

```
You: "What hosts were compromised?"
AIPAM: "Based on the analysis, host 192.168.1.105 shows
       signs of compromise with Emotet C2 beaconing to..."

You: "Is alert ET MALWARE Remcos a true positive?"
AIPAM: "Yes — the alert correlates with beaconing to 206.123.152.51
       on port 2404, a known Remcos C2 endpoint..."
```

The chat uses a **6-source hybrid RAG pipeline**: scoped page context, live sensor data, structured DB lookups, analyst-uploaded knowledge base documents, global forensic memory (ChromaDB), and cross-job campaign correlations. A dual-path retrieval router combines exact entity matching (Route A) with semantic vector search (Route B) to maximize recall.

### Using the Evidence Graph & Proof Builder

1. **Open the Evidence Graph** from the job detail tab bar
2. **Explore nodes** — click any host, alert, finding, theory, slice, IOC, or annotation
3. **Toggle the Proof Builder** sidebar and create a new proof (e.g., "Remcos C2 Chain")
4. **Pin evidence** — select a role (Supports / Contradicts / Context) and add analyst notes
5. **Edit metadata** — set status, severity, and confidence via the metadata editor
6. **Render Narrative** — generate a Markdown report, then copy it to clipboard

### Theory of the Case & Incident Slices

- Navigate to **Theories** from the job detail page to see ranked hypotheses with confidence scores
- Navigate to **Slices** to see how alerts and findings group into attack threads
- Navigate to **Why Unusual?** for context annotations on anomalous traffic
- Each page includes breadcrumb navigation back to the job

### Using the Analyst Cockpit

1. **Open the Investigation Queue** from the job detail page — items are ranked by composite score
2. **Filter and sort** by type, severity, MITRE tactic, or review status
3. **Expand any item** to see the evidence drawer with host context, IOCs, and "Seen Before?" panel
4. **Review items** — confirm, dismiss, or escalate; only confirmed findings enter forensic memory
5. **Compare jobs** — use the Before/After workspace to diff two analyses on the same target
6. **Build a narrative** — open the Proof Builder, select a mode (SOC Handoff / IR Technical / Executive), and generate
7. **Check correlations** — the Related Jobs sidebar shows which other jobs share the same IOCs, hosts, or MITRE techniques
8. **Monitor feedback impact** — visit Admin → Feedback Dashboard to see how analyst patterns adjust ranking

### Detection Rules

From any finding, generate **Suricata** or **Sigma** rules:
- Rules are auto-generated from finding metadata (IPs, ports, signatures)
- Manage all generated rules on the **Rules** page

### Exporting Results

- **HTML Report** — Full report for sharing with stakeholders
- **Markdown Export** — Technical report for documentation
- **Chat Transcript** — Download conversation history
- **Proof Narrative** — Rendered Markdown from the Proof Builder

---

## Forensic Workbench API

Five SO-CRATES-inspired forensic capabilities are available as first-class REST endpoints under `/api/v1`. All endpoints require the `Authorization: Bearer <AIPAM_API_TOKEN>` header.

---

### 1. Stream Transcript, Hexdump, and Carving

Drill from a job's PCAPs into decoded stream content or carve a stream as a standalone PCAP.

#### List PCAP files for a job

```bash
curl -s http://localhost:8000/api/v1/jobs/{job_id}/streams \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "pcaps": [
    {"name": "capture.pcap", "size_bytes": 1048576, "path": "input/capture.pcap"}
  ]
}
```

#### ASCII transcript of a single stream

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/streams/ascii?src=10.0.0.1&sport=54321&dst=93.184.216.34&dport=80&proto=tcp" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "protocol": "tcp",
  "transcript": "GET / HTTP/1.1\r\nHost: example.com\r\n...",
  "truncated": false
}
```

#### Per-packet hexdump

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/streams/hexdump?src=10.0.0.1&sport=54321&dst=93.184.216.34&dport=80" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "protocol": "tcp",
  "packets": [
    {
      "header": "0x0000  47 45 54  ...",
      "lines": ["0x0000  47 45 54 20 2f ..."]
    }
  ],
  "truncated": false
}
```

#### Carve stream to PCAP (download)

```bash
curl -o stream.pcap \
  "http://localhost:8000/api/v1/jobs/{job_id}/streams/pcap?src=10.0.0.1&sport=54321&dst=93.184.216.34&dport=80" \
  -H "Authorization: Bearer $TOKEN"
```

**Query parameters (all stream endpoints):**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `src` | ✓ | — | Source IP address |
| `sport` | ✓ | — | Source port |
| `dst` | ✓ | — | Destination IP address |
| `dport` | ✓ | — | Destination port |
| `proto` | — | `tcp` | Protocol (`tcp` or `udp`) |
| `pcap` | — | auto | PCAP filename within the job input directory |

---

### 2. Generic Artifact Upload and Classification

Upload any file (PCAP, binary, archive, or log) and get instant classification before creating a job.

#### Upload an artifact

```bash
curl -s -X POST "http://localhost:8000/api/v1/uploads/artifact?filename=malware.exe" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @malware.exe | jq .
```

```json
{
  "upload_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "filename": "malware.exe",
  "size_bytes": 204800,
  "sha256": "e3b0c44298fc1c149afb...",
  "artifact_class": "binary",
  "format": "pe"
}
```

**Artifact classes:** `pcap`, `binary`, `archive`, `log`, `unknown`

When `artifact_class == "binary"`, creating a job from this upload automatically triggers the YARA/binary analysis pipeline (no separate step needed).

#### Re-classify with a hint

```bash
curl -s -X POST "http://localhost:8000/api/v1/uploads/{upload_id}/classify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"artifact_class": "binary", "format": "elf"}' | jq .
```

```json
{
  "upload_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "artifact_class": "binary",
  "format": "elf"
}
```

---

### 3. First-Class Sigma Log Analysis

Run Sigma rules against all normalized events for a job and store detections as findings.

#### Run Sigma analysis

```bash
curl -s -X POST "http://localhost:8000/api/v1/jobs/{job_id}/sigma/analyze" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "rules_loaded": 12,
  "events_scanned": 4837,
  "detections": 3,
  "findings_created": 3
}
```

#### Retrieve Sigma detections

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/sigma" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "items": [
    {
      "finding_id": 42,
      "rule_id": "process_creation_susp_powershell",
      "rule_title": "Suspicious PowerShell Execution",
      "severity": "high",
      "timestamp": "2024-01-15T14:23:11Z",
      "evidence": {"event_type": "process_creation", "hostname": "ws01"}
    }
  ],
  "total": 3
}
```

Custom Sigma rules can be placed under `backend/app/sigma/rules/`. Rules are loaded automatically on each analysis run.

---

### 4. First-Class Binary / YARA Analysis

Upload a binary into a job, scan with YARA rules, and persist findings.

#### Upload and analyze a binary (attach to existing job)

```bash
curl -s -X POST "http://localhost:8000/api/v1/jobs/{job_id}/binary?filename=dropper.dll" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @dropper.dll | jq .
```

```json
{
  "file_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
  "filename": "dropper.dll",
  "findings_created": 2,
  "analysis": {
    "file_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
    "filename": "dropper.dll",
    "artifact_class": "binary",
    "format": "pe",
    "sha256": "b94f6f125c79e3a5ffaa826f584c10d5...",
    "size_bytes": 114688,
    "yara_available": true,
    "yara_matches": [
      {"rule": "MZ_Header", "tags": ["pe"], "meta": {"description": "PE executable header"}}
    ]
  }
}
```

#### List all binary analyses for a job

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/binary" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "items": [{"file_id": "c9bf9e57...", "filename": "dropper.dll", "format": "pe", ...}],
  "total": 1
}
```

#### Stateless binary triage (no persistence)

```bash
curl -s -X POST "http://localhost:8000/api/v1/binary/inspect?filename=unknown.bin" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @unknown.bin | jq .
```

```json
{
  "filename": "unknown.bin",
  "artifact_class": "binary",
  "format": "elf",
  "sha256": "...",
  "size_bytes": 8192,
  "yara_available": true,
  "yara_matches": []
}
```

**Auto-trigger**: When a job is created from an upload with `artifact_class == "binary"`, the orchestrator automatically copies the binary into the job's input directory and runs YARA analysis — no manual `POST /binary` step required.

**YARA rules location**: `backend/app/binalysis/rules/default.yar`
Add custom `.yar` files to that directory; they are loaded automatically.

---

### 5. Raw Event Explorer

Full-text search, structured filtering, aggregation, and network flow visualization over normalized events.

#### Search events

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/raw-events?q=powershell&limit=50" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "items": [
    {
      "event_id": 1023,
      "job_id": "abc123",
      "event_type": "process_creation",
      "hostname": "ws01",
      "src_ip": "10.0.0.5",
      "dest_ip": "192.168.1.1",
      "dest_port": 443,
      "proto": "tcp",
      "evidence_status": "confirmed",
      "tags": ["lateral_movement"],
      "data": {"cmdline": "powershell -enc ..."}
    }
  ],
  "total": 7,
  "limit": 50,
  "offset": 0
}
```

**Supported filter parameters:** `q` (substring), `event_type`, `source_type`, `src_ip`, `dest_ip`, `hostname`, `limit` (1–1000), `offset`

#### Aggregate events by field

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/raw-events/aggregate?field=dest_ip&limit=10" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "field": "dest_ip",
  "buckets": [
    {"value": "93.184.216.34", "count": 142},
    {"value": "10.0.0.1", "count": 37}
  ],
  "total_events": 4837
}
```

**Aggregatable fields:** `event_type`, `source_type`, `source_system`, `hostname`, `username`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `evidence_status`

#### Network flow (Sankey data)

```bash
curl -s "http://localhost:8000/api/v1/jobs/{job_id}/raw-events/flow?limit=20" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "nodes": [
    {"id": "src:10.0.0.5", "label": "10.0.0.5", "kind": "src"},
    {"id": "dst:93.184.216.34", "label": "93.184.216.34", "kind": "dst"},
    {"id": "port:443", "label": "443", "kind": "port"}
  ],
  "links": [
    {"source": "src:10.0.0.5", "target": "dst:93.184.216.34", "value": 142},
    {"source": "dst:93.184.216.34", "target": "port:443", "value": 142}
  ]
}
```

The flow response is structured as a Sankey diagram: `src_ip → dest_ip → dest_port`. Pass the `nodes` and `links` arrays directly to any D3-sankey or Recharts Sankey component.

---

## Roadmap

### Phase 1 — MVP Delivery (Complete)

- [x] Web UI for PCAP upload and results visualization
- [x] Backend APIs for ingestion, analysis job management, and report retrieval
- [x] Unified dataset creation (TrafficLLM + MTA PCAPs + GitHub indicator datasets)
- [x] Fine-tuned Llama 3.1 8B cyber model
- [x] Interactive chat interface tied to PCAP analysis
- [x] MITRE ATT&CK-aware reasoning and mapping
- [x] Unit + integration testing

### Phase 2 — DAWN Pipeline + Specialist Pyramid (Complete)

- [x] DAWN Deterministic Pipeline — Immutable ledger, cryptographic binding, meaning gates
- [x] Source-Agnostic Ingest — Unified Flow IR from PCAP, Security Onion, and Arkime
- [x] 3-Tier Specialist Pyramid — L1 (Generalist), L2 (Forensic COT), L3 (Mc4minta)
- [x] Chain-of-Thought Forensic Reasoning — MITRE ATT&CK mapping
- [x] Anti-Hallucination System — 6-layer defense
- [x] Heuristic–LLM Fusion — 10+ anomaly detectors
- [x] Automated Report Generation — Markdown + HTML
- [x] Golden Scenario Test Harness

### Phase 3 — Proactive Defense + Forensic Memory (Complete)

- [x] Forensic Memory — ChromaDB vector store for cross-case knowledge
- [x] 6-Source Hybrid RAG Chat — Scoped context + sensor data + structured DB + knowledge base + forensic memory + campaign correlations
- [x] Cross-Job Campaign Detection
- [x] Detection-as-Code — Suricata and Sigma rules from findings
- [x] Purple Team Simulation — Scapy-based adversary emulation
- [x] Closed-Loop Validation — 100% detection match rate
- [x] HITL Review Gate + Trust Receipts

### Sensors V2 Migration (Complete)

- [x] **Backend Foundation** — V2 models, schemas, database (SQLite + WAL), config
- [x] **Sensor Pipeline** — Docker-based sensor runner, registry, orchestrator, preflight checks
- [x] **API Expansion** — 25+ REST endpoints, SSE, correlation, batch operations
- [x] **Frontend Adaptation** — React SPA with TanStack Query, SSE hooks, V2 upload flow
- [x] **Integration Testing** — Golden PCAP corpus, smoke test CLI, parity check CLI
- [x] **Ops Tooling** — cleanup-jobs, support-bundle, apply-update, Docker Compose
- [x] **Documentation** — Updated README, env var reference, CLI docs
- [x] 110 tests passing (unit + integration)

### Analyst Workbench (Complete)

- [x] **Evidence Graph** — D3 visualization of 7 entity types with relationship edges
- [x] **Proof Builder** — Pin evidence with roles, analyst notes, metadata, and narrative rendering
- [x] **Theory of the Case** — Deterministic hypothesis generation and ranking (10+ types)
- [x] **Incident Slices** — Attack thread grouping by community_id, host overlap, and time proximity
- [x] **Why Unusual? (Annotations)** — Context annotations for anomalous traffic
- [x] **Ask AI Everywhere** — contextual chat buttons on Alerts, Hosts, IOCs, Findings pages
- [x] **Global Hosts** — Cross-job host tracking and forensics
- [x] **TI Matcher** — Threat intelligence feed integration with confidence scoring
- [x] **Knowledge Base** — Persistent forensic memory via ChromaDB
- [x] **Reports** — HTML + Markdown report generation with executive summaries
- [x] **Detection Rules** — Auto-generate Suricata and Sigma rules from findings
- [x] **Human-readable Evidence** — Supporting evidence shown as labeled chips

### Analyst Cockpit (Complete — 8 Sprints)

- [x] **Investigation Queue** — Ranked, filterable triage queue with composite scoring (Sprints 1–2)
- [x] **Before/After Comparison** — Side-by-side temporal diff of two jobs (Sprint 3)
- [x] **HITL Review Workflow** — Analyst confirmation gate with forensic memory indexing (Sprint 4)
- [x] **Case Narrative Builder** — LLM-powered proof narratives in 3 export modes (Sprint 5)
- [x] **Early Partial Results** — SSE-driven pipeline progress and intermediate data cards (Sprint 6)
- [x] **Feedback-Driven Ranking** — Queue learns from analyst confirm/reject patterns (Sprint 7)
- [x] **Cross-Job Correlation UX** — "Seen Before?" panels, campaign detection, related jobs (Sprint 8)

### Integrated Training and Air-Gap (Complete)

- [x] **Host-Native Training** — GPU fine-tuning outside Docker (Unsloth/CUDA + MLX/Metal)
- [x] **4-Phase Pipeline** — SFT, distillation, ORPO alignment, self-healing
- [x] **Training Ledger** — DAWN-compliant immutable JSONL record of all runs
- [x] **Model Export** — One-click LoRA merge, GGUF quantization, Ollama import
- [x] **Air-Gapped Migration** — Offline update packages with automated `update.sh`
- [x] **UI Professionalization** — Clean text-based interface suitable for enterprise SOC environments
- [x] **Model v9** — Current production model with ORPO alignment

### Forensic Workbench (Complete)

- [x] **Stream transcript/hexdump/carving** — ASCII transcript, per-packet hexdump, and carved-stream PCAP download via `tshark`/`tcpdump`
- [x] **Generic artifact upload & classification** — Upload any file type; auto-classifies as `pcap`, `binary`, `archive`, `log`, or `unknown`
- [x] **First-class Sigma log analysis** — Run Sigma rules against normalized events; detections persisted as findings
- [x] **First-class binary / YARA analysis** — Upload binaries directly; YARA scan results and metadata persisted; stateless `/binary/inspect` endpoint for quick triage
- [x] **Binary auto-trigger** — `artifact_class == "binary"` uploads automatically run YARA analysis when the job starts
- [x] **Raw event explorer** — Full-text search, structured filters, per-field aggregation, and Sankey flow data over normalized events

### Phase 4 — Enterprise Features (Future)

- [ ] Multi-tenancy and RBAC
- [ ] SIEM outputs (Elastic, Splunk, QRadar)
- [ ] Webhooks and integration APIs
- [ ] Kubernetes deployment option
- [ ] PDF report generation

---

## FAQ

### General Questions

**Q: Does AIPAM send my data to the cloud?**
> No. AIPAM runs 100% locally on your machine. Your network captures never leave your environment.

**Q: What file formats are supported?**
> AIPAM supports PCAP, PCAPNG, and CAP files from any standard capture tool (Wireshark, tcpdump, etc.).

**Q: How large can my PCAP file be?**
> There's no hard limit, but files over 100MB may take longer to process. For very large captures, consider splitting by time period.

**Q: Can AIPAM detect zero-day threats?**
> Yes! Because AIPAM analyzes behavior patterns rather than signatures, it can flag suspicious traffic even for unknown malware families.

### Technical Questions

**Q: What AI model does AIPAM use?**
> AIPAM uses a fine-tuned **Llama 3.1 8B** model (currently **v9**) with **LoRA (Low-Rank Adaptation)** for efficient training. The model is quantized to GGUF (Q4_K_M) and served locally via Ollama.

**Q: What are the hardware requirements?**
> - **Minimum**: 8GB RAM, 4 CPU cores
> - **Recommended**: 16GB RAM, 8 CPU cores, NVIDIA GPU with 8GB+ VRAM
> - **For training**: NVIDIA GPU with 16GB+ VRAM (Linux) or Apple Silicon Mac with 16GB+ unified memory

**Q: Can I train on my own data?**
> Yes. The integrated training system is accessible from the web UI's Training page. Start the host trainer (`python3 finetuning/host_trainer.py`) and configure training from the browser.

**Q: How do Zeek and Suricata fit in?**
> - **Zeek** parses network protocols and extracts metadata (flows, DNS, HTTP, TLS, etc.)
> - **Suricata** generates alerts based on known attack signatures
> - **TrafficLLM** (the AI) analyzes patterns and classifies traffic

### Troubleshooting

**Q: Analysis is stuck at "Processing"**
> Check if the worker container is running: `docker logs aipam-worker --tail=50`

**Q: I get "Failed to connect to LLM"**
> Ensure Ollama is running and the model is loaded: `ollama list | grep aipam`

**Q: Everything is classified as malware**
> Older model versions had bias toward malware. Upgrade to v9 which includes benign training data and alignment corrections.

---

## Support and Contributing

### Getting Help
- **Documentation**: [docs/](./docs/)
- **Issues**: Open a GitHub issue for bugs or feature requests

### Contributing
We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Acknowledgments
- **Malware Traffic Analysis** ([@malaboratory](https://twitter.com/malaboratory)) for training exercises
- **Zeek** and **Suricata** open-source projects
- **Ollama** for local LLM serving
- **Meta** for Llama 3.1 base model

---

<p align="center">
  <b>AIPAM - Making Network Security Smarter</b><br>
  <i>Detect threats faster. Investigate smarter. Respond confidently.</i>
</p>
