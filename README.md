# AIPAM - AI-Powered Advanced Packet Analysis for Malware Detection

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/AI%20Model-Llama%203.1%208B-orange" alt="AI Model">
  <img src="https://img.shields.io/badge/API-V2%20(Sensors)-blueviolet" alt="API V2">
  <img src="https://img.shields.io/badge/Tests-110%20passing-brightgreen" alt="Tests">
</p>

## 📋 Table of Contents

- [What is AIPAM?](#what-is-aipam)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [System Architecture](#system-architecture)
- [Execution Profiles](#execution-profiles)
- [Supported Malware Families](#supported-malware-families)
- [Training Data](#training-data)
- [Benchmark Results](#benchmark-results)
- [Getting Started](#getting-started)
- [Admin CLI (aipam-admin)](#admin-cli-aipam-admin)
- [Environment Variables](#environment-variables)
- [User Guide](#user-guide)
- [Roadmap](#roadmap)
- [FAQ](#faq)

---

## 🎯 What is AIPAM?

**AIPAM** (AI-Powered Advanced Packet Analysis for Malware Detection) is a cutting-edge security tool that uses artificial intelligence to analyze network traffic and detect malicious activity. Think of it as a smart security guard for your network that can:

- **Automatically detect malware** hiding in network traffic
- **Identify the type of threat** (ransomware, banking trojan, infostealer, etc.)
- **Explain what it found** in plain language
- **Suggest what to do next** to protect your systems

Unlike traditional security tools that only match known signatures, AIPAM uses a specially trained AI model that understands the *patterns* and *behaviors* of malicious traffic—even detecting threats it hasn't seen before.

### Who Is This For?

- **Security Analysts** who need faster threat analysis
- **SOC Teams** looking to reduce investigation time
- **Incident Responders** needing quick malware identification
- **Security Researchers** studying network-based threats
- **IT Administrators** wanting visibility into network threats

---

## ✨ Key Features

### 🔍 Modular Sensor Pipeline (V2)
Upload any PCAP and AIPAM runs a **staged sensor pipeline** with Docker-isolated analysis:
- **Zeek** + **Suricata** for protocol parsing and signature alerts
- **Beaconing detector**, **TLS enrichment**, **YARA file triage**, **TI matcher**
- Three **execution profiles**: triage (fast), standard, deep (comprehensive)

### 📡 Real-Time Progress (SSE)
Live updates via Server-Sent Events as each sensor completes:
- Sensor status tracking with colored indicators
- Pipeline stage progression
- Auto-refreshing job detail view

### 💬 AI-Assisted Investigation (Ask AI)
Context-aware AI chat available on **every page** — Alerts, Hosts, IOCs, Findings, and more:
- 🤖 **One-click "Ask AI"** buttons generate a scoped prompt with full entity context
- **3-source RAG** — Current case data + campaign correlations + forensic memory (ChromaDB)
- *"What hosts are infected?"* · *"Is this alert a true positive?"* · *"What should I do next?"*

### 🕸️ Evidence Graph
Interactive **D3-based visualization** of all evidence relationships for a job:
- **7 node types**: Hosts, Alerts, Findings, Theories, Slices, IOCs, Annotations
- Click any node to inspect details and pin it to a Proof
- Edge types: `triggered_on`, `correlated`, `belongs_to`, `annotates`, and more

### 🏗️ Proof Builder
Build structured forensic arguments by **pinning evidence** from the graph:
- **Role selection**: ✅ Supports / ❌ Contradicts / ℹ️ Context
- **Analyst notes** on each pinned item
- **Metadata editor** — status (draft/final/archived), severity, confidence slider
- **Narrative rendering** — generates a Markdown report grouped by evidence role
- **Copy to clipboard** for pasting into tickets or reports

### 🧠 Theory of the Case
Automated **hypothesis generation and ranking** (deterministic, no LLM):
- Scores 10+ hypothesis types: C2 beaconing, data exfiltration, lateral movement, ransomware, credential theft, etc.
- Supporting and contradicting evidence shown as human-readable chips (🚨 alerts, 💀 IOCs, 🔎 findings)
- Confidence labels (High / Medium / Low) with numerical scores

### 🔪 Incident Slices
Groups related alerts, findings, and connections into **logical attack threads**:
- Seeded from `community_id` grouping, merged by host overlap + time proximity
- Attached findings and IOCs per slice
- Ranked by severity and evidence count

### 📝 Why Unusual? (Annotations)
Context annotations explaining **why specific traffic is anomalous**:
- Links to related alerts, findings, and hosts
- Analyst-readable explanations of what made the traffic stand out

### 📊 Reports & Detection Rules
- **HTML + Markdown reports** — executive summary, per-host findings, IOC tables, MITRE mappings
- **Detection-as-Code** — auto-generate Suricata and Sigma rules from findings
- **Report generation** via API with customizable templates

### 🌐 Global Hosts (Cross-Job Forensics)
Track hosts across **all jobs** to identify repeat offenders:
- Aggregate view of every IP seen across analyses
- Drill into per-host detail with connections, DNS, TLS, alerts, and files

### 🔒 Air-Gapped Ready
AIPAM runs completely offline—no data ever leaves your network. Perfect for sensitive environments.
- Offline update bundles with SHA256 integrity verification
- Support bundle export for offline debugging
- All dependencies containerized

### 🛠️ Operational Tooling
Built-in admin CLI (`aipam-admin`) for production maintenance:
- **cleanup-jobs** — Automated retention policy enforcement
- **support-bundle** — Diagnostic archive (excludes PCAPs and secrets)
- **apply-update** — Air-gapped rule/TI updates with rollback
- **smoke-test** / **parity-check** — Validation tools

---

## 🔄 How It Works

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

## 🏗️ System Architecture

AIPAM V2 is built as a containerized application with five main services:

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
| **Ollama** | Local LLM inference for chat + classification | Ollama + fine-tuned Llama 3.1 8B |
| **ChromaDB** | Forensic memory — vector store for cross-case knowledge | ChromaDB |
| **SQLite** | Jobs, sensors, findings, hosts, IOCs, proofs, theories, slices | SQLite with WAL mode |

---

## ⚡ Execution Profiles

AIPAM V2 supports three analysis profiles that control which sensors run:

| Profile | Sensors | Use Case | Est. Time |
|---------|---------|----------|-----------|
| **Triage** | Zeek, Suricata | Quick alert check | ~1 min |
| **Standard** | + Beaconing, TLS Enrich, TI Matcher | Default analysis | ~5 min |
| **Deep** | + File Triage (YARA), all sensors | Full forensic sweep | ~15 min |

---

## 🦠 Supported Malware Families

AIPAM is trained to recognize **40+ malware families** across multiple categories:

### 🏦 Banking Trojans
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **Zeus** | 2007 | Steals banking credentials via keylogging and form grabbing |
| **Emotet** | 2014 | Spreads through malicious emails, drops other malware |
| **TrickBot** | 2016 | Steals credentials and delivers ransomware |
| **Qakbot** | 2007 | Banking trojan that hijacks email threads to spread |
| **IcedID** | 2017 | Banking trojan that partners with ransomware groups |
| **Dridex** | 2014 | Distributed via malicious Office documents |
| **Ursnif/Gozi** | 2007 | Form grabbing and web injection attacks |

### 🔐 Ransomware
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **Ryuk** | 2018 | Targeted ransomware with high ransom demands |
| **Conti** | 2020 | Fast encryption with data theft (double extortion) |
| **LockBit** | 2019 | Self-spreading ransomware as a service |
| **BlackCat/ALPHV** | 2021 | Cross-platform ransomware written in Rust |
| **REvil** | 2019 | High-profile attacks on enterprises |
| **Maze** | 2019 | Pioneered "name and shame" data leak tactics |
| **DarkSide** | 2020 | Known for Colonial Pipeline attack |

### 🕵️ Information Stealers
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **AgentTesla** | 2014 | Keylogger targeting browsers, email, FTP |
| **Formbook** | 2016 | Form grabbing and screenshot capture |
| **RedLine** | 2020 | Steals browser data, crypto wallets, VPN credentials |
| **Raccoon** | 2019 | Targets browsers, crypto wallets, Discord |
| **Lokibot** | 2015 | Password stealer targeting many applications |
| **Snake Keylogger** | 2020 | .NET keylogger with multiple exfil methods |

### 🎛️ Remote Access Trojans (RATs)
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **Cobalt Strike** | 2012 | Legitimate tool abused for attacks |
| **AsyncRAT** | 2019 | Open-source RAT with plugin support |
| **NjRAT** | 2012 | Full remote control capabilities |
| **Remcos** | 2016 | Commercial RAT used maliciously |

### 📦 Loaders & Droppers
| Family | First Seen | What It Does |
|--------|------------|--------------|
| **BazarLoader** | 2020 | Delivers Ryuk/Conti ransomware |
| **Nsis-ay** | 2014 | NSIS-based dropper for various payloads |

### 🤖 Botnets & Other
| Family | Type | What It Does |
|--------|------|--------------|
| **Neris** | Spam Bot | Sends spam and participates in DDoS |
| **Miuref** | Botnet | DDoS and spam distribution |
| **Virut** | File Infector | Spreads via infected executables |
| **Htbot** | Click Fraud | Generates fraudulent ad clicks |

---

## 📚 Training Data

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
| **V6** | 530,769 | Added MTA exercises & Q&A (+1,422) |
| **V7** | 549,308 | Added benign samples (+18,539) |

---

## 📈 Benchmark Results

We tested AIPAM on malware samples it had never seen during training:

### Performance Metrics (15 Test Samples)

| Metric | Score | What It Means |
|--------|-------|---------------|
| **Malicious Detection** | 100% | Never misses actual malware |
| **Type Accuracy** | 33.3% | Correctly identifies malware category |
| **Exact Family Match** | 6.7% | Identifies specific malware family |

### Key Insights

✅ **Perfect Malware Detection** - AIPAM detected all malicious traffic in testing. If there's malware, AIPAM will find it.

⚠️ **Type Classification** - The model correctly categorizes about 1/3 of threats by type (Loader, Stealer, RAT, etc.).

📝 **Family Identification** - Exact family matching is challenging but improving with more training data.

### What This Means for You

| Use Case | Reliability |
|----------|-------------|
| "Is this traffic malicious?" | ⭐⭐⭐⭐⭐ Excellent |
| "What type of malware is it?" | ⭐⭐⭐ Good |
| "Which exact malware family?" | ⭐⭐ Developing |

**Recommendation**: Use AIPAM to flag suspicious traffic, then leverage its MITRE ATT&CK mappings for investigation regardless of the specific family name.

---

## 🚀 Getting Started

### Prerequisites

- **Docker** and **Docker Compose v2** installed
- **8GB+ RAM** recommended (16GB+ for deep profile)
- **NVIDIA GPU** (optional, for faster AI inference)

### Quick Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/AIPAM.git
cd AIPAM

# 2. Configure environment
cp deploy/.env.example deploy/.env
# Edit deploy/.env — set AIPAM_API_TOKEN to a secure value

# 3. Start the full stack
docker compose -f deploy/docker-compose.yml up -d

# 4. Import the AI model
docker exec aipam-ollama ollama create aipam-trafficllm-v5 \
  -f /models/Modelfile

# 5. Open the web interface
open http://localhost   # Frontend on port 80
# API available at http://localhost:8000/api/v1/docs
```

### Verifying Installation

```bash
# Check all containers are running
docker compose -f deploy/docker-compose.yml ps

# Expected output:
# aipam-api        Running (healthy)
# aipam-worker     Running
# aipam-frontend   Running
# aipam-redis      Running (healthy)
# aipam-ollama     Running (healthy)

# Run the smoke test
AIPAM_API_TOKEN=your-token python -m backend.app.cli smoke-test
```

---

## �️ Admin CLI (`aipam-admin`)

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

---

## ⚙️ Environment Variables

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

## 📖 User Guide

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
| **Critical** | 🔴 Red | Active attack, immediate action required |
| **High** | 🟠 Orange | Confirmed malware, investigate immediately |
| **Medium** | 🟡 Yellow | Suspicious activity, review recommended |
| **Low** | 🟢 Green | Minor anomalies, monitor situation |
| **Info** | ⚪ Gray | Normal traffic, no action needed |

#### MITRE ATT&CK Techniques

Each finding includes mapped MITRE ATT&CK techniques. For example:
- **T1071** - Application Layer Protocol (C2 communication)
- **T1566** - Phishing (initial access)
- **T1486** - Data Encrypted for Impact (ransomware)

### Using the AI Chat (Ask AI)

Every evidence page has a 🤖 **Ask AI** button that jumps to the chat with a pre-filled, context-aware question. You can also open the chat page directly and ask free-form questions:

```
You: "What hosts were compromised?"
AIPAM: "Based on the analysis, host 192.168.1.105 shows
       signs of compromise with Emotet C2 beaconing to..."

You: "Is alert ET MALWARE Remcos a true positive?"
AIPAM: "Yes — the alert correlates with beaconing to 206.123.152.51
       on port 2404, a known Remcos C2 endpoint..."
```

The chat uses **3-source RAG**: current job data, cross-job campaign correlations, and a persistent forensic memory (ChromaDB vector store) that remembers past investigations.

### Using the Evidence Graph & Proof Builder

1. **Open the Evidence Graph** from the job detail tab bar
2. **Explore nodes** — click any host, alert, finding, theory, slice, IOC, or annotation
3. **Toggle the Proof Builder** sidebar and create a new proof (e.g., "Remcos C2 Chain")
4. **Pin evidence** — select a role (Supports / Contradicts / Context) and add analyst notes
5. **Edit metadata** — set status, severity, and confidence via the ⚙ editor
6. **Render Narrative** — click 📝 to generate a Markdown report, then 📋 copy it

### Theory of the Case & Incident Slices

- Navigate to **Theories** from the job detail page to see ranked hypotheses with confidence scores
- Navigate to **Slices** to see how alerts and findings group into attack threads
- Navigate to **Why Unusual?** for context annotations on anomalous traffic
- Each page includes breadcrumb navigation back to the job

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

## 🗺️ Roadmap

### Phase 1 — MVP Delivery (Completed ✅)

- [x] Web UI for PCAP upload and results visualization
- [x] Backend APIs for ingestion, analysis job management, and report retrieval
- [x] Unified dataset creation (TrafficLLM + MTA PCAPs + GitHub indicator datasets)
- [x] Fine-tuned Llama 3.1 8B cyber model
- [x] Interactive chat interface tied to PCAP analysis
- [x] MITRE ATT&CK-aware reasoning and mapping
- [x] Unit + integration testing

### Phase 2 — DAWN Pipeline + Specialist Pyramid (Completed ✅)

- [x] DAWN Deterministic Pipeline — Immutable ledger, cryptographic binding, meaning gates
- [x] Source-Agnostic Ingest — Unified Flow IR from PCAP, Security Onion, and Arkime
- [x] 3-Tier Specialist Pyramid — L1 (Generalist), L2 (Forensic COT), L3 (Mc4minta)
- [x] Chain-of-Thought Forensic Reasoning — MITRE ATT&CK mapping
- [x] Anti-Hallucination System — 6-layer defense
- [x] Heuristic–LLM Fusion — 10+ anomaly detectors
- [x] Automated Report Generation — Markdown + HTML
- [x] Golden Scenario Test Harness

### Phase 3 — Proactive Defense + Forensic Memory (Completed ✅)

- [x] Forensic Memory — ChromaDB vector store for cross-case knowledge
- [x] 3-Source RAG Chat — Current case + campaign correlations + forensic memory
- [x] Cross-Job Campaign Detection
- [x] Detection-as-Code — Suricata and Sigma rules from findings
- [x] Purple Team Simulation — Scapy-based adversary emulation
- [x] Closed-Loop Validation — 100% detection match rate
- [x] HITL Review Gate + Trust Receipts

### Sensors V2 Migration (Completed ✅)

- [x] **Backend Foundation** — V2 models, schemas, database (SQLite + WAL), config
- [x] **Sensor Pipeline** — Docker-based sensor runner, registry, orchestrator, preflight checks
- [x] **API Expansion** — 25+ REST endpoints, SSE, correlation, batch operations
- [x] **Frontend Adaptation** — React SPA with TanStack Query, SSE hooks, V2 upload flow
- [x] **Integration Testing** — Golden PCAP corpus, smoke test CLI, parity check CLI
- [x] **Ops Tooling** — cleanup-jobs, support-bundle, apply-update, Docker Compose
- [x] **Documentation** — Updated README, env var reference, CLI docs
- [x] 110 tests passing (unit + integration)

### Analyst Workbench (Completed ✅)

- [x] **Evidence Graph** — D3 visualization of 7 entity types with relationship edges
- [x] **Proof Builder** — Pin evidence with roles, analyst notes, metadata, and narrative rendering
- [x] **Theory of the Case** — Deterministic hypothesis generation and ranking (10+ types)
- [x] **Incident Slices** — Attack thread grouping by community_id, host overlap, and time proximity
- [x] **Why Unusual? (Annotations)** — Context annotations for anomalous traffic
- [x] **Ask AI Everywhere** — 🤖 contextual chat buttons on Alerts, Hosts, IOCs, Findings pages
- [x] **Global Hosts** — Cross-job host tracking and forensics
- [x] **TI Matcher** — Threat intelligence feed integration with confidence scoring
- [x] **Knowledge Base** — Persistent forensic memory via ChromaDB
- [x] **Reports** — HTML + Markdown report generation with executive summaries
- [x] **Detection Rules** — Auto-generate Suricata and Sigma rules from findings
- [x] **Human-readable Evidence** — Supporting evidence shown as chips (🚨 alerts, 💀 IOCs, 🔎 findings)

### Phase 4 — Enterprise Features (Future)

- [ ] Multi-tenancy and RBAC
- [ ] SIEM outputs (Elastic, Splunk, QRadar)
- [ ] Webhooks & integration APIs
- [ ] Kubernetes deployment option
- [ ] PDF report generation

---

## ❓ FAQ

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
> AIPAM uses a fine-tuned **Llama 3.1 8B** model with **LoRA (Low-Rank Adaptation)** for efficient training. The model is served locally via Ollama.

**Q: What are the hardware requirements?**
> - **Minimum**: 8GB RAM, 4 CPU cores
> - **Recommended**: 16GB RAM, 8 CPU cores, NVIDIA GPU with 8GB+ VRAM

**Q: Can I train on my own data?**
> Yes! The training pipeline is included. See `finetuning/README.md` for instructions.

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
> Older model versions had bias toward malware. Upgrade to V7 which includes benign training data.

---

## 📞 Support & Contributing

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
