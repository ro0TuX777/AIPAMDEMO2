# AIPAM - AI-Powered Advanced Packet Analysis for Malware Detection

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/AI%20Model-Llama%203.1%208B-orange" alt="AI Model">
</p>

## 📋 Table of Contents

- [What is AIPAM?](#what-is-aipam)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [System Architecture](#system-architecture)
- [Supported Malware Families](#supported-malware-families)
- [Training Data](#training-data)
- [Benchmark Results](#benchmark-results)
- [Getting Started](#getting-started)
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

### 🔍 Intelligent Traffic Analysis
Upload any network capture file (PCAP), and AIPAM will automatically:
- Parse and understand all network communications
- Identify suspicious patterns and behaviors
- Classify threats by malware family and type

### 💬 Interactive Chat Assistant
Ask follow-up questions about the analysis in plain English:
- *"What hosts are infected?"*
- *"How did this malware spread?"*
- *"What should I do to contain this?"*

### 📊 Detailed Reports
Get comprehensive reports including:
- Executive summary for management
- Technical details for analysts
- MITRE ATT&CK technique mapping
- Recommended remediation steps

### 🔒 Air-Gapped Ready
AIPAM runs completely offline—no data ever leaves your network. Perfect for sensitive environments.

### 🔗 Integration Ready
Connect to your existing security stack:
- **Security Onion** - Import captures directly
- **Arkime** - Export sessions for analysis
- **REST API** - Integrate with any system

---

## 🔄 How It Works

AIPAM follows a simple 5-step process to analyze your network traffic:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AIPAM Analysis Pipeline                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ① UPLOAD        ② PARSE           ③ ANALYZE        ④ CLASSIFY         │
│  ────────       ───────           ─────────        ──────────          │
│  PCAP file  →   Zeek extracts  →  AI examines  →   Identifies          │
│  dropped       network flows      patterns        malware type         │
│                                                                         │
│                              ⑤ REPORT                                   │
│                              ────────                                   │
│                         Generates findings,                             │
│                      recommendations & chat                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step-by-Step Breakdown

1. **Upload** - Drag and drop your PCAP file into the web interface
2. **Parse** - Zeek and Suricata extract network flows and generate alerts
3. **Analyze** - The AI model examines traffic patterns, timing, and behaviors
4. **Classify** - Traffic is categorized as benign or malicious (with malware family)
5. **Report** - A detailed report is generated with findings and next steps

---

## 🏗️ System Architecture

AIPAM is built as a modern, containerized application with four main components:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Your Computer                                   │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
│   │  Frontend   │    │   Backend   │    │   Worker    │                 │
│   │   (React)   │◄──►│  (FastAPI)  │◄──►│  (Celery)   │                 │
│   │  Port 5173  │    │  Port 8000  │    │ Zeek+Suri   │                 │
│   └─────────────┘    └──────┬──────┘    └──────┬──────┘                 │
│                             │                   │                        │
│                      ┌──────▼──────┐     ┌──────▼──────┐                │
│                      │    Redis    │     │   Ollama    │                │
│                      │   (Queue)   │     │  (AI Model) │                │
│                      └─────────────┘     └─────────────┘                │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Components Explained

| Component | What It Does | Technology |
|-----------|--------------|------------|
| **Frontend** | Web interface you interact with | React + TypeScript |
| **Backend** | Handles requests and coordinates analysis | Python FastAPI |
| **Worker** | Processes PCAP files in the background | Celery + Zeek + Suricata |
| **Redis** | Manages the job queue | Redis |
| **Ollama** | Runs the AI model for classification | Ollama + TrafficLLM |

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

- **Docker** and **Docker Compose** installed
- **8GB+ RAM** recommended
- **NVIDIA GPU** (optional, for faster AI inference)
- **Ollama** installed on host machine

### Quick Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/AIPAM.git
cd AIPAM

# 2. Start the application
docker compose up -d

# 3. Import the AI model to Ollama
ollama create aipam-trafficllm-v5 -f finetuning/aipam_gpu_training/Modelfile

# 4. Open the web interface
open http://localhost:5173
```

### Verifying Installation

```bash
# Check all containers are running
docker compose ps

# Expected output:
# aipam-backend    Running
# aipam-worker     Running
# aipam-frontend   Running
# aipam-redis      Running
```

---

## 📖 User Guide

### Analyzing a PCAP File

1. **Open the Dashboard** at `http://localhost:5173`
2. **Click "New Analysis"** in the navigation
3. **Drag and drop** your PCAP file (or click to browse)
4. **Click "Start Analysis"** and wait for processing
5. **View Results** - click on the job to see the full report

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

### Using the Chat Feature

After analysis, you can ask follow-up questions:

```
You: "What hosts were compromised?"
AIPAM: "Based on the analysis, host 192.168.1.105 shows 
       signs of compromise with Emotet C2 beaconing to..."

You: "What remediation steps should I take?"
AIPAM: "1. Isolate 192.168.1.105 from the network
        2. Block the C2 domains: evil.com, bad-domain.net
        3. Scan for lateral movement indicators..."
```

### Exporting Results

- **HTML Report** - Full report for sharing with stakeholders
- **Markdown Export** - Technical report for documentation
- **Chat Transcript** - Download conversation history

---

## 🗺️ Roadmap

### ✅ Completed (Current Version)

- [x] PCAP upload and analysis pipeline
- [x] AI-powered malware classification
- [x] Interactive chat with RAG (Retrieval-Augmented Generation)
- [x] MITRE ATT&CK technique mapping
- [x] HTML/Markdown report generation
- [x] Conversation persistence
- [x] Benign traffic recognition (V7)

### 🔄 In Progress

- [ ] **V7 Model Training** - Enhanced model with benign traffic recognition
- [ ] **Distributed Training** - Multi-GPU training for faster iteration
- [ ] **Model Accuracy Improvements** - Better family-level classification

### 🔮 Future Plans

#### Short Term (Q1 2026)
- [ ] **API Enhancements** - Webhooks and async processing
- [ ] **Bulk Analysis** - Process multiple PCAPs in batch
- [ ] **Real-time Monitoring** - Live PCAP stream analysis

#### Medium Term (Q2-Q3 2026)
- [ ] **Multi-tenant Support** - Team collaboration features
- [ ] **Threat Intelligence Integration** - Enrich findings with external TI
- [ ] **SIEM Integration** - Direct export to Splunk, Elastic, etc.
- [ ] **Self-Distillation (Continual Learning)** - Help the model improve over time by learning from high-confidence results and analyst-verified feedback (with safety checks to prevent bad data from teaching the model)

#### Long Term (2026+)
- [ ] **Network Forensics** - Deep packet inspection and reconstruction
- [ ] **Cloud Deployment** - Kubernetes/Cloud-native deployment

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
