# AIPAM Team Handoff Guide

## Overview

AIPAM (AI-Powered Advanced Packet Analysis for Malware Detection) is ready for continued development. This guide covers setup, current state, and next steps.

## Current State (Phase 1 Complete)

### ✅ Completed Features
- **PCAP Analysis Pipeline** - Upload, parse, aggregate, LLM analysis, report generation
- **RAG Chat** - ChromaDB-backed semantic search over analysis results
- **Conversation Persistence** - Chat history saved to SQLite
- **Markdown Export** - Download chat conversations
- **v2 Model Training** - 552K malware samples, ~44% complete as of handoff

### 🔄 In Progress
- v2 LoRA training (ETA: ~2-3 days from Dec 22, 2025)

---

## Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/NhanBC/AIPAM.git
cd AIPAM

# Backend
cd backend
pip install -r requirements.txt  # or: pip install .
cd ..

# Frontend
cd frontend
npm install
cd ..
```

### 2. Environment Setup

```bash
# Copy example env and configure
cp backend/.env.example backend/.env

# Required variables in .env:
# OPENAI_API_KEY=your_key (or use local model)
# LOCAL_LLM_ENDPOINT=http://localhost:11434 (for Ollama)
```

### 3. Get Model Files (Not in Git)

### v4 Malware-Traffic Model (Ollama GGUF) — recommended for teammates to test

This repo expects a **local Ollama** model name (see `LLM_MODEL_NAME`). The v4 model artifact is **not** committed to git due to size.

Provide teammates the following on a share drive:
- `aipam-trafficllm-v4.gguf` (GGUF model file)
- `Modelfile.trafficllm-v4` (Ollama Modelfile)

Then, from the repo root on the teammate machine:

```bash
# 1) Ensure Ollama is running
ollama serve

# 2) Copy share-drive files into repo
#    - place GGUF at: deploy/models/aipam-trafficllm-v4.gguf
#    - place Modelfile at: deploy/Modelfile.trafficllm-v4

# 3) Import the model into Ollama
cd deploy
ollama create aipam-trafficllm-v4 -f Modelfile.trafficllm-v4
```

### 4. Run the Application

```bash
# Terminal 1: Backend
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm run dev

# Access at http://localhost:5173
```

---

## Project Structure

```
AIPAM/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── main.py         # API endpoints
│   │   ├── tasks.py        # Celery tasks (analysis pipeline)
│   │   ├── chat_service.py # RAG chat implementation
│   │   ├── rag_index.py    # ChromaDB vector indexing
│   │   ├── llm_client.py   # LLM integration (OpenAI/Ollama)
│   │   └── db_models.py    # SQLModel database schemas
│   └── pyproject.toml
├── frontend/               # React + TypeScript frontend
│   └── src/components/
│       ├── ChatPanel.tsx   # Chat UI with export
│       └── ...
├── finetuning/             # Model training
│   └── aipam_gpu_training/
│       ├── train_continued.py  # v2 training script
│       └── merge_and_convert.py
├── deploy/                 # Docker deployment configs
└── docs/                   # Documentation
```

---

## Key APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/jobs` | POST | Create new analysis job |
| `/api/v1/jobs/{id}` | GET | Get job status/results |
| `/api/v1/jobs/{id}/chat` | POST | Chat about analysis |
| `/api/v1/jobs/{id}/reindex` | POST | Rebuild RAG index |

---

## Training (Continued Development)

### Resume v2 Training
```bash
cd finetuning/aipam_gpu_training
source venv/bin/activate
python train_continued.py --resume
```

### Train on New Data
1. Add PCAPs to `finetuning/trafficllm_training/pcaps/`
2. Preprocess: `python preprocess_pcaps.py`
3. Convert: `python convert_to_chat_format.py`
4. Train new LoRA

### Merge LoRA to Base Model
```bash
python merge_and_convert.py
```

---

## Phase 2 Roadmap (Planned)

- [ ] Threat Intel Integration (MITRE ATT&CK, VirusTotal)
- [ ] Real-time PCAP streaming
- [ ] Multi-model ensemble
- [ ] Dashboard analytics

---

## Files NOT in Git (Transfer Separately)

| File/Directory | Size | Location |
|----------------|------|----------|
| v4 Ollama GGUF model | ~8.5 GB | share drive → copy to `deploy/models/aipam-trafficllm-v4.gguf` |
| v4 Ollama Modelfile | ~1 KB | share drive → copy to `deploy/Modelfile.trafficllm-v4` |

*(Older LoRA/merged directories under `finetuning/aipam_gpu_training/` are also not committed.)*

---

## Contact

For questions about this handoff, contact the original developer.

Last updated: December 22, 2025

