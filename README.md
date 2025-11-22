# AIPAM (AI PCAP Analysis Module)

AIPAM is a two-part application (Python backend + React frontend) that ingests PCAP network captures and produces human-readable security analysis reports using an AI-driven pipeline.

## Components

- **backend/** – FastAPI + Celery + SQLModel service that:
  - Accepts PCAP uploads and connector-driven jobs (Security Onion, Arkime)
  - Runs an analysis pipeline (ingest → parse → baseline vs exploit split → aggregation → LLM analysis → report generation)
  - Persists job metadata, step status, and final results in a SQLite database
- **frontend/** – React (Vite) UI that interacts with the backend API

## Quick Start (Backend)

1. Create and activate a Python 3.11 virtualenv (recommended).
2. Install backend dependencies:
   ```bash
   cd backend
   python -m pip install -e .[dev] || python -m pip install fastapi uvicorn sqlmodel celery redis httpx python-multipart pytest
   ```
3. Run the API server:
   ```bash
   cd backend
   uvicorn app.main:app --reload
   ```
4. (Optional) Run tests:
   ```bash
   cd backend
   PYTHONPATH=. python -m pytest -q
   ```

## Quick Start (Frontend)

1. Install Node.js (v18+ recommended).
2. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```
3. Run the dev server:
   ```bash
   npm run dev
   ```

## Notes

- Local development uses a SQLite database stored in `backend/aipam.db` (ignored from git).
- See backend `app/` package for API endpoints, tasks, and models.

