# AIPAM (AI PCAP Analysis Module)

AIPAM ingests network captures (PCAP and related logs) and produces
human-readable security analysis reports via an AI-driven pipeline. It consists
of a Python backend (FastAPI + Celery + SQLModel) and a React (Vite) frontend.

## Features

- **Multiple ingestion modes**
  - Direct PCAP upload
  - Security Onion connector
  - Arkime connector
- **Analysis pipeline**
  - Ingest → parse → baseline vs exploit split
  - Host / host-pair aggregation
  - Change analysis
  - LLM-powered summary + report generation
- **Job tracking**
  - Create jobs via REST API
  - Check job status and per-step progress
  - Retrieve final analysis results and report URLs
- **Performance Benchmarking**
  - Continuous evaluation against known malware families
  - Detailed metrics on detection accuracy and type classification

## Benchmark Results (Latest)

Our recently completed benchmark on 15 malicious samples shows:
- **Malicious Detection:** 100%
- **Type Accuracy:** 33.3%
- **Exact Family Match:** 6.7%

For detailed analysis and latest results, see:
- [RESULTS_LATEST.md](file:///home/bc/Documents/AIPAM/benchmark/RESULTS_LATEST.md)
- [BIAS_ANALYSIS.md](file:///home/bc/Documents/AIPAM/benchmark/BIAS_ANALYSIS.md)

## Architecture

- **backend/**
  - `app/main.py` – FastAPI app and API endpoints
  - `app/tasks.py` – Celery worker and `run_pipeline(job_id)` task
  - `app/db_models.py`, `app/database.py` – SQLModel / SQLite persistence
  - `app/connectors.py` – Security Onion / Arkime connectors
  - `app/aggregation.py`, `app/baseline_utils.py`, `app/reporting.py` – core
    analysis and report generation
  - `app/tests/` – pytest suite for pipeline, connectors, and API endpoints
- **frontend/**
  - React + Vite single-page app
  - Pages for job creation, job details, and overall dashboard

## Backend: Setup and Usage

### Requirements

- Python 3.11+
- Redis (for Celery broker/backend) in most deployment setups

### Install dependencies

```bash
cd backend
python -m pip install -e .[dev] \
  || python -m pip install fastapi uvicorn sqlmodel celery redis httpx python-multipart pytest
```

### Environment variables (common)

- `DATABASE_URL` (optional)
  Default is a local SQLite file, e.g. `sqlite:///aipam.db`.

- `FILE_STORAGE_PATH` (optional)
  Directory where PCAPs and generated artifacts are stored.
  Default: `/tmp/aipam_storage`.

- `REPORTS_PATH` (optional)
  Directory where generated HTML/Markdown reports are written.
  Default: `<FILE_STORAGE_PATH>/reports`.

- Additional connector/LLM-specific variables are configured in the backend
  modules (`app/connectors.py`, `app/llm_client.py`).

### Run the API server

```bash
cd backend
uvicorn app.main:app --reload
```

This exposes the REST API (including job creation, status, and result endpoints).

### Run the Celery worker

In a separate shell:

```bash
cd backend
celery -A app.tasks.celery_app worker --loglevel=info
```

The API enqueues `run_pipeline(job_id)` tasks to this worker.

### Run backend tests

```bash
cd backend
PYTHONPATH=. python -m pytest -q
```

## Frontend: Setup and Usage

### Requirements

- Node.js 18+ (and npm)

### Install dependencies

```bash
cd frontend
npm install
```

### Run the dev server

```bash
cd frontend
npm run dev
```

By default, Vite will start on `http://localhost:5173`.

The frontend talks to the backend at `VITE_API_BASE_URL` (default
`http://localhost:8000/api/v1`). To point at a different backend, set this
environment variable when running Vite, for example:

```bash
cd frontend
VITE_API_BASE_URL="https://your-env.example.com/api/v1" npm run dev
```


### Run end-to-end (Playwright) tests

With dependencies installed, you can run the E2E suite against a running dev
server:

```bash
cd frontend
npm run dev   # in one terminal
```

In another terminal:

```bash
cd frontend
npm run test:e2e
```

Test results are also summarized in
`frontend/playwright-report/playwright-issues.json`.
## API Overview

### Job creation

- `POST /api/v1/jobs` – create a job from a direct PCAP upload.
- `POST /api/v1/jobs/from_security_onion` – create a job from a Security Onion
  source.
- `POST /api/v1/jobs/from_arkime` – create a job from an Arkime capture.

Each returns a JSON body with at least:

- `job_id` – server-assigned job identifier
- `status` – initial job status (e.g. `queued`)

### Job status

- `GET /api/v1/jobs/{job_id}` – return overall job status and per-step details.

Example response fields:

- `job_id` – the job identifier
- `status` – overall job status (`queued`, `running`, `completed`, `failed`)
- `steps` – array of `{ name, status, message }` for each pipeline step

### Job result

- `GET /api/v1/jobs/{job_id}/result` – return the final analysis result.

Behavior:

- Returns **409** if the job is not yet `completed`.
- Returns **404** if the job does not exist.
- Returns **500** if the job is `completed` but no result row exists.

On success, the body includes:

- `job_id`, `status`
- `summary` – high-level analysis summary (severity, key findings, MITRE info)
- `hosts` – detailed host findings
- `report_urls` – paths/URLs to generated reports (e.g. HTML)

## Development Notes

- Local development uses a SQLite database stored in `backend/aipam.db`
  (ignored in git).
- The backend test suite includes:
  - Connector ingest tests
  - Baseline vs exploit pipeline tests
  - API-level tests for job creation, status, and result endpoints
- Production deployments should use a more robust database and message broker
  configuration than the local defaults.

## License

TBD – add your preferred license here (e.g. MIT, Apache 2.0).
