# AIPAM Deployment Guide

**AI-Powered PCAP Analysis Module - Customer Deployment**

## Internal Team (from repo)  recommended

If you are a teammate testing from the GitHub repo, use the **root** `docker-compose.yml` and a **host-running Ollama** with model `aipam-trafficllm-v4`.

See:
- `docs/TEAM_TEST_DEPLOY_V4.md`
- `docs/SHARE_DRIVE_PACKAGE_V4.md`

## Quick Start (offline/customer-style package)

```bash
# 1. Load the Docker images (provided as tar files)
docker load < aipam-app.tar
docker load < aipam-ollama.tar

# 2. Start the stack
docker-compose -f docker-compose.yml up -d

# 3. Access the application
open http://localhost
```

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 20 GB | 50 GB |
| **GPU** | None (CPU mode) | NVIDIA GPU 8GB+ VRAM |
| **Docker** | v20.10+ | v24+ |
| **OS** | Ubuntu 20.04+ / Windows 10+ / macOS 12+ | Ubuntu 22.04 LTS |

## Deployment Options

### Option 1: Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Option 2: Individual Containers

```bash
# Start Ollama (LLM server)
docker run -d --name aipam-ollama \
  -p 11434:11434 \
  -v ollama-models:/root/.ollama \
  aipam-ollama:latest

# Start App (after Ollama is healthy)
docker run -d --name aipam-app \
  -p 80:80 \
  -e OLLAMA_HOST=http://aipam-ollama:11434 \
  -v aipam-data:/app/data \
  --link aipam-ollama:ollama \
  aipam-app:latest
```

## GPU Support (Optional)

For faster inference, enable GPU support:

```yaml
# In docker-compose.yml, uncomment:
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: 1
          capabilities: [gpu]
```

Requires: [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama server URL |
| `DATABASE_URL` | `sqlite:///data/aipam.db` | Database connection |

### Volumes

| Volume | Purpose |
|--------|---------|
| `aipam-data` | SQLite database, analysis results |
| `aipam-uploads` | Uploaded PCAP files |
| `ollama-models` | Cached LLM model weights |

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 80 | App | Web interface & API |
| 11434 | Ollama | LLM API (internal) |

## Health Checks

```bash
# Check app health
curl http://localhost/api/health

# Check Ollama health  
curl http://localhost:11434/api/tags

# Check all containers
docker-compose ps
```

## MNEMOS Chat Comparison Verification

Run these checks against the root `docker-compose.yml`, which owns the AIPAM
MNEMOS service and its Qdrant and Postgres stores. The offline package compose
file in this directory does not provide this comparison workflow.

### 1. Confirm effective configuration and service health

```bash
docker compose exec -T backend python -c "from backend.app.config_v2 import get_settings; s = get_settings(); print(f'mnemos_enabled={s.mnemos_enabled} base_url={s.mnemos_base_url}')"
curl -fsS http://localhost:1888/health
docker compose ps backend mnemos-service mnemos-qdrant mnemos-postgres
```

The backend command must report
`mnemos_enabled=True base_url=http://mnemos-service:8700`. The HTTP probe must
return status `healthy` or `ok`, and the required containers must be running.
An HTTP response from port 1888 alone does not prove that the backend has
MNEMOS enabled; check both commands.

### 2. Prepare historical evidence and reconcile it

1. Complete a source job and a different current job. The source job must be
   older than the current job only for operator clarity; retrieval identity is
   based on job IDs, not timestamps.
2. In the source job's Findings page, confirm at least one distinctive finding.
   Unreviewed, deferred, needs-review, and false-positive findings are not
   eligible for MNEMOS chat retrieval.
3. Run the reconciliation from the backend container:

```bash
docker compose exec -T backend python -m backend.app.cli reconcile-mnemos-findings
```

A successful run exits `0` and prints only:

```text
discovered=<confirmed count> indexed=<upserted count> skipped=0 failed=0
```

For a clean data set, `indexed` equals `discovered`. Each document uses the
stable ID `finding:<job_id>:<finding_id>`, so rerunning the command safely
upserts the same records rather than creating duplicates. Any nonzero `failed`
count or a nonzero process exit means reconciliation did not complete. A
nonzero `skipped` count identifies confirmed rows that could not be rendered
as valid documents and requires investigation before using the run as evidence.

### 3. Exercise and persist the paired conversations

1. Open **AI Chat** for the current job and ask a baseline question that should
   be similar to the distinctive confirmed finding in the source job. Wait for
   the baseline answer to complete.
2. Select **MNEMOS comparison**, then select **Copy to MNEMOS** under that saved
   baseline question. Confirm that the copied question and its source label are
   visible. Edit it if required, then select **Send to MNEMOS**.
3. Confirm that the MNEMOS result reports retrieval status `used`, shows a
   `historical_finding` citation whose job link points to the source job rather
   than the current job, and includes a separately labelled
   `=== Historical comparison ===` appendix.
4. Reload the page. Confirm that the baseline conversation and the selected
   MNEMOS branch both remain, including the copied-source provenance, answer,
   retrieval status, and historical citation.

If no eligible result matches, `no_matches` and the label **No relevant
historical confirmed findings found** are a healthy completed outcome. They do
not prove that reconciliation failed. `unavailable` or `error`, an HTTP 503 with
code `MNEMOS_UNAVAILABLE`, or the label **MNEMOS is unavailable. Try again.**
is an operational failure. MNEMOS comparison does not silently replace that
failure with an ordinary baseline answer.

### Evidence boundaries

- Historical retrieval considers analyst-confirmed findings from other jobs and
  revalidates every hit against the current database before display. It excludes
  the active job.
- Historical similarity is supporting context only. It does not establish that
  the same behavior, indicator, or conclusion exists in the current job.
- Current-job generation and historical evidence remain separate. AIPAM adds the
  historical appendix with deterministic server code after current-job answer
  generation and strips that appendix before a later turn is sent to the model.
- `source_project_id` comes only from existing BlueScrub job lineage. Ordinary
  jobs have `source_project_id: null`; the deterministic appendix labels these
  as `No project assigned`. Never infer a project from a job name or basename.
- The automated backend and browser suites use fakes and deterministic HTTP
  fixtures. Passing them proves the boundary, persistence, and UI contracts; it
  is not evidence that a live MNEMOS deployment was available during the run.

## Troubleshooting

### Ollama taking too long to start
The first startup imports the model (~2-5 minutes). Check logs:
```bash
docker logs aipam-ollama
```

### Out of memory errors
Reduce context size in Modelfile or add more RAM.

### GPU not detected
Ensure NVIDIA Container Toolkit is installed:
```bash
nvidia-container-cli info
```

## Support

For issues, contact: support@blue-cloak.com
