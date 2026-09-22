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

### 0. Back up existing volumes and migrate before serving

Run from the repository root with the same Compose project name and `.env`
used by the existing installation. Do not start the new API or worker against
the old schema. `create_all()` at application startup does not upgrade existing
tables. The root Compose services mount `aipam-data` at `/data`, `aipam-jobs`
at `/jobs`, and `aipam-uploads` at `/uploads`; the database is `/data/aipam.db`.

The following Bash commands stop database writers and capture all three existing
volumes, including SQLite WAL files, into a dated archive outside the volumes:

```bash
set -e
docker compose stop frontend backend worker
mkdir -p backups
docker compose run --rm --no-deps -v "$PWD/backups:/backup" backend python -c "import datetime,pathlib,tarfile; p=pathlib.Path('/backup') / ('aipam-before-chat-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.tar.gz'); t=tarfile.open(p,'w:gz'); [t.add(d,arcname=d.lstrip('/')) for d in ('/data','/jobs','/uploads')]; t.close(); print(p.name)"
ls -lh backups/aipam-before-chat-*.tar.gz

docker compose build backend worker frontend
docker compose run --rm --no-deps backend python -m alembic -c /app/alembic.ini current
docker compose run --rm --no-deps backend python -m alembic -c /app/alembic.ini heads
docker compose run --rm --no-deps backend python -m alembic -c /app/alembic.ini upgrade head
docker compose run --rm --no-deps backend python -m alembic -c /app/alembic.ini current
docker compose run --rm --no-deps backend python -c "import sqlite3; c=sqlite3.connect('/data/aipam.db'); versions={r[0] for r in c.execute('select version_num from alembic_version')}; assert versions == {'7a4d8e2c9b10'}, versions; errors=c.execute('pragma foreign_key_check').fetchall(); assert not errors, errors; print('schema head and foreign keys verified')"

docker compose up -d backend worker frontend
```

Stop on any failed command. Preserve the printed pre-upgrade revision with the
archive. The expected single head is `7a4d8e2c9b10`, directly after comparison
revision `6f3a2b9c1d4e` (whose parent is `d4e5f6a7b8c9`). These commands use the
image's `/app/alembic.ini`, its `/app/backend/alembic` script directory, and
Compose's `AIPAM_DB_PATH=/data/aipam.db`. A missing `alembic_version` in an older
unversioned installation requires matching its existing schema to a revision;
do not stamp head or run reconciliation to bypass a migration failure.

Downgrading below `6f3a2b9c1d4e` deliberately deletes MNEMOS comparison
conversations and their answers before removing mode/provenance columns.
Legacy baseline conversations and their messages remain. This prevents a later
upgrade from reclassifying historical appendices as baseline answers. Restore
the saved volumes with the matching application version to recover comparisons;
take the backup before performing any downgrade.

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

Subsequent analyst confirmations and edits of confirmed findings publish the
same canonical document after the database commit, with up to three attempts.
A remote failure leaves the analyst change committed; run the reconciliation
command again after service recovery or a process interruption. Soft-deleted
jobs, revoked findings, and missing sources are excluded from reconciliation
and online recall. Saved answers keep their original source hash and retrieval
outcome; history separately reports current source availability.

Admitted chat turns carry a fixed lease lasting the configured generation
timeout plus 60 seconds. Legacy pending turns use 31 minutes from creation.
Repeating the same job/request UUID returns the same conversation and turn;
an active turn reports `pending` with `retry_after_seconds=2`. Poll that same
request instead of submitting another turn. An expired lease is persisted as an
interrupted error on retry or the next admission; send a new request UUID to
generate again. Cancellation also saves an error, and late workers cannot replace
that saved terminal result. No periodic cleanup process is required for recovery.

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
