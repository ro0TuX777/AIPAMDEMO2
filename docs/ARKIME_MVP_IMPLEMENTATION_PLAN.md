# Arkime MVP Implementation Plan

> **Version**: 0.1 (2026-03-25)
> **Status**: Draft — implementation-ready MVP plan
> **Target**: Single-VM, air-gapped Docker Compose deployment
> **Branch**: `feature/arkime-mvp`
> **Primary Goal**: Add a local Arkime subsystem so analysts can pivot from AIPAM findings/alerts into packet sessions on the same appliance.

---

## 1) MVP Goal

Deliver a first-pass Arkime integration that:

1. Runs on the **same VM** as AIPAM for easier deployment.
2. Keeps Arkime **optional** using Docker Compose profiles.
3. Lets AIPAM remain the **system of record** for analysis.
4. Lets analysts **import AIPAM-managed PCAPs into Arkime**.
5. Adds an **Open in Arkime** pivot from AIPAM alert and finding views.

---

## 2) Non-Goals for This MVP

The following are explicitly out of scope for the first implementation:

- Multi-node Arkime
- Kubernetes deployment
- HA / failover
- Continuous live packet capture from TAP/SPAN
- Making Arkime required for AIPAM analysis
- Full Arkime lifecycle management from the AIPAM UI

---

## 3) Locked MVP Decisions

### 3.1 Deployment model

- Use **one VM** for the MVP.
- Run Arkime as an **optional subsystem** inside `deploy/docker-compose.yml`.
- Use a Compose profile such as `arkime` so base AIPAM deployments remain lean.

### 3.2 Analyst workflow

- AIPAM continues to analyze uploaded PCAPs directly.
- Arkime is used as a **packet-investigation destination**, not the primary ingest path.
- Import into Arkime is **manual or on-demand** for the MVP.

### 3.3 Pivot strategy

- **Primary key**: `community_id`
- **Fallback**: `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, and a bounded timestamp window

### 3.4 Storage strategy

- Keep Arkime PCAP storage and OpenSearch data in **separate Docker volumes / host paths**.
- Treat this as a small-retention MVP and document that production-scale retention may require a dedicated VM later.

---

## 4) Proposed Runtime Topology

Add the following services to `deploy/docker-compose.yml` under an Arkime profile:

1. `opensearch`
   - Stores Arkime session metadata
   - Internal network only
   - Dedicated persistent volume

2. `arkime-viewer`
   - Arkime UI and API
   - Exposed to the host for analysts
   - Uses the same Arkime config and raw-PCAP volume as the importer/capture service

3. `arkime-capture` (import-oriented)
   - Used for indexing existing PCAPs into Arkime
   - MVP usage is **offline import**, not live sniffing

4. `arkime-init` (one-time initialization pattern)
   - Initializes Arkime indices in OpenSearch
   - Creates initial admin user / bootstraps config

---

## 5) Required Configuration Additions

Normalize Arkime-related settings across `backend/app/config_v2.py` and `backend/app/settings_runtime.py`.

Recommended settings:

- `ARKIME_ENABLED`
- `ARKIME_API_URL`
- `ARKIME_PUBLIC_URL`
- `ARKIME_API_USERNAME`
- `ARKIME_API_PASSWORD`
- `ARKIME_OPENSEARCH_URL`
- `ARKIME_NODE_NAME`
- `ARKIME_IMPORT_ENABLED`
- `ARKIME_AUTO_IMPORT`
- `ARKIME_RAW_DIR`
- `ARKIME_IMPORT_QUEUE_DIR`

Notes:

- `ARKIME_API_URL` is for backend-to-Arkime communication, likely internal Docker DNS.
- `ARKIME_PUBLIC_URL` is for links opened in the analyst’s browser.
- Default `ARKIME_AUTO_IMPORT` to `false` for the MVP.

---

## 6) Backend Implementation Plan

### 6.1 Connector layer

Extend `backend/app/connectors.py` so `ArkimeConnector` can:

- determine whether Arkime is enabled/configured
- build Arkime viewer search URLs
- queue PCAP imports
- optionally check whether matching sessions exist

### 6.2 Import orchestration

Do **not** make the API container call Docker directly.

Instead:

- create a shared import-queue directory
- have AIPAM write import manifests for a job’s PCAP(s)
- have the Arkime import service process those manifests

This keeps the MVP simple, air-gap-friendly, and avoids Docker socket coupling.

### 6.3 Job import status

For the MVP, avoid a DB schema expansion unless implementation proves it is necessary.

Preferred first approach:

- store Arkime import status as a small JSON sidecar in the job directory
- track states such as `queued`, `running`, `imported`, and `failed`

### 6.4 API endpoints

Add Arkime-specific backend endpoints, likely under existing job/alert/finding routes:

- `POST /jobs/{job_id}/arkime/import`
- `GET /jobs/{job_id}/arkime/status`
- `GET /jobs/{job_id}/alerts/{alert_id}/arkime-link`
- `GET /jobs/{job_id}/findings/{finding_id}/arkime-link`

Return payloads should include:

- `enabled`
- `url`
- `basis` (`community_id` or `five_tuple`)
- `import_status`
- optional `message`

### 6.5 Likely backend files

- `backend/app/config_v2.py`
- `backend/app/settings_runtime.py`
- `backend/app/connectors.py`
- `backend/app/api/jobs.py`
- `backend/app/api/alerts.py`
- `backend/app/api/findings.py`
- `backend/app/schemas/alert.py`
- `backend/app/schemas/finding.py`
- `backend/app/schemas/job.py`

---

## 7) Frontend Implementation Plan

### 7.1 Analyst entry points

Add Arkime actions to:

- `frontend/src/pages/AlertDetailPage.tsx`
- `frontend/src/pages/FindingDetailPage.tsx`

If useful later, extend to list views after detail-page behavior is proven.

### 7.2 UI behavior

- If Arkime is disabled: hide Arkime actions
- If Arkime is enabled but PCAP not imported: show `Import into Arkime`
- If imported and pivot data exists: show `Open in Arkime`
- If pivot data is missing: disable the pivot and show a short explanation

### 7.3 Frontend plumbing

Add API client helpers in:

- `frontend/src/api.ts`

Potential UI elements:

- import status badge
- import progress / polling state
- success and failure toasts

---

## 8) Deployment and Packaging Changes

### 8.1 Compose

Update:

- `deploy/docker-compose.yml`

Add:

- Arkime profile
- Arkime services
- Arkime/OpenSearch volumes
- health checks
- environment variables

### 8.2 Offline packaging

Update:

- `deploy/package-for-customer.sh`
- generated `install.sh` content
- `deploy/README.md`

The offline package must include Docker images for:

- AIPAM app stack
- Arkime image
- OpenSearch image

### 8.3 Operator UX

Recommended startup modes:

- Base AIPAM: normal compose startup
- AIPAM + Arkime: compose startup with `arkime` profile enabled

---

## 9) Resource and Safety Guardrails

The single biggest MVP risk is resource contention between:

- Ollama
- Celery worker / pipeline jobs
- OpenSearch
- Arkime viewer/import processes

Guardrails:

- keep Arkime optional
- keep auto-import off by default
- use modest OpenSearch heap sizing for the MVP
- limit retention of imported PCAPs
- avoid exposing OpenSearch directly to analysts

---

## 10) Validation Plan

Implementation is not complete until the following are tested:

1. AIPAM still starts and functions when Arkime profile is **disabled**.
2. Arkime profile starts successfully on the same VM.
3. AIPAM can queue import for at least one job PCAP.
4. Imported PCAP appears in Arkime and is searchable.
5. An alert with `community_id` opens a valid Arkime session search.
6. A finding can pivot using `community_id` or fallback tuple + time logic.
7. Offline package can be built and loaded without external network dependencies.

---

## 11) Implementation Sequence

### Phase 1 — Compose and bootstrap

- add Arkime/OpenSearch services
- create volumes and env vars
- define init/bootstrap procedure

### Phase 2 — Backend integration

- expand Arkime settings
- extend `ArkimeConnector`
- add import queue/status endpoints
- add pivot-link endpoints

### Phase 3 — Frontend analyst workflow

- add Arkime buttons to alert detail
- add Arkime buttons to finding detail
- add import status handling and polling

### Phase 4 — Packaging and docs

- update offline packaging scripts
- update deployment README
- document startup and troubleshooting

### Phase 5 — End-to-end validation

- validate import flow
- validate pivots
- validate disabled-mode behavior
- validate packaging flow

---

## 12) MVP Acceptance Criteria

The Arkime MVP is complete when all of the following are true:

1. Arkime can be started as an **optional Compose profile** on the same VM.
2. AIPAM still works normally when Arkime is not enabled.
3. Analysts can import a job’s PCAP into local Arkime.
4. `AlertDetailPage` can pivot into Arkime using `community_id` when present.
5. `FindingDetailPage` can pivot into Arkime using `community_id` or tuple + time fallback.
6. The deployment remains compatible with the repo’s **air-gapped packaging** model.

---

## 13) Recommended Next Step

Implement this work on a dedicated branch:

- `feature/arkime-mvp`

Start with **Phase 1 (Compose + bootstrap)** so the Arkime subsystem can be brought up locally before touching the API and frontend pivot flow.