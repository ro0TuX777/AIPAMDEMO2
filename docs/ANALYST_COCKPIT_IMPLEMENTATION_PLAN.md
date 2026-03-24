# AIPAM Analyst Cockpit — Implementation Plan

> **Version**: 1.0 (2026-03-24)
> **Status**: Approved for development
> **Base Commit**: `47adfc7` (main)
> **Target**: Single-VM, air-gapped Ubuntu 24.04 LTS
> **Model**: `aipam-trafficllm-v10` (GGUF via Ollama)
> **Goal**: Transform AIPAM from a collection of analytic pages into a unified investigation cockpit that makes the analyst faster, more confident, and more effective.

---

## 0) Strategy Overview

### Problem Statement

AIPAM has strong analytic primitives — Findings, Theories, Slices, Annotations, Attack Graph, Timeline, Chat, and Before/After multi-PCAP support. However, the analyst currently suffers from **tab-hopping**: jumping between 4–6 pages per investigation to triage, compare, validate, and report. This fragmented workflow costs time and risks missed leads.

### Solution

Build an **Investigation Cockpit** in 4 releases across 8 sprints, each release independently deployable to the air-gapped server:

| Release | Branch | Sprints | Theme |
|---------|--------|---------|-------|
| **R1** — Immediate Analyst ROI | `feature/investigation-queue` | 1–2 | Unified triage queue |
| **R2** — Temporal + Trust | `feature/temporal-hitl` | 3–4 | Before/After compare + HITL review |
| **R3** — Reporting + Speed | `feature/proof-partial` | 5–6 | Draft case narrative + partial results |
| **R4** — Self-Improving Platform | `feature/feedback-correlation` | 7–8 | Feedback ranking + cross-job UX |

### Branch Strategy

```
main (47adfc7 — stable)
  └── feature/investigation-queue     ← R1
        ├── Sprint 1 commits
        ├── Sprint 2 commits
        ├── test + validate
        └── merge to main → package offline update
              └── feature/temporal-hitl         ← R2
                    ├── Sprint 3 commits
                    ├── Sprint 4 commits
                    ├── test + validate
                    └── merge to main → package offline update
                          └── feature/proof-partial       ← R3
                                ├── Sprint 5 commits
                                ├── Sprint 6 commits
                                ├── test + validate
                                └── merge to main → package offline update
                                      └── feature/feedback-correlation  ← R4
                                            ├── Sprint 7 commits
                                            ├── Sprint 8 commits
                                            ├── test + validate
                                            └── merge to main → final package
```

### Rules

1. **Never commit directly to `main`** during cockpit development.
2. Each feature branch is cut from the **updated `main`** after the previous release merges.
3. Each release produces an **offline update package** via `deploy/create-code-update.sh`.
4. Merge requires: all tests pass, TypeScript compiles, Docker containers build, manual analyst walkthrough.
5. All new database columns use **Alembic migrations** (not auto-create).

---

## 1) Sprint Length & Team Assumptions

| Parameter | Value |
|-----------|-------|
| Sprint length | 2 weeks |
| Team | 1 full-stack engineer + 1 part-time analyst/QA reviewer |
| Review cadence | End-of-sprint demo with analyst stakeholder |
| Definition of done | Tests pass, Docker builds, analyst can complete the target workflow |

---

## 2) Dependency Map

```
Sprint 1: Investigation Queue Foundation
    │
    ▼
Sprint 2: Investigation Queue v2 (filters, badges, drill-down)
    │
    ▼
Sprint 3: Before/After Comparison Workspace
    │
    ▼
Sprint 4: HITL Review Workflow
    │
    ▼
Sprint 5: Draft Case Narrative / Proof Builder
    │
    ▼
Sprint 6: Early Partial Results
    │
    ▼
Sprint 7: Feedback-Driven Ranking
    │
    ▼
Sprint 8: Cross-Job Correlation UX
```

---

# RELEASE 1 — Immediate Analyst ROI

**Branch:** `feature/investigation-queue`
**Cut from:** `main` at `47adfc7`
**Sprints:** 1–2 (4 weeks)
**Merge target:** `main`

---

## Sprint 1 — Investigation Queue Foundation (Weeks 1–2)

### Goal
Give the analyst **one place to start** every investigation — a ranked queue of "what to look at first" that aggregates signals from all existing data sources.

### Backend Changes

#### New API Endpoint: `GET /jobs/{jobId}/investigation-queue`

**File:** `backend/app/api/investigation.py` (new)

```python
GET /jobs/{job_id}/investigation-queue
Query params:
  - cursor: str | None
  - limit: int (default 50, max 200)
  - severity: str | None (critical, high, medium, low, info)
  - source_type: str | None (finding, alert, theory, slice, annotation)
  - pcap_label: str | None (before, after)
  - status: str | None (unreviewed, confirmed, false_positive, deferred)
  - sort: str (default "rank_score")
  - q: str | None (free-text search)

Response: InvestigationQueueResponse {
  schema_version: "1.0",
  items: InvestigationQueueItem[],
  page: PageInfo,
  meta: {
    total_unreviewed: int,
    total_confirmed: int,
    total_false_positive: int,
    severity_counts: { critical: int, high: int, medium: int, low: int, info: int }
  }
}
```

#### `InvestigationQueueItem` Schema

**File:** `backend/app/schemas/investigation.py` (new)

```python
class InvestigationQueueItem(BaseModel):
    queue_item_id: str            # unique across all source types
    source_type: str              # "finding" | "alert" | "theory" | "slice" | "annotation"
    source_id: str                # original ID in source table
    title: str
    summary: str | None
    severity: Severity
    confidence: float             # 0.0–1.0
    rank_score: float             # computed ranking score
    rank_factors: dict            # breakdown of why this score
    category: str | None
    sensor: str | None
    pcap_label: str | None        # "before" | "after" | None
    affected_hosts: list[str]     # IPs involved
    mitre_technique_id: str | None
    corroborating_count: int      # how many other signals support this
    status: str                   # "unreviewed" | "confirmed" | "false_positive" | "deferred"
    created_at: datetime
```

#### Ranking Algorithm

**File:** `backend/app/services/ranking.py` (new)

The ranking formula computes `rank_score` for each item:

```
rank_score = (
    severity_weight          * 0.30   # critical=1.0, high=0.8, medium=0.5, low=0.2, info=0.05
  + confidence               * 0.25   # direct from source
  + corroboration_score      * 0.20   # count of other signals involving same host/IOC
  + blast_radius_score       * 0.15   # number of affected hosts / total hosts
  + recency_score            * 0.10   # newer items score higher within same job
)
```

Sources queried and unified:
- `Finding` table → findings from all sensors
- `Alert` table → Suricata/heuristic alerts
- `Theory` table → LLM-generated theories
- Slice data → from job result slices
- Annotation data → analyst annotations

Each source is normalized into `InvestigationQueueItem` with source-specific mapping:

| Source | severity | confidence | affected_hosts |
|--------|----------|------------|----------------|
| Finding | `finding.severity` | `finding.confidence` | `finding.evidence_json → hosts` |
| Alert | mapped from `alert.severity` | `0.7` (Suricata base) | `[alert.src_ip, alert.dst_ip]` |
| Theory | `theory.severity` | `theory.confidence` | `theory.evidence_json → hosts` |

#### Database Changes

**File:** `backend/alembic/versions/xxx_add_investigation_status.py` (new migration)

Add columns to `findings` table:
```sql
ALTER TABLE findings ADD COLUMN analyst_status VARCHAR DEFAULT 'unreviewed';
ALTER TABLE findings ADD COLUMN analyst_notes TEXT;
ALTER TABLE findings ADD COLUMN reviewed_at TIMESTAMP;
```

Add columns to `alerts` table:
```sql
ALTER TABLE alerts ADD COLUMN analyst_status VARCHAR DEFAULT 'unreviewed';
ALTER TABLE alerts ADD COLUMN analyst_notes TEXT;
ALTER TABLE alerts ADD COLUMN reviewed_at TIMESTAMP;
```

Add columns to `theories` table:
```sql
ALTER TABLE theories ADD COLUMN analyst_status VARCHAR DEFAULT 'unreviewed';
ALTER TABLE theories ADD COLUMN analyst_notes TEXT;
ALTER TABLE theories ADD COLUMN reviewed_at TIMESTAMP;
```

#### New API Endpoint: `PATCH /jobs/{jobId}/investigation-queue/{itemId}/status`

**File:** `backend/app/api/investigation.py`

```python
PATCH /jobs/{job_id}/investigation-queue/{item_id}/status
Body: {
  status: "confirmed" | "false_positive" | "deferred" | "unreviewed",
  notes: str | None
}
Response: InvestigationQueueItem (updated)
```

This endpoint resolves the `source_type` and `source_id` from the `item_id`, then updates the appropriate table's `analyst_status`, `analyst_notes`, and `reviewed_at` columns.

#### Register Router

**File:** `backend/app/api/__init__.py` or app factory

Add `investigation_router` to the FastAPI app alongside existing routers.

### Frontend Changes

#### New Page: `InvestigationQueuePage.tsx`

**File:** `frontend/src/pages/InvestigationQueuePage.tsx` (new)

Features:
- Ranked list of investigation items, sorted by `rank_score` descending
- Each item shows: severity badge, title, source type icon, confidence bar, affected hosts count, pcap_label badge
- Quick-action buttons per item:
  - ✅ **Confirm** — sets `analyst_status = "confirmed"`
  - ❌ **False Positive** — sets `analyst_status = "false_positive"`
  - ⏸️ **Defer** — sets `analyst_status = "deferred"`
  - 🤖 **Ask AI** — opens ChatPanel scoped to this item
  - 🔍 **Details** — navigates to the source detail page (FindingDetailPage, AlertDetailPage, etc.)
- Summary bar at top: total items, unreviewed count, severity distribution
- Real-time update via existing SSE job events hook

#### Route Registration

**File:** `frontend/src/App.tsx`

Add route: `/jobs/:jobId/investigate` → `InvestigationQueuePage`

#### Navigation Update

**File:** `frontend/src/pages/JobDetailPage.tsx`

Add "Investigation Queue" as the **first tab** in the job detail navigation, before existing tabs.

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/api/investigation.py` | **Create** | Queue + status endpoints |
| `backend/app/schemas/investigation.py` | **Create** | Request/response schemas |
| `backend/app/services/ranking.py` | **Create** | Ranking algorithm |
| `backend/alembic/versions/xxx_add_investigation_status.py` | **Create** | DB migration |
| `backend/app/models/finding.py` | **Modify** | Add `analyst_status`, `analyst_notes`, `reviewed_at` columns |
| `backend/app/models/alert.py` | **Modify** | Add `analyst_status`, `analyst_notes`, `reviewed_at` columns |
| `backend/app/models/theory.py` | **Modify** | Add `analyst_status`, `analyst_notes`, `reviewed_at` columns |
| `backend/app/api/__init__.py` | **Modify** | Register investigation router |
| `frontend/src/pages/InvestigationQueuePage.tsx` | **Create** | Queue UI |
| `frontend/src/App.tsx` | **Modify** | Add route |
| `frontend/src/pages/JobDetailPage.tsx` | **Modify** | Add nav tab |

### Sprint 1 Testing & Validation

#### Backend Tests

**File:** `tests/unit/test_ranking.py` (new)

| Test | Description |
|------|-------------|
| `test_severity_weight_ordering` | Critical items rank higher than high, high higher than medium, etc. |
| `test_corroboration_boost` | Items with multiple supporting signals rank higher |
| `test_blast_radius_scaling` | Items affecting more hosts rank higher |
| `test_empty_job_returns_empty_queue` | No crash on jobs with no findings/alerts/theories |
| `test_single_source_type_filter` | Filtering by `source_type=finding` excludes alerts and theories |
| `test_pcap_label_filter` | Filtering by `pcap_label=after` returns only after-phase items |

**File:** `tests/integration/test_investigation_api.py` (new)

| Test | Description |
|------|-------------|
| `test_queue_endpoint_returns_ranked_items` | Create a job with findings + alerts, verify queue returns them ranked |
| `test_status_update_persists` | PATCH status to "confirmed", verify GET reflects the change |
| `test_pagination_works` | Create 60+ items, verify cursor pagination returns correct pages |
| `test_severity_filter` | Filter by severity=high, verify only high items returned |
| `test_search_filter` | Search by keyword, verify matching items returned |
| `test_meta_counts_accurate` | Verify `meta.total_unreviewed` and `severity_counts` are correct |

#### Frontend Tests

**File:** `frontend/tests/e2e/investigation-queue.spec.ts` (new)

| Test | Description |
|------|-------------|
| `test_queue_page_loads` | Navigate to `/jobs/{id}/investigate`, verify page renders |
| `test_items_sorted_by_rank` | Verify first item has highest rank_score |
| `test_confirm_action_updates_status` | Click confirm, verify item status changes |
| `test_filter_by_severity` | Select "High" filter, verify only high items shown |
| `test_navigate_to_detail` | Click details, verify navigation to correct detail page |

#### Manual Validation Checklist

- [ ] Analyst opens a completed job and sees the Investigation Queue as the first tab
- [ ] Items are ranked sensibly (critical findings above info-level alerts)
- [ ] Confirming an item changes its badge immediately
- [ ] "Ask AI" opens the chat panel with the correct context
- [ ] "Details" link navigates to the correct source page and back button returns to queue

### Sprint 1 Exit Criteria

1. `GET /jobs/{jobId}/investigation-queue` returns ranked, paginated results
2. `PATCH /jobs/{jobId}/investigation-queue/{itemId}/status` persists status changes
3. Queue UI renders with correct ranking, filters, and quick actions
4. All backend tests pass: `pytest tests/unit/test_ranking.py tests/integration/test_investigation_api.py -v`
5. TypeScript compiles: `cd frontend && npx tsc --noEmit`
6. Docker containers build: `docker compose build --no-cache`

---

## Sprint 2 — Investigation Queue v2 (Weeks 3–4)

### Goal
Make the queue **operational** — add filters, badges, evidence grouping, and drill-down so analysts can stay in one page for most triage work.

### Backend Changes

#### Enhanced Queue Filters

**File:** `backend/app/api/investigation.py` (modify)

Add query parameters:
```python
  - host: str | None           # filter items involving this IP
  - mitre_id: str | None       # filter by MITRE technique
  - has_corroboration: bool     # only items with corroborating_count > 1
  - reviewed: bool | None       # True = reviewed, False = unreviewed, None = all
```

#### Evidence Bundle Endpoint

**File:** `backend/app/api/investigation.py` (modify)

```python
GET /jobs/{job_id}/investigation-queue/{item_id}/evidence-bundle

Response: EvidenceBundleResponse {
  item: InvestigationQueueItem,
  related_findings: FindingItem[],
  related_alerts: AlertItem[],
  related_connections: ConnectionItem[],
  related_hosts: HostItem[],
  timeline_events: TimelineEventItem[]   # events involving same hosts/IPs
}
```

This endpoint gathers all corroborating evidence for a single queue item by:
1. Extracting affected hosts from the item
2. Querying findings, alerts, connections, and timeline events involving those hosts
3. Returning the combined evidence in one response

#### Batch Status Update

**File:** `backend/app/api/investigation.py` (modify)

```python
PATCH /jobs/{job_id}/investigation-queue/batch-status
Body: {
  item_ids: list[str],
  status: "confirmed" | "false_positive" | "deferred",
  notes: str | None
}
Response: { updated: int }
```

### Frontend Changes

#### Queue UI Enhancements

**File:** `frontend/src/pages/InvestigationQueuePage.tsx` (modify)

New features:
- **Badge system:**
  - 🆕 "New in After" — items from `pcap_label="after"` that have no equivalent in "before"
  - 🔗 "Multiple Signals" — items with `corroborating_count > 2`
  - 💥 "High Blast Radius" — items affecting 3+ hosts
  - ⚠️ "Unreviewed" — items with `analyst_status = "unreviewed"`
- **Filter bar:**
  - Severity multi-select
  - Source type multi-select
  - Host IP autocomplete
  - MITRE technique dropdown
  - Status filter (unreviewed / confirmed / false_positive / deferred)
  - "Has corroboration" toggle
- **Evidence drawer:**
  - Click item to expand inline evidence bundle (from evidence-bundle endpoint)
  - Shows related findings, alerts, connections, and timeline events
  - "Open full details" button for deep-dive
- **Batch actions:**
  - Checkbox selection on items
  - Batch confirm / batch false-positive / batch defer
- **URL state:**
  - Persist filter state in URL query params for shareability
  - `?severity=high&status=unreviewed&host=10.6.13.133`

#### Evidence Drawer Component

**File:** `frontend/src/components/EvidenceDrawer.tsx` (new)

Reusable collapsible panel that:
- Fetches evidence bundle on expand
- Shows tabbed sections: Findings | Alerts | Connections | Timeline
- Highlights the source item in context

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/api/investigation.py` | **Modify** | Add filters, evidence-bundle, batch-status endpoints |
| `backend/app/schemas/investigation.py` | **Modify** | Add EvidenceBundleResponse, BatchStatusRequest schemas |
| `frontend/src/pages/InvestigationQueuePage.tsx` | **Modify** | Badges, filters, evidence drawer, batch actions |
| `frontend/src/components/EvidenceDrawer.tsx` | **Create** | Reusable evidence panel |

### Sprint 2 Testing & Validation

#### Backend Tests

**File:** `tests/unit/test_ranking.py` (extend)

| Test | Description |
|------|-------------|
| `test_host_filter` | Filter by host IP returns only items involving that host |
| `test_mitre_filter` | Filter by MITRE technique ID returns matching items |
| `test_corroboration_filter` | `has_corroboration=true` excludes isolated items |

**File:** `tests/integration/test_investigation_api.py` (extend)

| Test | Description |
|------|-------------|
| `test_evidence_bundle_returns_related_data` | Verify evidence bundle includes related findings/alerts |
| `test_batch_status_updates_multiple_items` | Verify batch PATCH updates all specified items |
| `test_combined_filters` | Severity + host + status filters work together |
| `test_url_params_reproduce_results` | Same query params produce same results |

#### Frontend Tests

**File:** `frontend/tests/e2e/investigation-queue.spec.ts` (extend)

| Test | Description |
|------|-------------|
| `test_filter_by_host` | Enter host IP, verify items filtered |
| `test_evidence_drawer_opens` | Click item, verify evidence drawer expands |
| `test_batch_confirm` | Select 3 items, batch confirm, verify all updated |
| `test_badges_display` | Verify "New in After" badge appears for after-phase items |
| `test_url_state_persistence` | Apply filters, reload page, verify filters persist |

#### Manual Validation Checklist

- [ ] Analyst can filter queue to "unreviewed high-severity items involving host X"
- [ ] Evidence drawer shows corroborating signals without leaving the queue page
- [ ] Batch confirm works on 5+ items simultaneously
- [ ] URL reflects current filter state and is shareable
- [ ] Badge system correctly identifies "new in after" and "high blast radius" items

### Sprint 2 Exit Criteria

1. All enhanced filters work correctly with combined parameters
2. Evidence bundle endpoint returns corroborating data
3. Batch status update handles 50+ items
4. Badge system correctly categorizes items
5. All Sprint 1 + Sprint 2 tests pass
6. TypeScript compiles, Docker builds

---

## Release 1 Merge Procedure

### Pre-Merge Checklist

```bash
# 1. Ensure all tests pass
cd /home/bc/Documents/AIPAM
pytest tests/unit/test_ranking.py tests/integration/test_investigation_api.py -v
cd frontend && npx tsc --noEmit

# 2. Verify Docker builds
docker compose build --no-cache

# 3. Run full existing test suite to verify no regressions
pytest tests/ -v --ignore=tests/e2e

# 4. Run frontend e2e tests
cd frontend && npx playwright test tests/e2e/investigation-queue.spec.ts

# 5. Manual analyst walkthrough
# - Open a completed job
# - Verify Investigation Queue is first tab
# - Triage 10 items using the queue
# - Verify filters, badges, evidence drawer, batch actions

# 6. Merge to main
git checkout main
git merge feature/investigation-queue --no-ff -m "feat: Release 1 — Investigation Queue (Sprints 1-2)"
git push origin main

# 7. Package offline update
bash deploy/create-code-update.sh

# 8. Verify package
ls -lh dist/aipam-code-update-*/
```

### Post-Merge Validation

- [ ] `main` branch builds and runs correctly
- [ ] Existing jobs are accessible (no migration issues)
- [ ] New Investigation Queue tab appears on completed jobs
- [ ] Offline update package is < 7GB and contains all three expected files

---



# RELEASE 2 — Temporal + Trust

**Branch:** `feature/temporal-hitl`
**Cut from:** `main` (after Release 1 merge)
**Sprints:** 3–4 (4 weeks)
**Merge target:** `main`

---

## Sprint 3 — Before/After Comparison Workspace (Weeks 5–6)

### Goal
Turn the existing multi-PCAP temporal plumbing into a **visual analyst workspace** that answers: "What changed? What's new? What's worse? Did containment help?"

### Existing Foundation (No Changes Needed)

These files already provide the backend data:
- `backend/app/api/temporal.py` — `GET /jobs/{jobId}/temporal-delta`, `GET /jobs/{jobId}/temporal-flows`, `POST /jobs/{jobId}/temporal-narrative`
- `backend/app/schemas/temporal.py` — `TemporalDeltaResponse`, `TemporalFlowsResponse`, `TemporalNarrativeResponse`
- `backend/app/models/job_pcap.py` — `JobPcap` with `pcap_label` (before/after)

### Backend Changes

#### Enhanced Temporal Delta

**File:** `backend/app/api/temporal.py` (modify)

Add to the existing `TemporalDeltaResponse`:
```python
# New fields in the response
phase_summary: {
  before: { host_count, alert_count, finding_count, connection_count, ioc_count },
  after:  { host_count, alert_count, finding_count, connection_count, ioc_count }
},
severity_shift: {
  critical: { before: int, after: int, delta: int },
  high: { before: int, after: int, delta: int },
  medium: { before: int, after: int, delta: int },
  low: { before: int, after: int, delta: int }
},
containment_indicators: {
  removed_c2_connections: int,
  reduced_alert_categories: list[str],
  new_defensive_activity: list[str]
}
```

#### Temporal Export Endpoint

**File:** `backend/app/api/temporal.py` (modify)

```python
GET /jobs/{job_id}/temporal-export
Query params:
  - format: "markdown" | "html" (default "markdown")

Response: { content: str, filename: str }
```

Generates a structured before/after comparison report using the temporal delta and narrative.

### Frontend Changes

#### New Page: `ComparePage.tsx`

**File:** `frontend/src/pages/ComparePage.tsx` (new)

Layout — split-pane comparison workspace:

```
┌──────────────────────────────────────────────────┐
│  Before/After Comparison    [Export ▼] [Narrative]│
├────────────────────┬─────────────────────────────┤
│                    │                              │
│  Summary Cards     │  Delta Details               │
│  ┌──────┐ ┌──────┐│  ┌─────────────────────────┐│
│  │Before│ │After ││  │ New Hosts (after only)   ││
│  │ 12   │ │ 18   ││  │ 10.6.13.200             ││
│  │hosts │ │hosts ││  │ 10.6.13.201             ││
│  └──────┘ └──────┘│  ├─────────────────────────┤│
│  ┌──────┐ ┌──────┐│  │ New Alerts               ││
│  │  5   │ │ 14   ││  │ ▲ 9 new high-severity   ││
│  │alerts│ │alerts││  │ Zeus C2 beacon (NEW)     ││
│  └──────┘ └──────┘│  ├─────────────────────────┤│
│                    │  │ New Findings             ││
│  Severity Shift    │  │ Lateral movement (NEW)   ││
│  ■■■■□ → ■■■■■■■  │  ├─────────────────────────┤│
│  (before → after)  │  │ Removed Connections      ││
│                    │  │ C2 to 185.x.x.x (GONE) ││
│  Containment       │  ├─────────────────────────┤│
│  ✅ 3 C2 removed   │  │ IOC Deltas               ││
│  ⚠️ 2 new C2 found │  │ +5 new IPs, -2 removed  ││
│                    │  └─────────────────────────┘│
├────────────────────┴─────────────────────────────┤
│  [Generate Narrative]                             │
│  "After containment, 3 C2 connections were        │
│   severed but 2 new lateral movement paths..."    │
└──────────────────────────────────────────────────┘
```

Features:
- **Summary cards** with before/after counts and delta arrows
- **Severity shift bar** showing visual escalation/de-escalation
- **Containment indicators** with ✅/⚠️ status
- **Delta detail sections:** new hosts, new alerts, new findings, removed connections, IOC changes
- **Narrative button** — calls `POST /jobs/{jobId}/temporal-narrative` and displays result
- **Export button** — downloads markdown or HTML comparison report
- Items in delta lists are **clickable** — link to detail pages with `pcap_label` context

#### Route Registration

**File:** `frontend/src/App.tsx` (modify)

Add route: `/jobs/:jobId/compare` → `ComparePage`

#### Navigation Update

**File:** `frontend/src/pages/JobDetailPage.tsx` (modify)

Add "Compare" tab — **only visible** when job has 2+ PCAPs with different `pcap_label` values. Check via existing `/jobs/{jobId}/pcaps` endpoint.

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/api/temporal.py` | **Modify** | Enhanced delta response, export endpoint |
| `backend/app/schemas/temporal.py` | **Modify** | Add `phase_summary`, `severity_shift`, `containment_indicators` |
| `frontend/src/pages/ComparePage.tsx` | **Create** | Split-pane comparison workspace |
| `frontend/src/App.tsx` | **Modify** | Add compare route |
| `frontend/src/pages/JobDetailPage.tsx` | **Modify** | Add conditional Compare tab |

### Sprint 3 Testing & Validation

#### Backend Tests

**File:** `tests/integration/test_temporal_api.py` (extend existing or new)

| Test | Description |
|------|-------------|
| `test_enhanced_delta_has_phase_summary` | Verify `phase_summary` fields present in response |
| `test_severity_shift_computed_correctly` | Create before/after data, verify delta counts |
| `test_containment_indicators_detect_removed_c2` | After phase removes C2, verify indicator |
| `test_temporal_export_markdown` | Export as markdown, verify structured content |
| `test_temporal_export_html` | Export as HTML, verify valid HTML |
| `test_single_pcap_job_returns_error` | Job without before/after PCAPs returns 400 |

#### Frontend Tests

**File:** `frontend/tests/e2e/compare.spec.ts` (new)

| Test | Description |
|------|-------------|
| `test_compare_page_loads_for_temporal_job` | Navigate to compare, verify page renders |
| `test_compare_tab_hidden_for_single_pcap` | Single-PCAP job has no Compare tab |
| `test_summary_cards_show_counts` | Verify before/after count cards display |
| `test_narrative_generation` | Click narrative button, verify text appears |
| `test_export_downloads_file` | Click export, verify file download triggers |

#### Manual Validation Checklist

- [ ] Compare tab only appears for jobs with before + after PCAPs
- [ ] Summary cards accurately reflect before/after counts
- [ ] Delta sections correctly identify new, changed, and removed items
- [ ] Narrative generation produces coherent temporal analysis
- [ ] Export produces well-formatted markdown document
- [ ] Clicking delta items navigates to correct detail pages

### Sprint 3 Exit Criteria

1. Enhanced temporal delta response includes `phase_summary`, `severity_shift`, `containment_indicators`
2. Temporal export endpoint generates markdown and HTML
3. Compare page renders split-pane layout with all sections
4. Narrative generation works end-to-end
5. All temporal tests pass
6. TypeScript compiles, Docker builds

---

## Sprint 4 — HITL Review Workflow (Weeks 7–8)

### Goal
Formalize the transition from "unverified lead" to "confirmed evidence" with an auditable review workflow that gates downstream actions.

### Existing Foundation

- `backend/app/models/finding.py` — already has `feedback` column ("confirmed", "false_positive", "false_negative")
- `backend/app/api/findings.py` — has `PATCH /jobs/{jobId}/findings/{findingId}/feedback`
- `ARCHITECTURAL_CONSTITUTION.md` §3 — "The `hitl.findings_review` link is the final authority"
- Sprint 1 adds `analyst_status`, `analyst_notes`, `reviewed_at` columns to findings, alerts, and theories

### Backend Changes

#### Formal Review Status Enum

**File:** `backend/app/schemas/common.py` (modify)

```python
class AnalystStatus(str, Enum):
    unreviewed = "unreviewed"
    confirmed = "confirmed"
    false_positive = "false_positive"
    needs_review = "needs_review"     # NEW: flagged for second opinion
    deferred = "deferred"
```

#### Review Queue Endpoint

**File:** `backend/app/api/investigation.py` (modify)

```python
GET /jobs/{job_id}/review-queue
Query params:
  - status: AnalystStatus | None
  - reviewer: str | None
  - since: datetime | None

Response: ReviewQueueResponse {
  items: InvestigationQueueItem[],
  page: PageInfo,
  stats: {
    total: int,
    confirmed: int,
    false_positive: int,
    needs_review: int,
    deferred: int,
    unreviewed: int,
    review_rate: float    # confirmed / (confirmed + false_positive)
  }
}
```

This is a filtered view of the investigation queue showing only items that are in a review-relevant state, with review statistics.

#### Gated Actions

**File:** `backend/app/api/findings.py` (modify)

Add confirmation checks before these operations:

| Action | Gate | Behavior |
|--------|------|----------|
| Rule export (`POST /findings/{id}/export`) | `analyst_status == "confirmed"` | Return 409 if unconfirmed |
| Memory indexing (forensic_memory.py) | `analyst_status == "confirmed"` | Skip unconfirmed findings |
| Report "final" mode | All included findings confirmed | Warning if unconfirmed items included |

```python
# In export endpoint
if finding.analyst_status != "confirmed":
    raise HTTPException(
        status_code=409,
        detail="Finding must be confirmed before rule export. "
               "Use PATCH /investigation-queue/{id}/status to confirm."
    )
```

#### Review Audit Trail

**File:** `backend/app/models/finding.py` (modify)
**File:** `backend/app/models/alert.py` (modify)
**File:** `backend/app/models/theory.py` (modify)

Add `reviewer_id` column (string, nullable) — for future multi-user support. Currently set to "analyst" (single-user mode).

### Frontend Changes

#### Review Mode Toggle

**File:** `frontend/src/pages/InvestigationQueuePage.tsx` (modify)

Add "Review Mode" toggle that:
- Switches queue to show only reviewed items grouped by status
- Shows review statistics bar: "12 confirmed, 3 false positives, 5 deferred, 8 pending"
- Highlights items marked `needs_review`

#### Confirmation Gate UI

**File:** `frontend/src/pages/FindingDetailPage.tsx` (modify)

- If finding is unconfirmed, show warning banner: "⚠️ This finding is unreviewed. Confirm it before exporting rules."
- Rule export button shows disabled state with tooltip explaining the gate
- After confirmation, export button becomes active

#### Review Notes Panel

**File:** `frontend/src/components/ReviewNotesPanel.tsx` (new)

Inline panel on detail pages showing:
- Current status badge
- Analyst notes (editable)
- Review timestamp
- Status change buttons (Confirm / False Positive / Needs Review / Defer)
- Status history (if changed multiple times)

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/schemas/common.py` | **Modify** | Add `AnalystStatus` enum with `needs_review` |
| `backend/app/api/investigation.py` | **Modify** | Add review queue endpoint |
| `backend/app/api/findings.py` | **Modify** | Add confirmation gates on export |
| `backend/app/models/finding.py` | **Modify** | Add `reviewer_id` column |
| `backend/app/models/alert.py` | **Modify** | Add `reviewer_id` column |
| `backend/app/models/theory.py` | **Modify** | Add `reviewer_id` column |
| `backend/alembic/versions/xxx_add_reviewer_id.py` | **Create** | DB migration |
| `frontend/src/pages/InvestigationQueuePage.tsx` | **Modify** | Review mode toggle |
| `frontend/src/pages/FindingDetailPage.tsx` | **Modify** | Confirmation gate UI |
| `frontend/src/components/ReviewNotesPanel.tsx` | **Create** | Review notes component |

### Sprint 4 Testing & Validation

#### Backend Tests

**File:** `tests/unit/test_hitl_gates.py` (new)

| Test | Description |
|------|-------------|
| `test_export_blocked_for_unconfirmed` | Rule export returns 409 for unreviewed finding |
| `test_export_allowed_for_confirmed` | Rule export succeeds for confirmed finding |
| `test_memory_indexing_skips_unconfirmed` | Forensic memory only indexes confirmed findings |
| `test_needs_review_status` | Setting `needs_review` status works correctly |

**File:** `tests/integration/test_review_workflow.py` (new)

| Test | Description |
|------|-------------|
| `test_review_queue_shows_stats` | Verify review stats are accurate |
| `test_full_review_lifecycle` | Create finding → confirm → export → verify |
| `test_review_queue_filter_by_status` | Filter by confirmed only |
| `test_reviewer_id_populated` | Verify reviewer_id is set on status change |

#### Frontend Tests

**File:** `frontend/tests/e2e/review-workflow.spec.ts` (new)

| Test | Description |
|------|-------------|
| `test_review_mode_toggle` | Toggle review mode, verify UI changes |
| `test_export_gate_shows_warning` | Unconfirmed finding shows export warning |
| `test_confirm_enables_export` | Confirm finding, verify export button activates |
| `test_review_notes_persist` | Add notes, reload, verify notes present |

#### Manual Validation Checklist

- [ ] Attempting to export rules for unconfirmed finding shows clear error message
- [ ] Confirming a finding enables rule export
- [ ] Review mode shows accurate statistics
- [ ] "Needs review" flag is visible and actionable
- [ ] Analyst notes persist across page navigation

### Sprint 4 Exit Criteria

1. Confirmation gates prevent export of unreviewed findings
2. Review queue endpoint shows accurate statistics
3. Review mode UI toggle works correctly
4. All HITL tests pass
5. Existing finding feedback tests still pass (backward compatibility)
6. TypeScript compiles, Docker builds

---

## Release 2 Merge Procedure

### Pre-Merge Checklist

```bash
# 1. Run all Release 2 tests
cd /home/bc/Documents/AIPAM
pytest tests/integration/test_temporal_api.py tests/unit/test_hitl_gates.py tests/integration/test_review_workflow.py -v

# 2. Run full test suite for regression
pytest tests/ -v --ignore=tests/e2e

# 3. Frontend checks
cd frontend && npx tsc --noEmit
cd frontend && npx playwright test tests/e2e/compare.spec.ts tests/e2e/review-workflow.spec.ts

# 4. Docker build
docker compose build --no-cache

# 5. Manual walkthrough
# - Upload before + after PCAPs
# - Verify Compare tab appears and shows accurate delta
# - Generate temporal narrative
# - Export comparison report
# - Attempt rule export on unconfirmed finding (should be blocked)
# - Confirm finding, verify export now works
# - Check review mode statistics

# 6. Merge
git checkout main
git merge feature/temporal-hitl --no-ff -m "feat: Release 2 — Temporal Compare + HITL Review (Sprints 3-4)"
git push origin main

# 7. Package
bash deploy/create-code-update.sh
```

### Post-Merge Validation

- [ ] `main` branch builds and runs correctly
- [ ] Release 1 features (Investigation Queue) still work
- [ ] Compare page renders for temporal jobs
- [ ] HITL gates enforce confirmation requirements
- [ ] Offline update package generates successfully

---


# RELEASE 3 — Reporting + Speed

**Branch:** `feature/proof-partial`
**Cut from:** `main` (after Release 2 merge)
**Sprints:** 5–6 (4 weeks)
**Merge target:** `main`

---

## Sprint 5 — Draft Case Narrative / Proof Builder (Weeks 9–10)

### Goal
Shorten the path from confirmed evidence to deliverable report. Analyst selects evidence, AIPAM generates a structured first-draft narrative.

### Backend Changes

#### Proof Builder API

**File:** `backend/app/api/proof.py` (new)

```python
POST /jobs/{job_id}/proof/build
Body: {
  title: str,
  included_items: list[str],          # queue_item_ids from investigation queue
  mode: "soc_handoff" | "ir_technical" | "executive_summary",
  include_timeline: bool (default true),
  include_mitre_mapping: bool (default true),
  include_recommendations: bool (default true)
}

Response: ProofDraftResponse {
  proof_id: str,
  title: str,
  mode: str,
  narrative: str,                      # markdown narrative
  sections: [
    { heading: str, content: str, evidence_refs: list[str] }
  ],
  included_items: list[InvestigationQueueItem],
  generated_at: datetime,
  warnings: list[str]                  # e.g. "3 included items are unconfirmed"
}
```

```python
GET /jobs/{job_id}/proof/{proof_id}
Response: ProofDraftResponse

PATCH /jobs/{job_id}/proof/{proof_id}
Body: { narrative: str }               # analyst can edit the draft
Response: ProofDraftResponse

GET /jobs/{job_id}/proof/{proof_id}/export
Query params:
  - format: "markdown" | "html"
Response: { content: str, filename: str }
```

#### Proof Database Table

**File:** `backend/app/models/proof.py` (new)

```python
class Proof(Base):
    __tablename__ = "proofs"
    id = Column(String, primary_key=True)       # UUID
    job_id = Column(String, ForeignKey("jobs.job_id"), nullable=False)
    title = Column(String, nullable=False)
    mode = Column(String, nullable=False)        # soc_handoff, ir_technical, executive_summary
    narrative = Column(Text, nullable=False)      # editable markdown
    included_item_ids = Column(Text, nullable=False)  # JSON list of queue_item_ids
    generated_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=True)
```

#### Narrative Generation Service

**File:** `backend/app/services/narrative.py` (new)

Uses the existing LLM client (`backend/app/llm_client.py`) to generate structured narratives:

```python
def generate_case_narrative(
    items: list[InvestigationQueueItem],
    mode: str,
    job_context: dict
) -> str:
    """Generate a structured case narrative from confirmed evidence."""
    # Sections generated based on mode:
    # SOC Handoff: Executive Summary, Key Findings, Affected Systems, Recommended Actions
    # IR Technical: Incident Summary, Attack Path, Indicator Analysis, Timeline, MITRE Mapping, Containment Status
    # Executive Summary: Business Impact, Risk Assessment, Remediation Status, Next Steps
```

### Frontend Changes

#### Proof Builder Page

**File:** `frontend/src/pages/ProofBuilderPage.tsx` (new)

Features:
- **Evidence selection panel** (left): shows investigation queue items with checkboxes
  - Filter: confirmed only (default), all, specific severity
  - Drag-and-drop reordering of selected items
- **Draft preview panel** (right): shows generated narrative in markdown
  - Editable text area for analyst modifications
  - Section collapse/expand
  - Evidence reference links (clickable back to source)
- **Mode selector**: SOC Handoff | IR Technical | Executive Summary
- **Generate button**: calls `POST /jobs/{jobId}/proof/build`
- **Export button**: downloads as markdown or HTML
- **Save button**: persists edits via `PATCH /jobs/{jobId}/proof/{proofId}`
- **Warning banner**: shows if unconfirmed items are included

#### Navigation

**File:** `frontend/src/App.tsx` (modify) — add `/jobs/:jobId/proof` route
**File:** `frontend/src/pages/JobDetailPage.tsx` (modify) — add "Build Case" tab
**File:** `frontend/src/pages/InvestigationQueuePage.tsx` (modify) — add "Build Case from Selected" action button

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/api/proof.py` | **Create** | Proof CRUD + generation endpoints |
| `backend/app/models/proof.py` | **Create** | Proof database model |
| `backend/app/services/narrative.py` | **Create** | LLM narrative generation |
| `backend/app/schemas/proof.py` | **Create** | Request/response schemas |
| `backend/alembic/versions/xxx_add_proofs_table.py` | **Create** | DB migration |
| `frontend/src/pages/ProofBuilderPage.tsx` | **Create** | Proof builder UI |
| `frontend/src/App.tsx` | **Modify** | Add proof route |
| `frontend/src/pages/JobDetailPage.tsx` | **Modify** | Add Build Case tab |
| `frontend/src/pages/InvestigationQueuePage.tsx` | **Modify** | Add "Build Case" action |

### Sprint 5 Testing & Validation

#### Backend Tests

**File:** `tests/unit/test_narrative.py` (new)

| Test | Description |
|------|-------------|
| `test_soc_handoff_has_required_sections` | SOC mode includes Executive Summary, Key Findings, etc. |
| `test_ir_technical_has_mitre_mapping` | IR mode includes MITRE ATT&CK section |
| `test_executive_has_business_impact` | Executive mode includes Business Impact section |
| `test_unconfirmed_items_generate_warnings` | Including unconfirmed items produces warnings |

**File:** `tests/integration/test_proof_api.py` (new)

| Test | Description |
|------|-------------|
| `test_build_proof_returns_narrative` | POST build returns structured narrative |
| `test_proof_persists_and_retrieves` | GET proof returns saved data |
| `test_proof_edit_persists` | PATCH narrative, verify GET returns updated text |
| `test_proof_export_markdown` | Export as markdown, verify format |
| `test_proof_export_html` | Export as HTML, verify valid HTML |

#### Manual Validation Checklist

- [ ] Analyst can select items from queue and generate a case narrative
- [ ] Three report modes produce appropriately different outputs
- [ ] Analyst can edit the generated narrative and save changes
- [ ] Export produces well-formatted documents
- [ ] Warning appears when unconfirmed items are included

### Sprint 5 Exit Criteria

1. Proof build endpoint generates structured narratives in 3 modes
2. Proof CRUD operations work correctly
3. Export produces valid markdown and HTML
4. Analyst edits are persisted
5. All proof tests pass
6. TypeScript compiles, Docker builds

---


## Sprint 6 — Early Partial Results (Weeks 11–12)

### Goal
Reduce time-to-first-insight by surfacing early pipeline results while LLM analysis is still running.

### Existing Foundation

- `PartialJobResultDB` in `backend/app/db_models.py` — already stores intermediate results
- SSE endpoint `GET /jobs/{jobId}/events` in `backend/app/api/jobs.py` — real-time event streaming
- `useJobEvents` hook in `frontend/src/hooks/useJobEvents.ts` — frontend SSE consumer
- Pipeline checkpoints in `PipelineCheckpointDB` — step-by-step state tracking

### Backend Changes

#### Progressive Result Publishing

**File:** `backend/app/pipeline/orchestrator.py` (modify)

After each pipeline stage completes, publish partial results to the `PartialJobResultDB`:

| After Stage | Partial Result Published |
|-------------|--------------------------|
| `ingest` | File metadata, PCAP stats (size, packet count, duration) |
| `parse` | Top 10 talking hosts, protocol distribution, Suricata alert summary |
| `aggregate` | Host summaries, connection graph outline, initial anomaly flags |
| `sensors` | Sensor-specific results as each sensor completes |
| `llm_analysis` | (Full results — replaces partial) |

```python
# In orchestrator.py, after each stage:
_publish_partial_result(db, job_id, stage_name, {
    "stage": stage_name,
    "completed_at": datetime.utcnow().isoformat(),
    "data": stage_output_summary
})
```

#### SSE Event Types for Partial Results

**File:** `backend/app/api/jobs.py` (modify)

Add new SSE event types:
```python
# New event types emitted during pipeline
"partial_result"    # stage completed, partial data available
"early_alert"       # high-severity alert detected during parse
"sensor_complete"   # individual sensor finished
```

#### Partial Results API

**File:** `backend/app/api/jobs.py` (modify)

```python
GET /jobs/{job_id}/partial-results
Response: {
  job_id: str,
  status: str,                    # "running" | "completed"
  completed_stages: list[str],
  current_stage: str | None,
  partial_data: {
    pcap_stats: { ... } | None,
    top_hosts: list[HostSummary] | None,
    alert_summary: { total: int, by_severity: dict } | None,
    early_findings: list[FindingItem] | None,
    sensor_results: dict | None
  },
  estimated_completion: datetime | None
}
```

### Frontend Changes

#### Progressive Job Detail Page

**File:** `frontend/src/pages/JobDetailPage.tsx` (modify)

When job status is `running`:
- Show **progress stepper** with completed/active/pending stages
- Display partial results as they arrive via SSE:
  - PCAP stats card (after ingest)
  - Top hosts table (after parse)
  - Alert summary bar (after parse)
  - Early findings list (after aggregate)
- Clear "⏳ Analysis in progress — showing preliminary results" banner
- Auto-transition to full results when job completes

#### Early Alert Toast

**File:** `frontend/src/components/ToastProvider.tsx` (modify)

When `early_alert` SSE event received:
- Show toast notification: "🚨 High-severity alert: {alert.title}"
- Toast links to the alert detail when clicked

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/pipeline/orchestrator.py` | **Modify** | Publish partial results after each stage |
| `backend/app/api/jobs.py` | **Modify** | Partial results endpoint, new SSE events |
| `frontend/src/pages/JobDetailPage.tsx` | **Modify** | Progressive display, progress stepper |
| `frontend/src/components/ToastProvider.tsx` | **Modify** | Early alert toasts |
| `frontend/src/hooks/useJobEvents.ts` | **Modify** | Handle new SSE event types |

### Sprint 6 Testing & Validation

#### Backend Tests

**File:** `tests/integration/test_partial_results.py` (new)

| Test | Description |
|------|-------------|
| `test_partial_result_published_after_parse` | After parse stage, partial result exists |
| `test_partial_result_includes_top_hosts` | Partial result contains top hosts after parse |
| `test_partial_result_replaced_on_completion` | After full completion, partial result is cleaned up |
| `test_sse_emits_partial_result_event` | SSE stream includes `partial_result` events |
| `test_partial_results_endpoint_returns_data` | GET partial-results returns current state |

#### Frontend Tests

**File:** `frontend/tests/e2e/partial-results.spec.ts` (new)

| Test | Description |
|------|-------------|
| `test_progress_stepper_shows_stages` | Running job shows stage progress |
| `test_partial_data_displays` | Partial results appear as stages complete |
| `test_transition_to_full_results` | Page transitions when job completes |

#### Manual Validation Checklist

- [ ] Running job shows progress stepper with current stage highlighted
- [ ] Top hosts appear after parse completes (before LLM finishes)
- [ ] Alert summary appears early
- [ ] High-severity alerts trigger toast notifications
- [ ] Full results seamlessly replace partial results on completion
- [ ] No flicker or data loss during transition

### Sprint 6 Exit Criteria

1. Partial results published after ingest, parse, and aggregate stages
2. SSE emits `partial_result` and `early_alert` events
3. Frontend displays progressive results during analysis
4. Smooth transition from partial to full results
5. All partial results tests pass
6. TypeScript compiles, Docker builds

---

## Release 3 Merge Procedure

### Pre-Merge Checklist

```bash
# 1. Run Release 3 tests
cd /home/bc/Documents/AIPAM
pytest tests/unit/test_narrative.py tests/integration/test_proof_api.py tests/integration/test_partial_results.py -v

# 2. Full regression
pytest tests/ -v --ignore=tests/e2e

# 3. Frontend
cd frontend && npx tsc --noEmit
cd frontend && npx playwright test tests/e2e/partial-results.spec.ts

# 4. Docker build
docker compose build --no-cache

# 5. Manual walkthrough
# - Build a case from confirmed findings
# - Export as markdown and HTML
# - Upload a new PCAP and watch partial results appear
# - Verify early alerts trigger toasts
# - Verify Investigation Queue and Compare still work (R1 + R2)

# 6. Merge
git checkout main
git merge feature/proof-partial --no-ff -m "feat: Release 3 — Proof Builder + Partial Results (Sprints 5-6)"
git push origin main

# 7. Package
bash deploy/create-code-update.sh
```

### Post-Merge Validation

- [ ] `main` branch builds and runs correctly
- [ ] All R1 + R2 features still work
- [ ] Proof builder generates and exports narratives
- [ ] Partial results display during active analysis
- [ ] Offline update package generates successfully

---


# RELEASE 4 — Self-Improving Platform

**Branch:** `feature/feedback-correlation`
**Cut from:** `main` (after Release 3 merge)
**Sprints:** 7–8 (4 weeks)
**Merge target:** `main`

---

## Sprint 7 — Feedback-Driven Ranking & Noise Reduction (Weeks 13–14)

### Goal
Make the Investigation Queue smarter over time by learning from analyst confirmation and rejection patterns.

### Backend Changes

#### Feedback Analytics Service

**File:** `backend/app/services/feedback_analytics.py` (new)

Computes aggregate metrics from analyst review decisions across all jobs:

```python
class FeedbackAnalytics:
    def compute_sensor_trust(self, db) -> dict[str, SensorTrustProfile]:
        """Per-sensor confirmation rate, false positive rate, avg confidence delta."""

    def compute_signature_noise(self, db) -> list[NoisySignature]:
        """Signatures/categories with high false_positive rates."""

    def compute_ranking_adjustments(self, db) -> dict[str, float]:
        """Weight adjustments to apply to the ranking formula based on feedback."""

class SensorTrustProfile(BaseModel):
    sensor_name: str
    total_findings: int
    confirmed: int
    false_positive: int
    deferred: int
    confirmation_rate: float       # confirmed / (confirmed + false_positive)
    avg_confidence_delta: float    # avg(analyst_confidence - model_confidence)

class NoisySignature(BaseModel):
    signature_id: str
    signature_name: str
    category: str
    false_positive_rate: float
    total_occurrences: int
    last_seen: datetime
```

#### Enhanced Ranking with Feedback Weights

**File:** `backend/app/services/ranking.py` (modify)

Update ranking formula to incorporate feedback history:

```
rank_score = (
    severity_weight              * 0.25   # (reduced from 0.30)
  + confidence                   * 0.20   # (reduced from 0.25)
  + corroboration_score          * 0.20   # (unchanged)
  + blast_radius_score           * 0.15   # (unchanged)
  + recency_score                * 0.10   # (unchanged)
  + feedback_adjustment          * 0.10   # NEW: learned from analyst behavior
)

feedback_adjustment = (
    sensor_trust_factor          * 0.50   # high-trust sensors get boosted
  + signature_noise_penalty      * 0.30   # noisy signatures get penalized
  + category_confirmation_rate   * 0.20   # categories that get confirmed rank higher
)
```

#### Admin Metrics Endpoint

**File:** `backend/app/api/admin.py` (new)

```python
GET /admin/feedback-metrics
Response: {
  sensor_trust: list[SensorTrustProfile],
  noisy_signatures: list[NoisySignature],    # top 20 by false_positive_rate
  overall_stats: {
    total_reviewed: int,
    confirmation_rate: float,
    avg_review_time_seconds: float,
    most_trusted_sensor: str,
    noisiest_sensor: str
  },
  time_series: {
    daily_reviews: list[{ date: str, confirmed: int, false_positive: int }]
  }
}
```

### Frontend Changes

#### Admin Feedback Dashboard

**File:** `frontend/src/pages/AdminFeedbackPage.tsx` (new)

Features:
- **Sensor Trust Table**: per-sensor confirmation rate, volume, trend
- **Noisy Signatures List**: signatures with high false positive rates, with "suppress" action
- **Overall Stats Cards**: total reviewed, confirmation rate, avg review time
- **Daily Review Chart**: line chart showing review volume and confirmation rate over time
- **Ranking Impact Preview**: show how current feedback weights would change queue ordering

#### Queue Ranking Explanation

**File:** `frontend/src/pages/InvestigationQueuePage.tsx` (modify)

Add "Why this rank?" tooltip on each queue item showing:
- Breakdown of rank_score factors
- Feedback adjustment explanation (e.g., "Sensor X has 85% confirmation rate → +0.08")
- Comparison to base score without feedback

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/services/feedback_analytics.py` | **Create** | Feedback computation service |
| `backend/app/services/ranking.py` | **Modify** | Add feedback-adjusted ranking |
| `backend/app/api/admin.py` | **Create** | Admin metrics endpoint |
| `backend/app/schemas/admin.py` | **Create** | Admin response schemas |
| `frontend/src/pages/AdminFeedbackPage.tsx` | **Create** | Feedback dashboard |
| `frontend/src/pages/InvestigationQueuePage.tsx` | **Modify** | Rank explanation tooltips |
| `frontend/src/App.tsx` | **Modify** | Add admin route |

### Sprint 7 Testing & Validation

#### Backend Tests

**File:** `tests/unit/test_feedback_analytics.py` (new)

| Test | Description |
|------|-------------|
| `test_sensor_trust_computed_correctly` | Sensor with 8 confirmed / 2 FP = 80% trust |
| `test_noisy_signature_detected` | Signature with >60% FP rate flagged as noisy |
| `test_ranking_adjustment_boosts_trusted_sensor` | Trusted sensor findings rank higher |
| `test_ranking_adjustment_penalizes_noisy_signature` | Noisy signature findings rank lower |
| `test_no_feedback_returns_neutral_adjustment` | Zero feedback → adjustment = 0.0 |

**File:** `tests/integration/test_feedback_ranking.py` (new)

| Test | Description |
|------|-------------|
| `test_queue_order_changes_after_feedback` | Confirm findings from sensor A, verify A's items rank higher |
| `test_admin_metrics_endpoint` | Verify metrics response structure and accuracy |
| `test_feedback_metrics_time_series` | Verify daily review counts are correct |

#### Manual Validation Checklist

- [ ] After confirming 10+ findings from one sensor, that sensor's items rank higher in new jobs
- [ ] After marking 10+ false positives from a signature, those items rank lower
- [ ] Admin dashboard shows accurate sensor trust and noise data
- [ ] "Why this rank?" tooltip provides meaningful explanation
- [ ] Ranking changes are observable but not destabilizing

### Sprint 7 Exit Criteria

1. Feedback analytics computes sensor trust and signature noise
2. Ranking formula incorporates feedback adjustments
3. Admin metrics endpoint returns accurate data
4. Queue ranking observably improves with sufficient feedback
5. All feedback tests pass
6. TypeScript compiles, Docker builds

---

## Sprint 8 — Cross-Job Correlation UX (Weeks 15–16)

### Goal
Make forensic memory and cross-job correlation visible and actionable — not just technically present in the RAG backend.

### Existing Foundation

- `backend/app/api/chat.py` — RAG-powered chat with cross-job memory
- Architecture docs reference campaign correlation and forensic memory indexing
- Memory indexing already occurs for confirmed findings (after Sprint 4 HITL gate)

### Backend Changes

#### Cross-Job Correlation Endpoint

**File:** `backend/app/api/correlation.py` (new)

```python
GET /jobs/{job_id}/correlations
Query params:
  - item_id: str | None          # specific queue item to correlate
  - host: str | None             # specific IP to correlate
  - ioc: str | None              # specific IOC to correlate
  - limit: int (default 10)

Response: CorrelationResponse {
  query: { item_id | host | ioc },
  matches: list[CorrelationMatch],
  campaigns: list[CampaignCandidate]
}

class CorrelationMatch(BaseModel):
    job_id: str
    job_name: str
    job_created_at: datetime
    match_type: str              # "same_host" | "same_ioc" | "same_mitre" | "similar_pattern"
    matched_item: InvestigationQueueItem
    similarity_score: float      # 0.0–1.0
    context: str                 # brief explanation of why this matched

class CampaignCandidate(BaseModel):
    campaign_id: str             # generated grouping ID
    label: str                   # e.g., "Zeus C2 cluster across 3 jobs"
    job_ids: list[str]
    shared_iocs: list[str]
    shared_mitre_techniques: list[str]
    confidence: float
```

#### Seen-Before Utility

**File:** `backend/app/services/correlation.py` (new)

```python
def find_prior_occurrences(
    db, host: str | None, ioc: str | None, mitre_id: str | None,
    exclude_job_id: str | None
) -> list[CorrelationMatch]:
    """Search confirmed findings across all jobs for prior occurrences."""
    # Uses existing database queries + optional RAG similarity search
```

### Frontend Changes

#### "Seen Before?" Panel

**File:** `frontend/src/components/SeenBeforePanel.tsx` (new)

Appears on:
- `FindingDetailPage.tsx` — for the finding's hosts and IOCs
- `AlertDetailPage.tsx` — for alert source/destination IPs
- `InvestigationQueuePage.tsx` — as expandable section per item

Features:
- Shows prior job matches with similarity scores
- Clickable links to prior job findings
- "Same IOC seen in Job X (3 days ago)" with citation
- Campaign grouping indicator if multiple jobs share patterns

#### Related Jobs Sidebar

**File:** `frontend/src/components/RelatedJobsSidebar.tsx` (new)

Collapsible sidebar on JobDetailPage showing:
- Jobs with overlapping hosts
- Jobs with shared IOCs
- Jobs with similar MITRE technique patterns
- Sorted by relevance/recency

#### Navigation Updates

**File:** `frontend/src/pages/FindingDetailPage.tsx` (modify) — add SeenBeforePanel
**File:** `frontend/src/pages/AlertDetailPage.tsx` (modify) — add SeenBeforePanel
**File:** `frontend/src/pages/JobDetailPage.tsx` (modify) — add RelatedJobsSidebar

### Files Created/Modified Summary

| File | Action | Description |
|------|--------|-------------|
| `backend/app/api/correlation.py` | **Create** | Cross-job correlation endpoint |
| `backend/app/services/correlation.py` | **Create** | Correlation search service |
| `backend/app/schemas/correlation.py` | **Create** | Correlation response schemas |
| `frontend/src/components/SeenBeforePanel.tsx` | **Create** | Prior occurrence panel |
| `frontend/src/components/RelatedJobsSidebar.tsx` | **Create** | Related jobs sidebar |
| `frontend/src/pages/FindingDetailPage.tsx` | **Modify** | Add SeenBeforePanel |
| `frontend/src/pages/AlertDetailPage.tsx` | **Modify** | Add SeenBeforePanel |
| `frontend/src/pages/JobDetailPage.tsx` | **Modify** | Add RelatedJobsSidebar |
| `frontend/src/App.tsx` | **Modify** | Add correlation routes if needed |

### Sprint 8 Testing & Validation

#### Backend Tests

**File:** `tests/unit/test_correlation.py` (new)

| Test | Description |
|------|-------------|
| `test_same_host_correlation` | Two jobs with same host produce correlation match |
| `test_same_ioc_correlation` | Two jobs with same IOC produce correlation match |
| `test_mitre_technique_correlation` | Two jobs with same MITRE technique correlate |
| `test_campaign_candidate_detection` | 3+ jobs sharing IOCs produce campaign candidate |
| `test_no_correlation_for_single_job` | Single job returns empty correlations |
| `test_excludes_current_job` | Current job excluded from correlation results |

**File:** `tests/integration/test_correlation_api.py` (new)

| Test | Description |
|------|-------------|
| `test_correlation_endpoint_returns_matches` | GET correlations returns structured data |
| `test_correlation_by_host` | Filter by host returns host-specific matches |
| `test_correlation_by_ioc` | Filter by IOC returns IOC-specific matches |

#### Manual Validation Checklist

- [ ] "Seen Before?" panel shows prior occurrences on finding detail pages
- [ ] Clicking a prior match navigates to the source job/finding
- [ ] Related Jobs sidebar appears on job detail page
- [ ] Campaign grouping correctly clusters related jobs
- [ ] Correlations only include confirmed findings (HITL gate respected)

### Sprint 8 Exit Criteria

1. Correlation endpoint returns accurate cross-job matches
2. Campaign candidate detection works for 3+ related jobs
3. SeenBeforePanel renders on finding and alert detail pages
4. RelatedJobsSidebar renders on job detail page
5. All correlation tests pass
6. TypeScript compiles, Docker builds

---

## Release 4 Merge Procedure

### Pre-Merge Checklist

```bash
# 1. Run Release 4 tests
cd /home/bc/Documents/AIPAM
pytest tests/unit/test_feedback_analytics.py tests/unit/test_correlation.py \
       tests/integration/test_feedback_ranking.py tests/integration/test_correlation_api.py -v

# 2. Full regression (all releases)
pytest tests/ -v --ignore=tests/e2e

# 3. Frontend
cd frontend && npx tsc --noEmit
cd frontend && npx playwright test

# 4. Docker build
docker compose build --no-cache

# 5. Full system walkthrough
# - Complete a multi-PCAP job (before + after)
# - Triage via Investigation Queue (R1)
# - Compare before/after (R2)
# - Confirm findings via HITL review (R2)
# - Build case narrative from confirmed evidence (R3)
# - Observe partial results on a new job (R3)
# - Verify feedback ranking adjustments (R4)
# - Check "Seen Before?" correlations (R4)
# - Verify Related Jobs sidebar (R4)

# 6. Merge
git checkout main
git merge feature/feedback-correlation --no-ff -m "feat: Release 4 — Feedback Ranking + Cross-Job Correlation (Sprints 7-8)"
git push origin main

# 7. Package
bash deploy/create-code-update.sh

# 8. Verify package integrity
sha256sum dist/aipam-code-update-*/docker-images.tar.gz dist/aipam-code-update-*/repo.tar.gz
```

### Post-Merge Validation

- [ ] `main` branch builds and runs correctly
- [ ] All R1 + R2 + R3 features still work
- [ ] Feedback ranking produces observable improvements
- [ ] Cross-job correlations surface prior occurrences
- [ ] Campaign detection groups related jobs
- [ ] Offline update package generates successfully
- [ ] Full end-to-end analyst workflow completes without errors

---

# SUCCESS METRICS

## Analyst Speed

| Metric | Baseline (Current) | Target (After R4) | How to Measure |
|--------|--------------------|--------------------|----------------|
| Time to first meaningful lead | ~5–10 min (manual tab exploration) | < 30 sec (queue shows top lead) | Timestamp from job open to first item interaction |
| Time to first confirmation | ~15–20 min | < 5 min | Timestamp from job open to first `confirmed` status |
| Time to draft report | ~1–2 hours (manual) | < 15 min (proof builder) | Timestamp from first confirmation to proof export |
| Page hops per investigation | 4–6 tabs | 1–2 (queue + details) | Frontend analytics: distinct page navigations per session |

## Analyst Effectiveness

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Confirmed finding rate | > 40% of reviewed items | `confirmed / (confirmed + false_positive)` |
| False positive rejection rate | > 25% (noise reduction) | `false_positive / total_reviewed` |
| Before/After compare usage | > 60% of temporal jobs | Jobs with compare tab opened / jobs with 2+ PCAPs |
| Queue adoption | > 80% of sessions start from queue | Sessions starting from `/jobs/{id}/investigate` |
| Proof builder usage | > 50% of completed investigations | Jobs with at least one proof draft created |

## Product Quality

| Metric | Target | How to Measure |
|--------|--------|----------------|
| LLM explanation usefulness | > 70% positive | Chat feedback button ratio |
| Ranking accuracy improvement | Measurable after 50+ reviewed jobs | Spearman correlation between rank and analyst confirmation |
| Cross-job hit rate | > 30% of findings have prior occurrence | Correlations returned / total confirmed findings |
| Report edit ratio | < 30% of narrative changed | Levenshtein distance between generated and exported proof |

---

# RISK REGISTER

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| UI complexity — too many panels overwhelm analyst | Medium | High | Progressive disclosure: queue first, details on demand |
| LLM narratives outrun evidence quality | Medium | High | HITL gates in Sprint 4 prevent promotion of weak findings |
| Ranking formula doesn't match analyst intuition | Medium | Medium | Configurable weights, "Why this rank?" transparency |
| Large PCAPs cause partial results timeout | Low | Medium | Graceful degradation: show what's ready, indicate pending |
| Feedback loop amplifies bias | Low | Medium | Include "base score" alongside adjusted score for comparison |
| Migration issues on air-gapped server | Low | High | Alembic migrations with rollback scripts; test on staging first |
| Cross-job correlation produces false links | Medium | Medium | Require minimum similarity threshold; show confidence scores |
| Feature branch drift from main | Low | Medium | Short release cycles (4 weeks max); no cross-branch dependencies |

---

# COMPLETE FILE CHANGE INVENTORY

## New Backend Files (15)

| File | Sprint | Description |
|------|--------|-------------|
| `backend/app/api/investigation.py` | 1 | Investigation queue + review queue endpoints |
| `backend/app/schemas/investigation.py` | 1 | Queue request/response schemas |
| `backend/app/services/ranking.py` | 1 | Ranking algorithm (enhanced in Sprint 7) |
| `backend/alembic/versions/xxx_add_investigation_status.py` | 1 | Status columns migration |
| `backend/alembic/versions/xxx_add_reviewer_id.py` | 4 | Reviewer ID migration |
| `backend/alembic/versions/xxx_add_proofs_table.py` | 5 | Proofs table migration |
| `backend/app/api/proof.py` | 5 | Proof CRUD + generation endpoints |
| `backend/app/models/proof.py` | 5 | Proof database model |
| `backend/app/services/narrative.py` | 5 | LLM narrative generation |
| `backend/app/schemas/proof.py` | 5 | Proof schemas |
| `backend/app/services/feedback_analytics.py` | 7 | Feedback computation |
| `backend/app/api/admin.py` | 7 | Admin metrics endpoint |
| `backend/app/schemas/admin.py` | 7 | Admin schemas |
| `backend/app/api/correlation.py` | 8 | Cross-job correlation endpoint |
| `backend/app/services/correlation.py` | 8 | Correlation search service |
| `backend/app/schemas/correlation.py` | 8 | Correlation schemas |

## New Frontend Files (7)

| File | Sprint | Description |
|------|--------|-------------|
| `frontend/src/pages/InvestigationQueuePage.tsx` | 1 | Unified triage queue (enhanced in Sprints 2, 7) |
| `frontend/src/components/EvidenceDrawer.tsx` | 2 | Expandable evidence panel |
| `frontend/src/pages/ComparePage.tsx` | 3 | Before/After comparison workspace |
| `frontend/src/components/ReviewNotesPanel.tsx` | 4 | HITL review notes |
| `frontend/src/pages/ProofBuilderPage.tsx` | 5 | Case narrative builder |
| `frontend/src/pages/AdminFeedbackPage.tsx` | 7 | Feedback analytics dashboard |
| `frontend/src/components/SeenBeforePanel.tsx` | 8 | Cross-job prior occurrence panel |
| `frontend/src/components/RelatedJobsSidebar.tsx` | 8 | Related jobs sidebar |

## New Test Files (12)

| File | Sprint | Description |
|------|--------|-------------|
| `tests/unit/test_ranking.py` | 1 | Ranking algorithm unit tests |
| `tests/integration/test_investigation_api.py` | 1 | Queue API integration tests |
| `frontend/tests/e2e/investigation-queue.spec.ts` | 1 | Queue e2e tests |
| `tests/integration/test_temporal_api.py` | 3 | Temporal API tests |
| `frontend/tests/e2e/compare.spec.ts` | 3 | Compare page e2e tests |
| `tests/unit/test_hitl_gates.py` | 4 | HITL gate unit tests |
| `tests/integration/test_review_workflow.py` | 4 | Review workflow integration tests |
| `frontend/tests/e2e/review-workflow.spec.ts` | 4 | Review e2e tests |
| `tests/unit/test_narrative.py` | 5 | Narrative generation unit tests |
| `tests/integration/test_proof_api.py` | 5 | Proof API integration tests |
| `tests/integration/test_partial_results.py` | 6 | Partial results integration tests |
| `frontend/tests/e2e/partial-results.spec.ts` | 6 | Partial results e2e tests |
| `tests/unit/test_feedback_analytics.py` | 7 | Feedback analytics unit tests |
| `tests/integration/test_feedback_ranking.py` | 7 | Feedback ranking integration tests |
| `tests/unit/test_correlation.py` | 8 | Correlation unit tests |
| `tests/integration/test_correlation_api.py` | 8 | Correlation API integration tests |

## Modified Existing Files (12)

| File | Sprint(s) | Changes |
|------|-----------|---------|
| `backend/app/models/finding.py` | 1, 4 | Add `analyst_status`, `analyst_notes`, `reviewed_at`, `reviewer_id` |
| `backend/app/models/alert.py` | 1, 4 | Add `analyst_status`, `analyst_notes`, `reviewed_at`, `reviewer_id` |
| `backend/app/models/theory.py` | 1, 4 | Add `analyst_status`, `analyst_notes`, `reviewed_at`, `reviewer_id` |
| `backend/app/api/__init__.py` | 1, 5, 7, 8 | Register new routers |
| `backend/app/api/temporal.py` | 3 | Enhanced delta response, export endpoint |
| `backend/app/schemas/temporal.py` | 3 | Add phase_summary, severity_shift, containment_indicators |
| `backend/app/api/findings.py` | 4 | Confirmation gates on export |
| `backend/app/pipeline/orchestrator.py` | 6 | Publish partial results after each stage |
| `backend/app/api/jobs.py` | 6 | Partial results endpoint, new SSE events |
| `frontend/src/App.tsx` | 1, 3, 5, 7 | Add routes for new pages |
| `frontend/src/pages/JobDetailPage.tsx` | 1, 3, 5, 6, 8 | Add tabs, progress stepper, related sidebar |
| `frontend/src/hooks/useJobEvents.ts` | 6 | Handle new SSE event types |
| `frontend/src/pages/FindingDetailPage.tsx` | 4, 8 | Confirmation gate UI, SeenBeforePanel |
| `frontend/src/pages/AlertDetailPage.tsx` | 8 | SeenBeforePanel |
| `frontend/src/components/ToastProvider.tsx` | 6 | Early alert toasts |

---

# TIMELINE SUMMARY

```
Week  1–2:  Sprint 1  — Investigation Queue Foundation        ┐
Week  3–4:  Sprint 2  — Investigation Queue v2                ┘ R1: feature/investigation-queue
            ▸ Test, validate, merge to main, package

Week  5–6:  Sprint 3  — Before/After Comparison Workspace     ┐
Week  7–8:  Sprint 4  — HITL Review Workflow                  ┘ R2: feature/temporal-hitl
            ▸ Test, validate, merge to main, package

Week  9–10: Sprint 5  — Draft Case Narrative / Proof Builder  ┐
Week 11–12: Sprint 6  — Early Partial Results                 ┘ R3: feature/proof-partial
            ▸ Test, validate, merge to main, package

Week 13–14: Sprint 7  — Feedback-Driven Ranking               ┐
Week 15–16: Sprint 8  — Cross-Job Correlation UX              ┘ R4: feature/feedback-correlation
            ▸ Test, validate, merge to main, final package
```

**Total duration:** 16 weeks (4 months)
**Total releases:** 4 independently deployable packages
**Total new files:** ~34 (15 backend + 8 frontend + 16 test)
**Total modified files:** ~15

---

*This plan respects the AIPAM Architectural Constitution: deterministic execution, air-gapped deployment, HITL authority, and offline packaging constraints.*