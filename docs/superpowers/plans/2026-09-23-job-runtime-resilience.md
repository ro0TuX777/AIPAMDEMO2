# Job Runtime Resilience and Pipeline Throughput Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AIPAM analysis jobs terminate truthfully after worker failures or cancellation, keep chat synchronized with job state, and reduce large-PCAP processing time without introducing concurrent SQLite writers.

**Architecture:** The `jobs` row owns a task identity, fencing token, database heartbeat, cancellation state, and accepted immutable run manifest. The worker claims and finalizes through compare-and-swap operations, every task-owned commit uses a fenced SQLAlchemy session, and a supervisor reconciles or terminates stale executions. Pipeline throughput improves through streamed correlation, evidence-scoped theory generation, and a bounded two-worker filesystem DAG whose database writes remain on the orchestrator thread.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy/Alembic, Celery/Redis, SQLite WAL, React 18, TypeScript, TanStack Query, Docker Compose, pytest, Node test runner, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-23-job-runtime-resilience-design.md`

## Global Constraints

- Keep Celery whole-job concurrency at `1` while the application database is SQLite.
- Use database UTC time for ownership and lease comparisons; Redis and Celery state are diagnostic, not authoritative.
- Use a `15` second heartbeat, `120` second stale threshold, `30` second cooperative-cancel target, persisted force/deadline timestamps at `45`/`60` seconds, a `2` second cancellation-supervisor poll, and a `30` second undispatched grace period.
- Use a `21,300` second Celery soft limit, `21,600` second hard limit, and `25,200` second Redis visibility timeout; startup validation must reject any visibility timeout less than or equal to the hard limit.
- Default `AIPAM_SENSOR_PARALLELISM` to `2`, clamp it to `1..2`, and keep every SQLAlchemy write on the orchestrator thread.
- Do not automatically replay or take over an interrupted execution. Reconciliation fails it closed; a user rerun creates a new job.
- A duplicate, canceled, superseded, or delayed Celery delivery must acknowledge without invoking the pipeline.
- Every run writes immutable output under its own token. Readers use `accepted_run_manifest_json`; they never scan unaccepted run directories.
- Baseline and MNEMOS chat are available only for `completed` and `completed_with_errors` jobs.
- Legacy unversioned SQLite adoption must operate on a backup-derived candidate, fail closed on unknown fingerprints, and never mutate the source before candidate validation.
- Live rollback uses the verified whole-database backup; the schema-convergence revision is not a supported live downgrade because dropping its formerly metadata-only tables would destroy data.
- Deterministic artifact order and the analysis `bundle_sha256` defined in Task 7 must remain stable for identical inputs despite concurrent sensor completion.
- No API token, MNEMOS token, credentials, PII, or raw broker exception may enter logs, migration receipts, handoffs, or public API errors.
- Existing baseline evidence: `569` unit tests pass; five `tests/unit/test_kb_library.py` tests fail because no embedding model is selected. Treat those five as pre-existing unless this branch changes embedding selection.
- The host `node` command currently resolves to a missing executable. Run frontend build and browser checks in Docker until host Node is repaired.
- The repository's DAWN harnesses require the external sibling checkout `E:\DAWN`, which is absent during planning. A missing DAWN checkout is an explicit release-verification blocker: record it, do not fabricate a `PASS`, and do not substitute a smoke test.

## Review Focus

- Broker accepts a task and `apply_async()` still raises: Task 4 must prove a worker claim wins and no second execution starts.
- A handler ignores cooperative cancellation: Task 4 must prove escalation kills the Celery child and reaps run-labelled children by 60 seconds.
- Theory candidates reorder after scoring changes: Task 6 must prove semantic keys preserve IDs and analyst review fields.
- One alert signature spans multiple correlation batches: Task 7 must prove the synthesized finding is identical to the unbatched result.
- An unversioned database contains populated partial chat-comparison tables: Task 9 must prove adoption refuses without changing the source checksum.

---

### Task 1: Add the durable job-runtime state machine

**Files:**
- Modify: `backend/alembic/versions/e2a9f4b71d83_enhance_temporal_correlations.py`
- Create: `backend/alembic/versions/7f2c9a4e8b11_converge_runtime_schema.py`
- Create: `backend/alembic/versions/8b6f4d2a1c90_add_job_runtime_state.py`
- Create: `backend/app/services/job_runtime.py`
- Create: `tests/unit/test_job_runtime.py`
- Create: `backend/app/tests/test_schema_migration_chain.py`
- Modify: `backend/app/models/job.py`
- Modify: `backend/app/models/__init__.py`
- Modify: `backend/app/schemas/common.py`
- Modify: `backend/app/schemas/job.py`
- Modify: `backend/app/domain_models.py`
- Modify: `openapi.yaml`

**Interfaces:**
- Repairs fresh Alembic creation at `e2a9f4b71d83` and makes `7f2c9a4e8b11` the explicit schema-convergence parent of the runtime migration; production startup no longer depends on metadata `create_all()` to supply missing structures.
- Produces: `RunHandle(job_id, task_id, run_token, execution_attempt)`, `ExecutorIdentity(worker_node, worker_container_id, executor_pid, executor_pid_start_ticks, executor_boot_id)`, `ClaimDisposition`, `assign_task`, `mark_dispatched`, `mark_dispatch_failed`, `claim_job`, `register_executor`, `heartbeat_job`, `request_cancel`, `finalize_owned_job`, and `reconcile_stale_jobs` in `backend.app.services.job_runtime`.
- Produces: public active status `canceling` and job response fields `cancel_requested_at` and `heartbeat_at`.

- [ ] **Step 1: Write migration and model-shape tests**

Add a file-backed SQLite fixture and assertions like:

```python
def test_runtime_migration_adds_nullable_ownership_and_manifest_columns(alembic_db):
    upgrade_to_head(alembic_db)
    columns = column_names(alembic_db, "jobs")
    assert {
        "celery_task_id", "execution_attempt", "run_token", "worker_id",
        "worker_container_id", "executor_pid", "executor_pid_start_ticks", "executor_boot_id",
        "heartbeat_at", "dispatched_at", "cancel_requested_at",
        "cancel_force_at", "cancel_deadline_at", "cancel_escalation_token",
        "cancel_escalation_started_at",
        "artifact_layout_version", "accepted_run_manifest_json",
    } <= columns


def test_empty_database_upgrades_to_head_with_runtime_metadata_parity(empty_db):
    upgrade_to_head(empty_db)
    assert_runtime_metadata_matches_database(empty_db)


def test_canceling_is_active_not_terminal():
    assert JobStatus.canceling.value == "canceling"
    assert "canceling" not in TERMINAL_JOB_STATUSES
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run: `python -m pytest tests/unit/test_job_runtime.py backend/app/tests/test_schema_migration_chain.py -q`

Expected: FAIL because a fresh chain currently reaches `e2a9f4b71d83` before `temporal_correlations` exists, metadata-only tables/columns are absent from Alembic, and the runtime state does not exist.

- [ ] **Step 3: Add runtime columns and backward-compatible schemas**

Repair the historical `e2a9f4b71d83` fresh-database path by creating the original `temporal_correlations` shape, its two implicit single-column indexes, and four named indexes when the table is absent before adding its seven enhancement columns; retain its existing-table behavior and symmetric downgrade. Add convergence revision `7f2c9a4e8b11` after `7a4d8e2c9b10`. For each of the eight metadata-only tables `context_annotations`, `incident_slices`, `job_log_sources`, `normalized_events`, `proofs`, `reports`, `theories`, and `proof_items`, create it only when absent; when present, validate its supported shape and add/rebuild only the explicitly declared missing objects. Apply the same inspect-before-change rule while ensuring `temporal_correlations.log_source_filename` and `log_summary`; analyst review columns plus `idx_alerts_analyst_status` on `alerts`; `filename` on `files`; confidence, timestamp, source/destination IP, evidence/corroboration, analyst review fields, `idx_findings_analyst_status`, and `idx_findings_evidence_status` on `findings`; `source_type`, `exercise_id`, and `source_manifest_json` on `jobs`; and `content_sha256` plus `idx_kb_doc_sha` on `kb_documents`. Backfill required values with `jobs.source_type='pcap'`, `findings.confidence=0.0`, `findings.evidence_status='observed'`, and `findings.corroboration_score=0.0` before nullability enforcement. Rebuild `hosts` uniqueness from `(job_id, ip)` to `(job_id, ip, pcap_label)`. Tests cover a clean versioned database where the eight tables are absent and both allowlisted create-all schemas where they already exist, then compare the explicit runtime metadata allowlist to SQLite introspection.

Migration `8b6f4d2a1c90` must revise `7f2c9a4e8b11` and add:

```python
op.add_column("jobs", sa.Column("celery_task_id", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("execution_attempt", sa.Integer(), nullable=False, server_default="0"))
op.add_column("jobs", sa.Column("run_token", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("worker_id", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("worker_container_id", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("executor_pid", sa.Integer(), nullable=True))
op.add_column("jobs", sa.Column("executor_pid_start_ticks", sa.BigInteger(), nullable=True))
op.add_column("jobs", sa.Column("executor_boot_id", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("heartbeat_at", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("dispatched_at", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("cancel_requested_at", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("cancel_force_at", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("cancel_deadline_at", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("cancel_escalation_token", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("cancel_escalation_started_at", sa.String(), nullable=True))
op.add_column("jobs", sa.Column("artifact_layout_version", sa.Integer(), nullable=False, server_default="1"))
op.add_column("jobs", sa.Column("accepted_run_manifest_json", sa.Text(), nullable=True))
op.create_index("idx_jobs_celery_task_id", "jobs", ["celery_task_id"], unique=False)
```

Backfill pre-migration jobs with artifact layout `1`; set the database server default to `2` but keep the application model default at `1` until Task 3 installs the worker acceptance boundary. Expose `heartbeat_at` and `cancel_requested_at` in `JobListItem`; keep layout, task IDs, tokens, executor identity, and manifests private. Implement a fresh empty-database upgrade and a populated SQLite migration round trip from `7a4d8e2c9b10 -> 7f2c9a4e8b11 -> 8b6f4d2a1c90 -> 7f2c9a4e8b11 -> 8b6f4d2a1c90`, proving pre-existing job fields survive.

- [ ] **Step 4: Write failing compare-and-swap lifecycle tests**

Cover these exact transitions:

```python
def test_only_matching_queued_task_can_claim(db, queued_job):
    assign_task(db, queued_job.job_id, "task-a", now=DB_NOW)
    assert claim_job(db, queued_job.job_id, "task-b", "token-b", worker_id="w1").disposition == ClaimDisposition.superseded
    claimed = claim_job(db, queued_job.job_id, "task-a", "token-a", worker_id="w1")
    assert claimed.disposition == ClaimDisposition.claimed
    assert claim_job(db, queued_job.job_id, "task-a", "token-c", worker_id="w2").disposition == ClaimDisposition.busy


def test_running_cancel_becomes_canceling_and_old_owner_cannot_complete(db, running_job):
    request_cancel(db, running_job.job_id)
    assert db.get(Job, running_job.job_id).status == "canceling"
    assert finalize_owned_job(db, handle=running_job.handle, outcome="completed") is False
```

Also test queued cancel, repeated cancel, terminal cancel conflict, old token heartbeat, fresh/stale reconciliation, completed timestamp set once, and database-time lease comparison.

- [ ] **Step 5: Implement atomic lifecycle operations**

Use SQLAlchemy `update()` predicates and require `rowcount == 1`; do not emulate locking with `SELECT FOR UPDATE` on SQLite. The public signatures are:

Implement these exact callable contracts:

- `assign_task(db: Session, job_id: str, task_id: str) -> int`
- `mark_dispatched(db: Session, job_id: str, task_id: str) -> bool`
- `mark_dispatch_failed(db: Session, job_id: str, task_id: str, public_error: str) -> bool`
- `claim_job(db: Session, job_id: str, task_id: str, run_token: str, worker_id: str) -> ClaimResult`
- `register_executor(db: Session, handle: RunHandle, identity: ExecutorIdentity) -> bool`
- `heartbeat_job(db: Session, handle: RunHandle) -> HeartbeatDisposition`
- `request_cancel(db: Session, job_id: str) -> CancelResult`
- `claim_cancel_escalation(db: Session, job_id: str, escalation_token: str, *, lease_seconds: int) -> EscalationClaim`
- `complete_cancel_escalation(db: Session, handle: RunHandle, escalation_token: str) -> bool`
- `finalize_owned_job(db: Session, handle: RunHandle, outcome: JobOutcome, *, error_summary: str | None = None, metrics_json: str | None = None, accepted_manifest_json: str | None = None) -> bool`
- `reconcile_stale_jobs(db: Session, *, stale_seconds: int, undispatched_grace_seconds: int) -> ReconcileStats`

Use SQLite `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')` in updates. `request_cancel()` sets `cancel_force_at` and `cancel_deadline_at` from database time. Escalation claim/reclaim uses a 15-second lease and compare-and-swap over canceling status, task ID, run token, current lease token/time, and force time. Executor registration, cancellation completion, and clearing require the matching task ID/run token; escalation completion also requires its token. Reconciliation changes stale `running` to `failed`, stale `canceling` to `canceled`, and old undispatched `queued` to `failed`; it never reclaims work.

- [ ] **Step 6: Run lifecycle and schema tests**

Run: `python -m pytest tests/unit/test_job_runtime.py tests/unit/test_job_lifecycle.py tests/unit/test_models.py backend/app/tests/test_schema_migration_chain.py -q`

Expected: PASS, including race losers returning a disposition without overwriting the winner.

- [ ] **Step 7: Commit the runtime state foundation**

```powershell
git add backend/alembic/versions/e2a9f4b71d83_enhance_temporal_correlations.py backend/alembic/versions/7f2c9a4e8b11_converge_runtime_schema.py backend/alembic/versions/8b6f4d2a1c90_add_job_runtime_state.py backend/app/models/job.py backend/app/models/__init__.py backend/app/schemas/common.py backend/app/schemas/job.py backend/app/domain_models.py backend/app/services/job_runtime.py tests/unit/test_job_runtime.py backend/app/tests/test_schema_migration_chain.py openapi.yaml
git commit -m "feat: add durable job runtime state"
```

### Task 2: Isolate run output and gate artifact visibility

**Files:**
- Create: `backend/app/pipeline/run_artifacts.py`
- Create: `tests/unit/test_run_artifacts.py`
- Modify: `backend/app/pipeline/job_dir.py`
- Modify: `backend/app/api/alerts.py`
- Modify: `backend/app/api/artifacts.py`
- Modify: `backend/app/api/findings.py`
- Modify: `backend/app/api/jobs.py`
- Modify: `backend/app/cli.py`
- Modify: `backend/app/services/cleanup.py`
- Modify: `backend/app/services/job_service.py`
- Modify: `backend/app/tests/test_api_jobs.py`
- Modify: `backend/app/api/binary.py`
- Modify: `backend/app/normalize/network_events.py`
- Modify: `backend/app/pipeline/telemetry_pipeline.py`
- Modify: `backend/app/bluescrub/service.py`
- Modify: `backend/app/bluescrub/scanners/sbom.py`
- Modify: `tests/unit/test_phase3_api.py`
- Modify: `backend/app/tests/test_phase3_correlation.py`
- Modify: `backend/app/tests/test_phase10_hardening.py`

**Interfaces:**
- Consumes: private `Job.accepted_run_manifest_json` from Task 1.
- Produces: `RunManifestEntry(run_token, phase_label, bundle_sha256=None)`, `create_run_output_dir`, `build_accepted_manifest`, `resolve_accepted_run_dirs`, `resolve_published_artifact_dir`, and `cleanup_unaccepted_runs`; Task 7 populates the optional digest.
- Establishes two path contracts: an owned `run_output_dir` passed only inside the active pipeline, and `resolve_accepted_run_dirs()` used only by external or post-finalization readers.

- [ ] **Step 1: Write failing immutable-run and manifest tests**

```python
def test_readers_resolve_only_manifest_entries(tmp_path, job):
    accepted = create_run_output_dir(tmp_path, job.job_id, "run-a")
    abandoned = create_run_output_dir(tmp_path, job.job_id, "run-b")
    (accepted / "metrics" / "job_metrics.json").write_text("{}")
    (abandoned / "metrics" / "job_metrics.json").write_text('{"bad":true}')
    job.accepted_run_manifest_json = json.dumps([{"run_token": "run-a", "phase_label": None}])
    assert resolve_accepted_run_dirs(job, tmp_path) == [accepted]


def test_phase_acceptance_replaces_only_same_phase(job):
    current = [{"run_token": "base", "phase_label": None}, {"run_token": "old-after", "phase_label": "after"}]
    assert build_accepted_manifest(current, "new-after", "after") == [
        {"run_token": "base", "phase_label": None},
        {"run_token": "new-after", "phase_label": "after"},
    ]
```

Also assert path traversal tokens are rejected; terminal layout-1 jobs with a null manifest resolve only the historical stable output paths read-only; active layout-1 jobs and every layout-2 job with a missing/malformed manifest fail closed; and cleanup never removes accepted tokens.

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `python -m pytest tests/unit/test_run_artifacts.py -q`

Expected: FAIL because run-scoped paths and manifest resolution do not exist.

- [ ] **Step 3: Implement immutable run directories and manifest helpers**

Use this layout:

```text
/jobs/<job_id>/input/                  # stable uploaded inputs
/jobs/<job_id>/.runs/<run_token>/      # immutable execution output
  sensors/
  artifacts/                          # execution-owned evidence
  metrics/
  logs/
/jobs/<job_id>/published/<artifact_id>/  # immutable post-terminal API exports
```

Validate UUID tokens before joining paths. `build_accepted_manifest()` returns canonical compact JSON ordering: base entry first, then phase entries ordered by label. It does not rename directories. Only `finalize_owned_job()` may store the returned JSON. Active pipeline functions receive their owned `run_output_dir` directly and must never call the accepted-run resolver before finalization.

Keep this commit deployable: refactor active pipeline signatures to separate `input_root` and `run_output_dir`, but continue passing the historical stable root for layout-1 jobs. The worker does not create layout-2 jobs or switch output into `.runs` until Task 3 adds claim/finalize acceptance in the same commit.

- [ ] **Step 4: Route output readers through the manifest resolver**

Inventory and replace every external read of stable `sensors`, execution `artifacts`, `metrics`, logs, diagnostics, file lookup, and ZIP/CLI bundle input with `resolve_accepted_run_dirs()`. Cover `jobs.get_job()` diagnostics, `download_extracted_file()` with `File.pcap_label`, `job_service.create_export_zip()`, `cli.cmd_support_bundle()`, and `cli.cmd_perf_gate()`. Keep `/input`, stream endpoints, Arkime/Security Onion import state, and user-uploaded source material at the stable job root. Where multiple phase directories exist, merge in manifest order and let the newest matching phase entry win; archive names include phase/run disambiguation.

Split all active-pipeline interfaces into explicit stable `input_root` and owned `run_output_dir` arguments. Update orchestrator variants, sensor runner/handlers, correlation, network normalization, telemetry diagnostics, BlueScrub service, and SBOM writing so outputs never land in the stable root. API-created evidence packages go under stable `/published/<artifact_id>/` only for terminal jobs, use immutable per-artifact filenames, and may be built solely from the database plus accepted run directories. Binary uploads use a distinct stable API-artifact subtree and reject active jobs. None of these API-owned artifacts enter the execution manifest.

Seed an abandoned `.runs/<token>` tree plus stable-root decoys for a layout-2 job and assert that diagnostics, extracted-file download, job ZIP export, alerts/findings artifacts, support bundle, performance gate, CLI evidence export, and `job_service` export cannot name or return any abandoned bytes. Assert malformed/missing layout-2 manifests, traversal, and symlink escapes fail closed. Separately create two evidence packages and prove their immutable downloads differ and survive later accepted-manifest changes. Preserve the explicit terminal layout-1 compatibility path and stable-root behavior for stream, Arkime, and binary-upload tests.

- [ ] **Step 5: Run artifact and existing path tests**

Run: `python -m pytest tests/unit/test_run_artifacts.py tests/unit/test_phase2_pipeline.py tests/unit/test_phase3_api.py backend/app/tests/test_phase3_correlation.py tests/unit/test_streams_api.py tests/unit/test_phase7_ops.py backend/app/tests/test_api_jobs.py backend/app/tests/test_phase10_hardening.py -q`

Expected: PASS; unaccepted output cannot be returned by an API or CLI evidence path.

- [ ] **Step 6: Commit artifact isolation**

```powershell
git add backend/app/pipeline/run_artifacts.py backend/app/pipeline/job_dir.py backend/app/pipeline/telemetry_pipeline.py backend/app/pipeline/orchestrator.py backend/app/pipeline/sensor_runner.py backend/app/pipeline/sensor_handlers.py backend/app/normalize/correlate.py backend/app/normalize/network_events.py backend/app/bluescrub/service.py backend/app/bluescrub/scanners/sbom.py backend/app/api/alerts.py backend/app/api/artifacts.py backend/app/api/findings.py backend/app/api/jobs.py backend/app/api/binary.py backend/app/cli.py backend/app/services/cleanup.py backend/app/services/job_service.py backend/app/tests/test_api_jobs.py backend/app/tests/test_phase10_hardening.py backend/app/tests/test_phase3_correlation.py tests/unit/test_run_artifacts.py tests/unit/test_phase2_pipeline.py tests/unit/test_phase3_api.py
git commit -m "feat: isolate and gate analysis run artifacts"
```

### Task 3: Make the orchestrator return one truthful outcome

**Files:**
- Create: `backend/app/pipeline/outcomes.py`
- Create: `tests/unit/test_pipeline_outcomes.py`
- Modify: `backend/app/pipeline/orchestrator.py`
- Modify: `backend/app/worker.py`
- Modify: `backend/app/models/job.py`
- Modify: `backend/app/services/job_creation.py`
- Modify: `backend/app/services/job_imports.py`
- Modify: `backend/app/services/job_lifecycle.py`
- Modify: `backend/app/runtime_supervisor.py`
- Modify: `tests/unit/test_phase2_pipeline.py`
- Modify: `backend/app/tests/test_bluescrub_pipeline.py`

**Interfaces:**
- Produces: `PipelineOutcome(status, metrics, required_failures, optional_failures, accepted_manifest_json)`.
- Produces an operational worker boundary `execute_job(job_id, task_id, pcap_label)` that claims through Task 1, passes an owned `run_output_dir`, finalizes through compare-and-swap, and uses a fresh session after rollback for every exception.
- Produces: Celery task `aipam.distill_job(job_id)` for post-terminal frontier distillation.

- [ ] **Step 1: Write failing outcome-policy tests**

```python
def test_required_stage_failure_is_failed():
    outcome = derive_outcome(required=[failure("correlate")], optional=[])
    assert outcome.status == "failed"


def test_optional_sensor_failure_is_completed_with_errors():
    outcome = derive_outcome(required=[], optional=[failure("beaconing")])
    assert outcome.status == "completed_with_errors"


def test_successful_pipeline_does_not_write_job_status(orchestrator_db, monkeypatch):
    outcome = run_pipeline(**successful_pipeline_args(orchestrator_db, monkeypatch))
    assert outcome.status == "completed"
    assert orchestrator_db.get(Job, JOB_ID).status == "running"


def test_worker_claims_and_finalizes_returned_outcome(worker_harness):
    worker_harness.pipeline.return_value = completed_outcome()
    worker_harness.run()
    assert worker_harness.fresh_job().status == "completed"
```

Cover binary and BlueScrub pipelines, correlation failure, theory failure, annotations failure, quota failure, duplicate/busy deliveries, and canceled/ownership exceptions propagating without conversion to partial success. Inject an `IntegrityError` that makes the pipeline session rollback-required and prove a fresh session sets `failed` plus `completed_at`. Assert every production create/import/rerun path creates layout 2, while migrated layout-1 terminal jobs remain readable.

- [ ] **Step 2: Run outcome tests and confirm current behavior fails**

Run: `python -m pytest tests/unit/test_pipeline_outcomes.py tests/unit/test_phase2_pipeline.py backend/app/tests/test_bluescrub_pipeline.py -q`

Expected: FAIL because the orchestrator writes status directly and several caught failures still lead to plain completion.

- [ ] **Step 3: Introduce `PipelineOutcome` and central failure classification**

```python
@dataclass(frozen=True)
class PipelineOutcome:
    status: Literal["completed", "completed_with_errors", "failed"]
    metrics: dict[str, Any]
    required_failures: Sequence[StageFailure]
    optional_failures: Sequence[StageFailure]
    accepted_manifest_json: str
```

Remove job-level `running` and terminal writes plus `job.complete` emission from `run_pipeline`; the worker boundary owns those transitions. Implement `execute_job()` in the same step: claim with the Celery request ID, create and pass the owned `run_output_dir`, run the pipeline, finalize the returned outcome and accepted manifest, and emit `job.complete` only after a successful terminal commit. Switch the Job model default and every production job-creation/import/rerun path to `artifact_layout_version=2` in this same commit. On any exception, rollback and close the pipeline session, then use a fresh session: matching `canceling` finalizes `canceled`; a lost task/token performs private-run cleanup without overwriting the winner; every other matching owner finalizes `failed`; then re-raise unexpected exceptions. Required core stages are input validation, correlation persistence, and final manifest construction. Sensor/enrichment failures are optional unless their registry entry declares them required.

- [ ] **Step 4: Move frontier distillation behind terminal analysis**

Remove synchronous `asyncio.run(distill_v2(db_session_factory=get_session_factory(), job_id=job_id, teacher=teacher))` from the orchestrator. Add `aipam.distill_job`, dispatched only after `execute_job()` commits a successful terminal outcome. Distillation records its own result in logs/metrics and never rewrites job status.

- [ ] **Step 5: Run pipeline outcome tests**

Run: `python -m pytest tests/unit/test_pipeline_outcomes.py tests/unit/test_phase2_pipeline.py backend/app/tests/test_bluescrub_pipeline.py -q`

Expected: PASS; one returned outcome describes every caught stage/sensor failure, the worker claim/finalize path is operational at this commit, a poisoned session cannot strand a job, and distillation is absent from core runtime.

- [ ] **Step 6: Commit the outcome contract**

```powershell
git add backend/app/pipeline/outcomes.py backend/app/pipeline/orchestrator.py backend/app/worker.py backend/app/models/job.py backend/app/services/job_creation.py backend/app/services/job_imports.py backend/app/services/job_lifecycle.py tests/unit/test_pipeline_outcomes.py tests/unit/test_phase2_pipeline.py backend/app/tests/test_bluescrub_pipeline.py
git commit -m "refactor: centralize pipeline outcome policy"
```

### Task 4: Enforce worker ownership, heartbeat, recovery, and cancellation

**Files:**
- Create: `backend/app/pipeline/runtime_control.py`
- Create: `backend/app/pipeline/sensor_process.py`
- Create: `backend/app/runtime_supervisor.py`
- Create: `tests/unit/test_worker_job_runtime.py`
- Create: `tests/unit/test_job_dispatch.py`
- Modify: `backend/app/config_v2.py`
- Modify: `backend/app/database_v2.py`
- Modify: `backend/app/worker.py`
- Modify: `backend/app/services/job_dispatch.py`
- Modify: `backend/app/services/job_lifecycle.py`
- Modify: `backend/app/pipeline/recovery.py`
- Modify: `backend/app/pipeline/orchestrator.py`
- Modify: `backend/app/pipeline/sensor_runner.py`
- Modify: `backend/app/pipeline/sensor_handlers.py`
- Modify: `backend/app/anomaly_detector.py`
- Modify: `backend/app/suricata_rules.py`
- Modify: `backend/app/bluescrub/isolation/runner.py`
- Modify: `backend/app/bluescrub/isolation/limits.py`
- Modify: `backend/app/api/jobs.py`
- Modify: `backend/app/services/job_service.py`
- Modify: `backend/app/tests/test_capture_stage_resilience.py`
- Modify: `backend/app/tests/test_sensor_runner.py`
- Modify: `backend/app/tests/test_capa_sensor.py`
- Modify: `backend/app/tests/test_yara_scanning.py`
- Modify: `backend/app/tests/test_triage_correctness.py`
- Modify: `backend/app/tests/test_settings_runtime.py`
- Modify: `docker-compose.yml`
- Modify: `.env.example`

**Interfaces:**
- Consumes: Task 1 runtime transitions, Task 2 run directories, and Task 3 `PipelineOutcome`.
- Produces: `FencedSession`, `get_fenced_session_factory(handle)`, `ExecutionControl`, `ExecutorIdentity`, the Task 3 `execute_job(job_id, task_id, pcap_label)` boundary with fencing/supervision added, and the `runtime-supervisor` Compose service.

- [ ] **Step 1: Write failing dispatch-race tests**

```python
def test_task_id_is_persisted_before_publish(db, queued_job):
    seen = {}
    def sender(*, task_id, args):
        seen["stored"] = db.get(Job, queued_job.job_id).celery_task_id
    dispatch_job(db, queued_job.job_id, sender=sender, task_id_factory=lambda: "task-a")
    assert seen["stored"] == "task-a"


def test_publish_exception_cannot_overwrite_fast_worker_claim(db, queued_job):
    def accepted_then_raised(*, task_id, args):
        claim_in_fresh_session(queued_job.job_id, task_id)
        raise ConnectionError("confirmation lost")
    result = dispatch_job(db, queued_job.job_id, sender=accepted_then_raised,
                          task_id_factory=lambda: "task-a")
    assert result.status == "running"
```

Also cover definite broker failure, API-process-loss reconciliation, delayed delivery after failure, normal/phase dispatch parity, and public errors excluding Redis details.

- [ ] **Step 2: Implement identified dispatch and claim flow**

Use `apply_async(args=[job_id, pcap_label] if pcap_label is not None else [job_id], task_id=task_id)`. `mark_dispatched` accepts `queued` or matching `running`. Publication-error failure requires matching task ID, `queued`, and null `dispatched_at`. Update create/import/rerun/reanalyze routes to pass a session and return HTTP `503` with only stable code `JOB_DISPATCH_FAILED` plus `job_id` when failure wins.

- [ ] **Step 3: Write failing fencing and exception-finalization tests**

```python
def test_internal_commit_is_fenced(fenced_db, handle):
    revoke_ownership(handle)
    fenced_db.add(make_finding(job_id=handle.job_id, finding_id="F-fenced"))
    with pytest.raises(JobOwnershipLost):
        fenced_db.commit()
    assert count_findings(handle.job_id) == 0


def test_flush_failure_terminalizes_with_fresh_session(worker_harness):
    worker_harness.pipeline.side_effect = IntegrityError("insert", {}, Exception("duplicate"))
    with pytest.raises(IntegrityError):
        worker_harness.run()
    job = worker_harness.fresh_job()
    assert job.status == "failed"
    assert job.completed_at is not None


def test_cancel_before_internal_commit_finishes_canceled(worker_harness):
    worker_harness.request_cancel_immediately_before_commit()
    worker_harness.run()
    assert worker_harness.fresh_job().status == "canceled"
```

Test duplicate/busy delivery, canceled delivery, worker loss, heartbeat busy retry, stale reconciliation, PID-reuse identity rejection, stale-token cleanup refusal, and exactly one post-commit `job.complete` event. Add settings tests for defaults, malformed values, all time-limit boundaries, and startup refusal when `visibility_timeout <= task_time_limit`.

- [ ] **Step 4: Implement `FencedSession` and worker boundary**

Register a `before_commit` listener on the dedicated subclass. On the transaction connection, classify the matching task ID/run token as `owned` for `running`, `cancel_requested` for `canceling`, or `lost` otherwise. Continue only for `owned`, raise `JobCancellationRequested` for `cancel_requested`, and raise `JobOwnershipLost` for `lost`. Do not install it on API or supervisor sessions.

Before any pipeline work, the Celery pool child atomically persists `self.request.hostname`, the full worker container ID, its namespaced PID, Linux `/proc/<pid>/stat` field 22, and `/proc/sys/kernel/random/boot_id` through `register_executor()`. This exact Celery child owns the fenced database session and heartbeat. Configure `worker_max_tasks_per_child = 1` so the identity cannot be reused for a second task before delayed escalation runs.

`execute_job()` must:

```python
claim -> create run dir -> start ExecutionControl -> run_pipeline
      -> finalize_owned_job(outcome + accepted manifest)
      -> emit job.complete -> dispatch distillation when successful
except JobCancellationRequested: fresh-session finalize canceled
except JobOwnershipLost:
    rollback/close task session
    -> fresh-session finalize canceled only when status is canceling and task/token still match
    -> otherwise clean private run resources without overwriting the current owner
except Exception: rollback/close task session
    -> fresh-session finalize canceled when matching row is already canceling
    -> otherwise fresh-session finalize failed -> re-raise
finally: stop heartbeat and reap run-labelled children
```

- [ ] **Step 5: Write failing cooperative and escalated cancellation tests**

Use a real child process fixture and a deliberately unresponsive handler. Assert queued cancel is an immediate terminal no-op, running cancel becomes `canceling`, the cooperative child stops within 30 seconds, and unresponsive handler groups plus the exact Celery child are gone and the row is `canceled` by the persisted 60-second deadline. Include cancellation immediately before an internal commit, escalation lease contention/reclaim, a reused PID with different start ticks, a changed boot ID, a stale run token, an absent/recreated worker container, and a conflicting live identity. An absent recorded executor permits matching labelled-child cleanup and canceled finalization because it can no longer write; a different live PID/start/boot/container identity is never signalled and leaves the job fenced with an operator-visible escalation error.

- [ ] **Step 6: Thread `ExecutionControl` through blocking work**

Add checkpoints before/after every stage, in the `run_capture_tool` watchdog, between PCAPs/files/records, between correlation chunks, and between theory batches. Use one concrete cancellation channel: `<run_output_dir>/control/cancel.requested`, created atomically by `ExecutionControl` when its database heartbeat observes `canceling` and by the supervisor when it scans that row. `sensor_process.py` receives this path as a required argument; `SensorExecutionContext.checkpoint()` and bounded iterator loops poll file existence. `sensor_process.py` is the mandatory boundary for all seven registry handlers and starts a new process session/group; scheduler threads launch and supervise it rather than calling handler Python directly. Zeek, Suricata, CAPA, YARA, anomaly detection, parsing, and TI filesystem reads therefore remain killable. Factor the existing process-group primitives in `bluescrub/isolation/runner.py` and `limits.py` instead of creating a second signal implementation. Label any Docker containers with `aipam.job_id`, `aipam.run_token`, and `aipam.celery_task_id`. Atomically write each handler PID, start ticks, boot ID, PGID, and handler name to the private run control file before waiting; remove it only after `wait()` reaps that handler.

Implement and test this registry-wide isolation inventory; Task 8 cannot start until every row uses the stated boundary:

| Registry entry | Current blocking work | Required boundary/checkpoints |
|---|---|---|
| `zeek` | `run_capture_tool()` subprocess, 5,400s per PCAP | wrapper process group; total handler deadline; checkpoint between PCAPs; kill whole group |
| `suricata` | capture subprocess plus materialized `eve.json` | wrapper process group; total deadline; streamed records with checkpoints |
| `tls_enrich` | directory walk and synchronous JSONL parsing | wrapper process group; checkpoint per file and record batch |
| `beaconing` | materialization plus CPU-heavy `AnomalyDetector.analyze()` | wrapper process group; detector-loop checkpoints and total deadline |
| `file_triage` | `read_bytes()`, YARA compile, native `rules.match()` | wrapper process group; per-file checkpoints and total deadline |
| `capa` | repeated `subprocess.run(timeout=300)` | wrapper process group; checkpoint between candidates; overall 900s deadline |
| `ti_matcher` | mount traversal, `read_text()`, JSONL scans | wrapper process group; checkpoint per file/record batch; total 600s deadline |

The supervisor keeps its 15-second reconciliation/health heartbeat and a separate 2-second cancellation loop. At `cancel_force_at` (45 seconds), claim the persisted escalation lease, create the cancel file, stop submissions, send TERM to tracked handler groups and matching labelled containers, wait at most 3 seconds, then KILL/reap survivors. Resolve the full worker container ID and use `docker exec` to run a control helper inside it; re-read boot ID and `/proc/<pid>/stat`, require exact identity, enumerate descendants, terminate deepest-first, TERM the Celery child, wait at most 3 seconds, then KILL. Bound every Docker call/poll by the persisted `cancel_deadline_at`, reserve the final 3 seconds for compare-and-swap finalization/event emission, and test completion at or before 60 seconds under the matching/absent identity paths. If the recorded container/PID is absent, clean exact labelled resources and finalize canceled. If a different live identity occupies it, signal nothing, persist a stable escalation error, retain `canceling`, and alert for operator action.

- [ ] **Step 7: Add periodic runtime supervision and Celery limits**

Add settings with exact defaults from Global Constraints. `runtime_supervisor.py` reconciles every 15 seconds, polls cancellation deadlines every 2 seconds, and writes `/tmp/aipam-runtime-supervisor.heartbeat` after each successful reconciliation pass. Its `--health` mode exits nonzero when that file is older than 45 seconds. Configure:

```python
task_acks_late = True
task_reject_on_worker_lost = True
worker_prefetch_multiplier = 1
task_soft_time_limit = 21_300
task_time_limit = 21_600
broker_transport_options = {"visibility_timeout": 25_200}
worker_max_tasks_per_child = 1
```

Add a `runtime-supervisor` Compose service using the app image, shared `/data` and `/jobs` volumes, Redis configuration, and the Docker socket needed to reap run-labelled sensor containers. Run it with the same restricted root/Docker access already required by the worker and healthcheck `python -m backend.app.runtime_supervisor --health`. Keep the worker command `--concurrency=1`.

- [ ] **Step 8: Run runtime, route, and capture tests**

Run: `python -m pytest tests/unit/test_job_runtime.py tests/unit/test_job_dispatch.py tests/unit/test_worker_job_runtime.py tests/unit/test_job_lifecycle.py backend/app/tests/test_capture_stage_resilience.py backend/app/tests/test_sensor_runner.py backend/app/tests/test_capa_sensor.py backend/app/tests/test_yara_scanning.py backend/app/tests/test_triage_correctness.py backend/app/tests/test_settings_runtime.py backend/app/tests/test_api_jobs.py -q`

Expected: PASS for dispatch ambiguity, fencing, worker loss, cancellation, cleanup, and single terminal emission.

- [ ] **Step 9: Commit the runtime enforcement**

```powershell
git add backend/app/config_v2.py backend/app/database_v2.py backend/app/worker.py backend/app/runtime_supervisor.py backend/app/services/job_dispatch.py backend/app/services/job_lifecycle.py backend/app/services/job_service.py backend/app/pipeline/runtime_control.py backend/app/pipeline/sensor_process.py backend/app/pipeline/recovery.py backend/app/pipeline/orchestrator.py backend/app/pipeline/sensor_runner.py backend/app/pipeline/sensor_handlers.py backend/app/anomaly_detector.py backend/app/suricata_rules.py backend/app/bluescrub/isolation/runner.py backend/app/bluescrub/isolation/limits.py backend/app/api/jobs.py backend/app/tests/test_capture_stage_resilience.py backend/app/tests/test_sensor_runner.py backend/app/tests/test_capa_sensor.py backend/app/tests/test_yara_scanning.py backend/app/tests/test_triage_correctness.py backend/app/tests/test_settings_runtime.py tests/unit/test_job_dispatch.py tests/unit/test_worker_job_runtime.py docker-compose.yml .env.example
git commit -m "feat: fence and supervise analysis jobs"
```

### Task 5: Keep ChatPage synchronized with the complete job state machine

**Files:**
- Create: `frontend/Dockerfile.test`
- Modify: `frontend/.dockerignore`
- Create: `frontend/src/api/jobStatus.ts`
- Create: `frontend/tests/e2e/chat-job-lifecycle.spec.ts`
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/jobs.ts`
- Modify: `frontend/src/pages/ChatPage.tsx`
- Modify: `frontend/src/pages/JobDetailPage.tsx`
- Modify: `frontend/src/components/JobSubPageNav.tsx`
- Modify: `frontend/src/demo/mockApi.ts`

**Interfaces:**
- Consumes: backend `canceling`, `heartbeat_at`, and `cancel_requested_at` from Tasks 1 and 4.
- Produces: `isActiveJobStatus`, `isTerminalJobStatus`, and `isChatReadyJobStatus` shared predicates.

- [ ] **Step 1: Add a reproducible frontend test image**

Remove the `/tests` exclusion from `frontend/.dockerignore` while continuing to exclude reports and results. Create `frontend/Dockerfile.test` from `mcr.microsoft.com/playwright:v1.56.1-noble`, copy `package.json` and `package-lock.json`, run `npm ci`, copy the complete frontend source including `tests`, and set `/app` as its working directory. This image supplies Node plus the pinned Chromium runtime without touching the broken host Node installation.

- [ ] **Step 2: Write failing lifecycle browser tests, including shared predicate behavior**

In `chat-job-lifecycle.spec.ts`, import the status predicates and assert:

```typescript
expect(isActiveJobStatus("canceling")).toBe(true);
expect(isTerminalJobStatus("failed")).toBe(true);
expect(isChatReadyJobStatus("failed")).toBe(false);
expect(isChatReadyJobStatus("completed_with_errors")).toBe(true);
```

Update `cancelJob()` contract expectation to `Promise<JobGetResponse>`.

Route job responses through `queued -> running -> completed`, and separately `running -> canceling -> canceled` and `running -> failed`. Count requests to conversation and KB endpoints.

```typescript
await expect(page.getByText("Analysis in progress")).toBeVisible();
expect(conversationRequests).toBe(0);
await expect(page.getByRole("button", { name: "Enable MNEMOS" })).toBeVisible();
expect(conversationRequests).toBeGreaterThan(0);
```

Assert polling stops after terminal status, query failure renders Retry, failed shows `error_summary`, canceled offers rerun navigation, and `completed_with_errors` shows chat plus a partial-analysis warning.

- [ ] **Step 3: Run focused frontend tests and confirm they fail**

Build the test image and run Vite plus Playwright inside it:

```powershell
docker build -f frontend/Dockerfile.test -t aipam-frontend-test frontend
docker run --rm -e E2E_BASE_URL=http://127.0.0.1:5173 aipam-frontend-test bash -lc "npm run dev -- --host 0.0.0.0 > /tmp/vite.log 2>&1 & for i in {1..60}; do curl -fsS http://127.0.0.1:5173 >/dev/null && break; sleep 1; done; npm run test:e2e -- chat-job-lifecycle.spec.ts"
```

Expected: FAIL because ChatPage fetches once, uses only successful terminal states, and hydrates chat dependencies too early.

- [ ] **Step 4: Implement shared status predicates and active polling**

Use:

```typescript
refetchInterval: query =>
  isActiveJobStatus(query.state.data?.job.status) ? 2_000 : false,
refetchIntervalInBackground: true,
```

Place the job query before conversation/KB effects. Gate baseline conversation loading, comparison restore, and KB hydration on `isChatReadyJobStatus(job?.status)`. Keep both baseline and MNEMOS panes unchanged inside the ready branch.

- [ ] **Step 5: Render explicit state and error panels**

Render separate copy for queued, running, canceling, failed, canceled, deleted, and query-error states. Update the cancel mutation cache from the returned `JobGetResponse`; show “Cancellation requested” for `canceling`. Use the same predicates in JobDetail and subpage navigation.

- [ ] **Step 6: Run frontend API, browser, and build checks**

```powershell
docker build --no-cache -f frontend/Dockerfile.test -t aipam-frontend-test frontend
docker run --rm aipam-frontend-test npm run test:api
docker run --rm -e E2E_BASE_URL=http://127.0.0.1:5173 aipam-frontend-test bash -lc "npm run dev -- --host 0.0.0.0 > /tmp/vite.log 2>&1 & for i in {1..60}; do curl -fsS http://127.0.0.1:5173 >/dev/null && break; sleep 1; done; npm run test:e2e -- chat-job-lifecycle.spec.ts mnemos-chat-comparison.spec.ts"
docker compose build frontend
```

Expected: PASS; MNEMOS comparison remains available beside baseline chat only after successful analysis.

- [ ] **Step 7: Commit the synchronized UI**

```powershell
git add frontend/Dockerfile.test frontend/.dockerignore frontend/src/api/jobStatus.ts frontend/src/api/types.ts frontend/src/api/jobs.ts frontend/src/pages/ChatPage.tsx frontend/src/pages/JobDetailPage.tsx frontend/src/components/JobSubPageNav.tsx frontend/src/demo/mockApi.ts frontend/tests/e2e/chat-job-lifecycle.spec.ts
git commit -m "fix: synchronize chat with job lifecycle"
```

### Task 6: Generate stable theories only for evidence-relevant hosts

**Files:**
- Create: `backend/alembic/versions/9c7e5a3b2d10_add_theory_semantic_key.py`
- Modify: `backend/app/models/theory.py`
- Modify: `backend/app/services/theory_engine.py`
- Modify: `tests/unit/test_theory_engine.py`
- Create: `tests/unit/test_theory_migration.py`
- Modify: `backend/app/pipeline/orchestrator.py`

**Interfaces:**
- Consumes: `ExecutionControl` checkpoints from Task 4.
- Produces: `EvidenceIndex`, `select_relevant_hosts`, `semantic_theory_id`, and metrics keys `discovered_hosts`, `relevant_hosts`, `skipped_benign_hosts`, `theory_scopes`, and `duration_ms`.

- [x] **Step 1: Write failing relevant-host and query-count tests**

```python
def test_connection_only_host_gets_no_host_theory(db, seeded_job):
    seed_host(db, "10.0.0.1", connections=100)
    seed_alert(db, "10.0.0.2")
    result = generate_all_theories(db, seeded_job.job_id)
    assert result["relevant_hosts"] == 1
    assert theory_scopes(db) == {("job", seeded_job.job_id), ("host", "10.0.0.2")}


def test_evidence_loading_query_count_is_constant(db, seeded_job, query_counter):
    seed_relevant_hosts(db, count=200)
    generate_all_theories(db, seeded_job.job_id)
    assert query_counter.selects <= 8
```

Build relevance from exact structured associations: `Finding.src_ip`/`dest_ip`; `Alert.src_ip`/`dest_ip`/`host_ip`; IOC `value` only when `ioc_type` is one of `ip`, `ipv4`, `ipv6`, `ip-dst`, or `ip-src` and `ipaddress.ip_address(value)` equals the host; and parsed JSON evidence values compared as complete strings. Never use SQL/text substring matching. Include corroborated/confirmed telemetry through its structured host fields. Assert observed-only telemetry and connection counts do not qualify. Add `10.0.0.1` versus `10.0.0.10`, compressed IPv6 equivalence, malformed JSON, null field, and cross-phase tests.

- [x] **Step 2: Write failing semantic-ID and review-preservation tests**

```python
def test_candidate_reordering_keeps_theory_identity_and_review(db, seeded_job):
    first = generate_all_theories(db, seeded_job.job_id)
    reviewed = confirm_top_theory(db, notes="analyst-confirmed")
    reverse_candidate_scores(monkeypatch)
    generate_all_theories(db, seeded_job.job_id)
    row = db.scalar(select(Theory).where(Theory.theory_key == reviewed.theory_key))
    assert row.theory_id == reviewed.theory_id
    assert row.analyst_status == "confirmed"
    assert row.analyst_notes == "analyst-confirmed"


def test_migration_preserves_reviewed_legacy_row(migrated_db):
    row = migrated_db.one_theory()
    assert migrated_db.count_semantic_tuple(row) == 1
    assert row.theory_id == "TH-legacy-random"
    assert row.analyst_status == "confirmed"
```

Generate at least 100,000 semantic IDs across jobs/scopes and assert uniqueness. Add a regression for the observed eight-hex collision path and a flush-failure rollback.

- [x] **Step 3: Run theory tests and confirm they fail**

Run: `python -m pytest tests/unit/test_theory_engine.py -q`

Expected: FAIL because every host is processed, evidence is queried per scope, IDs use eight random hex characters, and each scope commits.

- [x] **Step 4: Add `theory_key` migration and deterministic identity**

Migration `9c7e5a3b2d10` revises `8b6f4d2a1c90` and adds non-null semantic key columns after backfill: `phase_key = COALESCE(pcap_label, '')`, `scope_id_key = COALESCE(scope_id, '')`, and `theory_key = hypothesis_type`. Consolidate duplicate semantic tuples deterministically, selecting a reviewed row before an unreviewed row and then the lowest integer primary key; preserve the selected row's existing `theory_id` and review metadata, and copy the most recent non-null review fields before deleting duplicates. Add a unique constraint over `(job_id, phase_key, scope_type, scope_id_key, theory_key)` so null labels cannot bypass uniqueness. Do not rewrite surviving legacy IDs. New rows use:

```python
def semantic_theory_id(job_id: str, pcap_label: str | None,
                       scope_type: str, scope_id: str, theory_key: str) -> str:
    name = "|".join([job_id, pcap_label or "", scope_type, scope_id, theory_key])
    return f"TH-{uuid5(AIPAM_THEORY_NAMESPACE, name)}"
```

The semantic key is the stable generator branch key (`c2`, `benign`, and so on); score, rank, label copy, and candidate position are excluded. Add populated migration tests and the round trip `8b6f4d2a1c90 -> 9c7e5a3b2d10 -> 8b6f4d2a1c90 -> 9c7e5a3b2d10`, proving all pre-existing fields survive the supported downgrade/upgrade cycle.

- [x] **Step 5: Preload evidence and batch one transaction**

Build `EvidenceIndex` with one set-based query per evidence family and phase-consistent filters. Upsert by the enforced semantic tuple, preserving the existing `theory_id`, `analyst_status`, `analyst_notes`, `reviewed_at`, and `reviewer_id`; assign `semantic_theory_id()` only when inserting a tuple that has never existed. Flush every 100 scopes, checkpoint between batches, and commit once. Remove per-host calls to `generate_theories()` that commit internally.

- [x] **Step 6: Run theory and pipeline regression tests**

Run: `python -m pytest tests/unit/test_theory_engine.py tests/unit/test_theory_migration.py tests/unit/test_pipeline_outcomes.py tests/unit/test_phase2_pipeline.py -q`

Expected: PASS; query/commit counts do not grow once per discovered host and stable review metadata survives regeneration.

- [x] **Step 7: Commit theory performance and identity**

```powershell
git add backend/alembic/versions/9c7e5a3b2d10_add_theory_semantic_key.py backend/app/models/theory.py backend/app/services/theory_engine.py backend/app/pipeline/orchestrator.py tests/unit/test_theory_engine.py tests/unit/test_theory_migration.py
git commit -m "perf: scope and stabilize theory generation"
```

### Task 7: Stream correlation with bounded memory and replay receipts

**Files:**
- Create: `backend/alembic/versions/a1d8f6b4c320_add_correlation_run_receipts.py`
- Create: `backend/app/models/correlation_run.py`
- Create: `backend/app/pipeline/bundle_digest.py`
- Modify: `backend/app/models/__init__.py`
- Modify: `backend/app/normalize/correlate.py`
- Modify: `backend/app/pipeline/orchestrator.py`
- Modify: `backend/app/tests/test_correlation.py`
- Modify: `backend/app/tests/test_correlation_v2.py`
- Modify: `tests/unit/test_correlation.py`
- Create: `tests/unit/test_bundle_digest.py`

**Interfaces:**
- Consumes: `ExecutionControl` from Task 4 and the current owned `run_output_dir` passed internally from Tasks 2-3. It never resolves the accepted manifest while the run is active.
- Produces: `CorrelationResult(counts, committed_finding_events, replayed, input_fingerprint)`, `compute_analysis_bundle_sha256()`, manifest field `bundle_sha256`, and table `correlation_runs(job_id, correlator_version, input_fingerprint, counts_json, completed_at)`.

- [ ] **Step 1: Write failing streaming-equivalence tests**

Generate JSONL fixtures larger than two insert batches and compare the expected row projections and counts to the existing correlator for connections, alerts, DNS, TLS, findings, IOCs, files, timeline, and hosts.

```python
def test_signature_accumulator_crosses_batch_boundary(db, job_dir):
    write_alerts(job_dir, signature="Repeated C2", count=2_005)
    result = correlate_job(JOB_ID, job_dir, db, batch_size=2_000)
    finding = finding_by_title(db, "Repeated C2")
    assert json.loads(finding.evidence_json)["alert_count"] == 2_005
    assert result.counts["findings"] == 1
```

Assert severity ties, first-in-order category/engine/phase, earliest timestamp, confidence formula, IOC deduplication, host aggregation, malformed-line skipping, and canonical sensor/file/line order.

- [ ] **Step 2: Write failing transaction and replay tests**

```python
def test_cancel_between_batches_rolls_back_rows_and_receipt(db, job_dir, control):
    control.cancel_after_checkpoint(2)
    with pytest.raises(JobCancellationRequested):
        correlate_job(JOB_ID, job_dir, db, control=control, batch_size=100)
    assert correlation_row_count(db, JOB_ID) == 0
    assert receipt_count(db, JOB_ID) == 0


def test_identical_fingerprint_is_noop(db, job_dir):
    first = correlate_and_commit(db, job_dir)
    second = correlate_and_commit(db, job_dir)
    assert second.replayed is True
    assert row_counts(db) == first.counts
```

- [ ] **Step 3: Run correlation tests and confirm they fail**

Run: `python -m pytest backend/app/tests/test_correlation.py backend/app/tests/test_correlation_v2.py tests/unit/test_correlation.py -q`

Expected: FAIL because `_collect_sensor_outputs()` materializes all events, alert synthesis makes a second full pass, and no replay receipt exists.

- [ ] **Step 4: Add the receipt model and canonical fingerprint**

Migration `a1d8f6b4c320` revises `9c7e5a3b2d10`. Use a unique constraint on `(job_id, correlator_version, input_fingerprint)`. Hash the phase label plus every sensor result file under the owned `run_output_dir` in canonical relative-path order, streaming file bytes into SHA-256. Add populated `upgrade -> downgrade -> upgrade` coverage for this table and prove pre-existing analysis rows survive.

- [ ] **Step 5: Replace collection with one-pass iterators and accumulators**

Implement `_iter_jsonl()` and `_iter_sensor_outputs()` generators. Buffer typed Core insert mappings to 2,000 rows, execute them without committing, then clear the buffer. Keep compact `HostAccumulator`, `(ioc_type, value)` set, and `AlertGroupAccumulator` keyed by signature. The alert accumulator retains count, first event, best severity, earliest timestamp, affected IPs, and first-in-order metadata.

- [ ] **Step 6: Commit atomically before publishing finding events**

Insert the receipt and all rows in one transaction. `correlate_job()` returns high-severity event payloads without publishing them. The orchestrator commits, then emits those events; a rollback emits none.

After all correlation, annotations, and theories for the run have committed, call `compute_analysis_bundle_sha256(db, job_id, phase_label)`. Normalize IP addresses with `ipaddress`, floats to fixed decimal strings, and JSON recursively with sorted object keys; sort set-like JSON arrays. Exclude job ID, every integer primary key, generated IDs (`connection_id`, `alert_id`, `dns_id`, `tls_id`, `finding_id`, `ioc_id`, `file_id`, `theory_id`), artifact paths/IDs, analyst fields, runtime durations, and creation/completion metadata. For job-scoped theories normalize `scope_id` to an empty string and omit generated evidence-ID arrays. Each entity's listed tuple is both its projection and lexicographic sort key:

| Entity | Canonical semantic tuple |
|---|---|
| connection | phase, community, host/src/src-port/dest/dest-port/proto, duration, sent/received bytes, service, event timestamp |
| alert | phase, host/community, severity, engine, signature/category/SID, src/src-port/dest/dest-port/proto, normalized refs/tags, event timestamp |
| DNS | phase, host/community/src/dest, query/qtype, normalized answers, rcode/TTL, event timestamp |
| TLS | phase, host/community/src/dest/dest-port, SNI/JA3/JA3S/ALPN/version, certificate subject/issuer/fingerprint, event timestamp |
| finding | phase, sensor/severity/category/title/summary/community, confidence, event timestamp, src/dest, evidence status/corroboration score, normalized corroborating sources; omit ID-bearing `evidence_json` |
| IOC | phase, type/value/severity/confidence/source sensor, normalized sources, context |
| file | phase, filename/host/community/SHA-256/MD5/ssdeep/size/MIME/entropy/source, normalized YARA matches, event timestamp; omit extracted path/download artifact ID |
| timeline | phase, event timestamp/type/severity/title, normalized details |
| host | phase, normalized IP/role/counts/bytes/first-last seen, normalized domains/services/severity counts |
| theory | phase key, scope type, normalized scope key, theory key/type, label/score/confidence/rank, normalized score breakdown/explanation/next steps; omit review fields and evidence-ID arrays |

Serialize `{schema: "aipam-analysis-bundle-v1", entities: ...}` with UTF-8, sorted JSON keys, and compact separators, then SHA-256 it and store the digest in that run's manifest entry before worker finalization. Tests use distinct job IDs for the same generated fixture at parallelism 1 and 2 and require the same `bundle_sha256`; changing a semantic finding, IOC, or theory must change it.

- [ ] **Step 7: Run correlation regression and bounded-batch tests**

Run: `python -m pytest backend/app/tests/test_correlation.py backend/app/tests/test_correlation_v2.py tests/unit/test_correlation.py tests/unit/test_bundle_digest.py tests/unit/test_pipeline_outcomes.py -q`

Expected: PASS with buffer length never exceeding 2,000 and identical semantic counts/projections.

- [ ] **Step 8: Commit streamed correlation**

```powershell
git add backend/alembic/versions/a1d8f6b4c320_add_correlation_run_receipts.py backend/app/models/correlation_run.py backend/app/models/__init__.py backend/app/normalize/correlate.py backend/app/pipeline/bundle_digest.py backend/app/pipeline/orchestrator.py backend/app/tests/test_correlation.py backend/app/tests/test_correlation_v2.py tests/unit/test_correlation.py tests/unit/test_bundle_digest.py
git commit -m "perf: stream and fence correlation persistence"
```

### Task 8: Schedule independent sensors with bounded concurrency

**Files:**
- Create: `backend/app/pipeline/scheduler.py`
- Create: `tests/unit/test_pipeline_scheduler.py`
- Modify: `backend/app/config_v2.py`
- Modify: `backend/app/sensors/registry.py`
- Modify: `backend/app/pipeline/orchestrator.py`
- Modify: `backend/app/pipeline/sensor_runner.py`
- Modify: `backend/app/pipeline/sensor_handlers.py`
- Modify: `tests/unit/test_phase2_pipeline.py`
- Modify: `backend/app/tests/test_settings_runtime.py`
- Modify: `.env.example`

**Interfaces:**
- Consumes: Task 4 `ExecutionControl` and existing `SensorDef.inputs_required`/`skip_if_missing_inputs`.
- Produces: `run_sensor_dag(nodes, parallelism, run_node, on_start, on_finish, control) -> list[SensorResult]`.

- [ ] **Step 1: Write failing pure-scheduler tests**

Use barriers and a thread-safe event log to prove:

```python
def test_stage_pair_overlaps_but_never_exceeds_two_workers():
    trace = run_barrier_scheduler(parallelism=2)
    assert trace.overlapped("zeek", "suricata")
    assert trace.max_active == 2


def test_dependency_and_parent_thread_contract():
    trace = run_completed_scheduler(parallelism=2)
    assert trace.started_after("capa", "file_triage")
    assert trace.started_after("ti_matcher", "suricata")
    assert set(trace.finish_thread_ids) == {trace.orchestrator_thread_id}
```

Add separate concrete tests named `test_sensor_layer_starts_only_after_zeek_and_suricata_settle`, `test_cancel_stops_new_submissions_and_reaps_running_nodes`, and `test_failed_required_input_obeys_registry_skip_policy` using the same trace fixture.

Assert deterministic registry-order persistence even when futures finish in reverse order. Preserve current skip behavior: only nodes with `skip_if_missing_inputs=True` skip after failed/missing producers. Parameterize over every `SENSORS` entry and require the Task 4 subprocess isolation mode plus a positive total deadline. Add settings cases for missing/default, `0`, `1`, `2`, `3`, negative, and malformed `AIPAM_SENSOR_PARALLELISM`, proving the result is always an integer in `1..2` or startup rejects malformed input with a stable message.

- [ ] **Step 2: Run scheduler tests and confirm they fail**

Run: `python -m pytest tests/unit/test_pipeline_scheduler.py -q`

Expected: FAIL because stages and sensors run in serial loops and no scheduler exists.

- [ ] **Step 3: Implement the bounded DAG scheduler**

Use `ThreadPoolExecutor(max_workers=min(max(parallelism, 1), 2))`, Kahn-style readiness, and `wait(pending_futures, return_when=FIRST_COMPLETED, timeout=1)`. The graph is:

```text
input -> {zeek, suricata}
stage barrier -> {tls_enrich, beaconing, file_triage, ti_matcher}
file_triage -> capa
```

Workers receive immutable definitions and per-thread Docker clients; they never receive a SQLAlchemy session. The parent calls `_record_sensor_result`, emits status, checks quota, and supplies results to downstream nodes.

- [ ] **Step 4: Pass cancellation and deadlines into every handler**

Extend the handler contract with `SensorExecutionContext(checkpoint, deadline, stop_event, cancel_file)`, where `stop_event` is the parent scheduler's in-process mirror and `cancel_file` is the cross-process authority defined in Task 4. All seven registry entries must already launch through `sensor_process.py`; fail startup if a registered handler lacks an explicit isolation mode or deadline. The scheduler may report a timeout only after the handler process group is stopped and reaped; abandoning a Python future while it keeps writing is forbidden.

- [ ] **Step 5: Run scheduler, sensor, and orchestrator tests**

Run: `python -m pytest tests/unit/test_pipeline_scheduler.py tests/unit/test_phase2_pipeline.py backend/app/tests/test_capture_stage_resilience.py backend/app/tests/test_sensor_runner.py backend/app/tests/test_settings_runtime.py -q`

Expected: PASS at parallelism 1 and 2; no DB callback occurs from worker threads.

- [ ] **Step 6: Commit bounded parallel scheduling**

```powershell
git add backend/app/pipeline/scheduler.py backend/app/config_v2.py backend/app/sensors/registry.py backend/app/pipeline/orchestrator.py backend/app/pipeline/sensor_runner.py backend/app/pipeline/sensor_handlers.py tests/unit/test_pipeline_scheduler.py tests/unit/test_phase2_pipeline.py backend/app/tests/test_capture_stage_resilience.py backend/app/tests/test_settings_runtime.py .env.example
git commit -m "perf: schedule independent sensors concurrently"
```

### Task 9: Replace implicit schema creation with safe legacy adoption

**Files:**
- Create: `backend/app/schema_bootstrap.py`
- Create: `backend/app/schema_cli.py`
- Create: `backend/app/tests/fixtures/schema/legacy_unversioned.sql`
- Create: `backend/app/tests/fixtures/schema/legacy_partial_chat_empty.sql`
- Create: `backend/app/tests/fixtures/schema/legacy_partial_chat_populated.sql`
- Create: `backend/app/tests/test_schema_bootstrap.py`
- Modify: `backend/app/database_v2.py`
- Modify: `backend/alembic/env.py`
- Modify: `backend/app/main_v2.py`
- Modify: `backend/app/worker.py`
- Modify: `backend/app/runtime_supervisor.py`
- Modify: `docker-compose.yml`
- Modify: `deploy/Dockerfile.app`
- Modify: `README.md`

**Interfaces:**
- Produces: `inspect_schema_profile`, `adopt_legacy_database`, `assert_schema_current`, and CLI commands `python -m backend.app.schema_cli migrate|verify`.
- Consumes: Alembic head after Tasks 1, 6, and 7.

- [ ] **Step 1: Capture allowlisted legacy fixtures and fingerprints**

Support only these exact profiles; all others fail closed:

| Profile ID | Fixture provenance | Candidate action / predecessor |
|---|---|---|
| `fresh-empty-v1` | zero user objects and no `alembic_version` | run the repaired Alembic chain from base without stamping |
| `alembic:<sorted-current-revisions>` | revisions known by Alembic `ScriptDirectory`, including branch states `c7d4f6a1e2b3`, `e2a9f4b71d83`, and their two-head set | prove every revision is a target-head ancestor and migrate candidate normally; never stamp |
| `legacy-unversioned-precomparison-v1` | 48-table deployment layout at code boundary `f6583ecb4aa439f77296022cec91ed20ac92685b`; canonical SHA-256 `3f64e11ebef645a842b2c880396c5a52b9ad82dd16f72fd3a9d0fee2c855acb1` | exact fingerprint, stamp candidate `d4e5f6a7b8c9`, then upgrade |
| `legacy-unversioned-partial-comparison-v1` | observed live 50-table layout at deployed commit `26170e2686504edce4d2f91a7ea345084382c3b7`; canonical SHA-256 `5e12805b3b8a9972bb20e5d26b6409cf0eb46d77bca02cdd3fb917e326a66e76` | require both comparison tables empty; remove their known indexes/trigger and tables only on candidate; stamp `d4e5f6a7b8c9`; upgrade |

`legacy_partial_chat_populated.sql` is a refusal fixture, not a supported profile. An empty, malformed, ahead, unknown, or inconsistent `alembic_version` table is also unsupported. Use canonical format `aipam-schema-fingerprint-v1`: tables/columns, normalized types, nullability, defaults, primary-key position, semantic unique column sets, foreign keys/actions, named indexes/predicates, and normalized triggers; exclude row counts and generated `sqlite_autoindex_*` names. Store profile IDs, source commits, expected predecessors, and hashes in code; do not infer a closest match or allow an operator-supplied revision override.

- [ ] **Step 2: Write failing adoption/refusal tests**

```python
def test_empty_partial_chat_artifacts_are_adopted(tmp_path):
    source = load_fixture(tmp_path, "legacy_partial_chat_empty.sql")
    receipt = adopt_legacy_database(source)
    assert current_revision(source) == alembic_head()
    assert existing_chat_rows(source) == EXPECTED_CHAT_ROWS
    assert receipt["source_sha256"]


def test_populated_conflicting_table_refuses_without_source_change(tmp_path):
    source = load_fixture(tmp_path, "legacy_partial_chat_populated.sql")
    before = sha256(source)
    with pytest.raises(UnsupportedLegacySchema):
        adopt_legacy_database(source)
    assert sha256(source) == before
```

Verify both fixture hashes exactly and prove one-column, index, foreign-key, or trigger drift rejects. Also cover unknown fingerprint, insufficient disk, active queued/running/canceling/deleting jobs, backup failure, Alembic failure, validation failure, multiprocess concurrent init, killed lock-holder reacquisition despite stale file contents, empty database, every supported versioned ancestor/branch state, committed content resident in WAL, interruption after backup/migration/validation/prepared receipt/checkpoint/replacement/receipt commit, all handles disposed at replacement, backup restore dry run, and API/worker refusal at behind/ahead revisions. Early refusals preserve byte SHA; later pre-replacement failures preserve logical schema/rows.

- [ ] **Step 3: Run bootstrap tests and confirm they fail**

Run: `python -m pytest backend/app/tests/test_schema_bootstrap.py backend/app/tests/test_chat_comparison_migration.py -q`

Expected: FAIL because startup uses `create_all()`, swallows errors, and has no legacy adoption command.

- [ ] **Step 4: Implement candidate-based migration**

Use `/data/.aipam.db.schema.lock` with an OS advisory lock held on an open descriptor: `fcntl.flock` on POSIX and `msvcrt.locking` in Windows tests. Write PID, hostname/container ID, operation ID, start time, and database basename after acquisition. API, worker, and supervisor hold a shared lock for process lifetime; migration takes the exclusive lock. File contents may remain after a crash because OS ownership releases automatically; never infer ownership from age or delete/steal a live lock. A second initializer times out with `MigrationInProgress`. The first rollout still stops the old API/worker because that image does not participate in this protocol.

The command must use direct, context-managed SQLite connections without constructing the application SQLAlchemy engine and execute:

```text
exclusive init lock -> read-only profile/active-job refusal -> source quick_check
-> WAL-aware SQLite backup API creates immutable checksummed backup
-> validate/fsync/chmod read-only backup in journal_mode=DELETE
-> SQLite backup API creates same-directory candidate from backup
-> quick_check backup/candidate -> exact profile match
-> apply only that profile's declared stamp/action -> alembic upgrade head on candidate
-> integrity_check + foreign_key_check + schema/data/metadata invariants
-> close all handles; require candidate -wal/-shm absent
-> fsync backup, candidate, and prepared receipt
-> source-only PRAGMA wal_checkpoint(TRUNCATE), require busy=0/all frames checkpointed
-> close source; require source -wal/-shm absent or empty; assert connection registry empty
-> os.replace(candidate, source) on same filesystem -> fsync parent directory
-> reopen source read-only and revalidate -> atomically mark receipt committed -> release lock
```

Use `/data/schema-backups/aipam.<UTC>.<operation-id>.sqlite3`, `/data/.aipam.db.<operation-id>.candidate`, and `/data/schema-receipts/<operation-id>.json`; require free space of at least three times `page_count * page_size` plus 256 MiB. Explicitly dispose every SQLAlchemy/Alembic engine, update `alembic/env.py` to dispose its `NullPool` engine, and never rely on garbage collection before replacement.

If any step before the final checkpoint fails, source bytes remain unchanged; checkpoint failure may change page placement but not logical content after the verified backup exists. An interruption test must prove the source is either the complete old file or complete validated candidate, never a partial mix. Legacy source plus a prepared receipt means replacement did not occur: quarantine the candidate and retry with a new operation ID. Target-head source matching the prepared candidate checksum means replacement occurred: finish validation and commit the receipt. Any third checksum/revision state blocks operator recovery. The receipt contains paths, checksums, profile ID, revisions, row-count/primary-key/chat/non-content invariants, and timestamps without secrets or row content.

- [ ] **Step 5: Remove production `create_all()` and swallowed startup errors**

Keep metadata creation only in explicit test helpers. The startup order is mandatory for API, worker, and supervisor: acquire the process-lifetime shared schema lock, assert the schema is current, create the SQLAlchemy engine/session factories, and retain the lock descriptor until process exit. Refuse startup on absent, unversioned, behind, ahead, or inconsistent schema. Remove per-task `init_v2_db()` calls and broad startup `except: pass` behavior. Tests pause a process between lock acquisition and engine creation and prove an exclusive migration cannot pass it.

- [ ] **Step 6: Add one-shot Compose schema init**

Add one-shot `aipam-db-init` using the app image and `/data` volume. API, worker, and supervisor depend on its successful completion. Document manual first adoption and the only supported live rollback: stop every writer/init service, acquire the exclusive lock, verify receipt/backup checksum/quick-check/source profile, back up the migrated database separately, build and validate a restore candidate from the retained backup with SQLite's backup API, close/checkpoint every handle, atomically replace the source, fsync the directory, write a `restored` receipt, and start the previous image recorded in the migration receipt. Alembic downgrades remain developer round-trip checks for the new feature revisions, not a production rollback path.

- [ ] **Step 7: Run migration and chat regression tests**

Run: `python -m pytest backend/app/tests/test_schema_bootstrap.py backend/app/tests/test_chat_comparison_migration.py backend/app/tests/test_api_chat_comparisons.py -q`

Expected: PASS; a supported unversioned fixture reaches Alembic head and MNEMOS comparison columns/tables work without data loss.

- [ ] **Step 8: Commit safe schema bootstrap**

```powershell
git add backend/app/schema_bootstrap.py backend/app/schema_cli.py backend/app/tests/fixtures/schema backend/app/tests/test_schema_bootstrap.py backend/app/database_v2.py backend/alembic/env.py backend/app/main_v2.py backend/app/worker.py backend/app/runtime_supervisor.py docker-compose.yml deploy/Dockerfile.app README.md
git commit -m "feat: add safe sqlite schema bootstrap"
```

### Task 10: Validate the integrated system and prepare the live rollout

**Files:**
- Create: `docker-compose.runtime-test.yml`
- Create: `scripts/runtime_resilience_harness.py`
- Create: `docs/evidence/job-runtime-resilience-2026-09-23.md`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-09-23-job-runtime-resilience.md` only to check completed boxes during execution

**Interfaces:**
- Consumes: all Tasks 1-9.
- Produces: sanitized evidence receipt, operator runbook, and reviewable deployment commands. Live database migration and remote push remain separate approval-bound actions.

- [ ] **Step 1: Run focused backend suites**

```powershell
python -m pytest tests/unit/test_job_runtime.py tests/unit/test_job_dispatch.py tests/unit/test_worker_job_runtime.py tests/unit/test_run_artifacts.py tests/unit/test_pipeline_outcomes.py tests/unit/test_theory_engine.py tests/unit/test_theory_migration.py tests/unit/test_pipeline_scheduler.py tests/unit/test_correlation.py tests/unit/test_bundle_digest.py backend/app/tests/test_capture_stage_resilience.py backend/app/tests/test_sensor_runner.py backend/app/tests/test_settings_runtime.py backend/app/tests/test_correlation.py backend/app/tests/test_correlation_v2.py backend/app/tests/test_schema_migration_chain.py backend/app/tests/test_schema_bootstrap.py backend/app/tests/test_chat_comparison_migration.py backend/app/tests/test_api_jobs.py -q
```

Expected: PASS with zero failures.

- [ ] **Step 2: Run the full backend suite and classify only known baseline failures**

Run: `python -m pytest tests/unit backend/app/tests -q`

Expected: all changed-area tests pass. If the five embedding-selection KB tests still fail identically, record their exact names and unchanged traceback signature as baseline. Any new failure blocks completion.

- [ ] **Step 3: Build and test through Docker**

```powershell
docker compose build backend frontend
docker build -f frontend/Dockerfile.test -t aipam-frontend-test frontend
docker run --rm aipam-frontend-test npm run test:api
docker run --rm -e E2E_BASE_URL=http://127.0.0.1:5173 aipam-frontend-test bash -lc "npm run dev -- --host 0.0.0.0 > /tmp/vite.log 2>&1 & for i in {1..60}; do curl -fsS http://127.0.0.1:5173 >/dev/null && break; sleep 1; done; npm run test:e2e -- chat-job-lifecycle.spec.ts mnemos-chat-comparison.spec.ts"
```

Expected: images build; API tests and both browser specifications pass.

- [ ] **Step 4: Run deterministic and resilience integration scenarios on a disposable database**

Create `docker-compose.runtime-test.yml` as a standalone stack with isolated project-scoped DB/job/upload volumes, Redis, schema init, backend, one-worker Celery, runtime supervisor, and a harness service; publish no host ports. Mount the Docker socket only into worker, supervisor, and harness, and bind `./scripts` plus `./tests/fixtures` read-only into the harness because the production app image intentionally omits them. Enable `AIPAM_RUNTIME_TEST_MODE=1`, which makes `sensor_process.py` emit deterministic sensor fixtures and exposes file-based pause hooks at `sensor:zeek:started` and `theory:before-flush`; reject that setting outside this standalone Compose file.

`runtime_resilience_harness.py` submits `tests/fixtures/golden/small_benign.pcap`, creates/releases pause files in the shared jobs volume, locates containers only through its unique Compose project label, and exits nonzero on any failed assertion. It implements scenarios `deterministic`, `worker-loss-sensor`, `worker-loss-theory`, `cancel-queued`, and `cancel-running`; records monotonic request-to-terminal timing; waits up to 135 seconds for stale-worker reconciliation; verifies no unaccepted bytes are externally readable; confirms redelivery is a no-op; and reruns as a new job. Run exactly:

```powershell
python -m tests.fixtures.golden.generate_golden_pcaps
$runtimeProject = "aipam-runtime-test-$([guid]::NewGuid().ToString('N'))"
docker compose -p $runtimeProject -f docker-compose.runtime-test.yml build
docker compose -p $runtimeProject -f docker-compose.runtime-test.yml up -d redis aipam-db-init backend worker runtime-supervisor
try {
    docker compose -p $runtimeProject -f docker-compose.runtime-test.yml run --rm runtime-test-harness python scripts/runtime_resilience_harness.py --base-url http://backend:8000 --fixture /app/tests/fixtures/golden/small_benign.pcap --scenarios deterministic,worker-loss-sensor,worker-loss-theory,cancel-queued,cancel-running
} finally {
    docker compose -p $runtimeProject -f docker-compose.runtime-test.yml down -v --remove-orphans
}
```

The deterministic scenario uses distinct job IDs at parallelism 1 and 2, requires identical canonical projections and `bundle_sha256`, then mutates one semantic result and requires a different digest. Worker-loss scenarios kill only the labelled disposable worker at each pause hook and assert stale terminalization, no accepted abandoned artifacts, no duplicate redelivery execution, and successful rerun. Cancellation scenarios require cooperative completion by 30 seconds where applicable and matching/absent-identity forced completion by 60 seconds, with labelled process/container cleanup.

- [ ] **Step 5: Enforce the external DAWN release prerequisite**

Check the external dependency before running either repository harness:

```powershell
$dawnRoot = (Resolve-Path '..\DAWN' -ErrorAction Stop).Path
$releaseVerifier = Join-Path $dawnRoot 'dawn\links\quality.release_verifier\run.py'
if (-not (Test-Path -LiteralPath $releaseVerifier)) {
    throw "DAWN quality.release_verifier is unavailable: $releaseVerifier"
}
$env:DAWN_ROOT = $dawnRoot
python scripts/verify_pyramid.py
python scripts/closed_loop_test.py
```

At planning time `E:\DAWN` is absent, so this repository cannot establish the verifier's supported CLI, `aipam_forensic.yaml` contract, fixture, or ledger path. Treat those as an explicit external release prerequisite. Run `quality.release_verifier` only after the external checkout/version and its documented exact command are available and added to this plan/evidence receipt; capture that command, DAWN commit, pipeline file, fixture, expected ledger path/trace, and sanitized `PASS` output. Until then record `external verification blocked: DAWN dependency unavailable` and stop the release audit. Do not claim release readiness or substitute a different smoke test.

- [ ] **Step 6: Write the evidence receipt and operator runbook**

Record commit range, migration head, test commands/counts, baseline exclusions, deterministic hashes, timing before/after, worker-loss/cancel evidence, backup/rollback dry run, MNEMOS chat check, and remaining limitations. Include exact manual rollout sequence without executing it:

```text
confirm no active jobs -> stop API/worker/supervisor -> run schema init backup/candidate migration
-> verify receipt/head -> start services -> submit small disposable job
-> verify baseline + MNEMOS chat -> submit measured large-PCAP job
```

- [ ] **Step 7: Commit verification documentation**

```powershell
git add docker-compose.runtime-test.yml scripts/runtime_resilience_harness.py docs/evidence/job-runtime-resilience-2026-09-23.md README.md docs/superpowers/plans/2026-09-23-job-runtime-resilience.md
git commit -m "docs: record job resilience verification"
```

## Plan self-review

- Spec coverage: Tasks 1-4 implement ownership, fencing, cancellation, exception terminalization, artifact acceptance, dispatch races, and reconciliation. Task 5 implements chat lifecycle behavior. Tasks 6-8 implement theory, correlation, and bounded sensor throughput. Task 9 implements safe legacy schema adoption. Task 10 covers deterministic evidence, the external DAWN release gate, and rollout.
- Placeholder scan: no unfinished implementation markers or deferred code steps are present.
- Type consistency: `RunHandle` originates in Task 1; `PipelineOutcome` in Task 3; `ExecutionControl`/`FencedSession` in Task 4; performance tasks consume those exact interfaces.
- Review focus: uncertain publish is tested in Task 4, cancellation escalation in Task 4, semantic theory identity in Task 6, cross-batch alert aggregation in Task 7, and populated mixed-schema refusal in Task 9.
- Adversarial review: the final pass found no unresolved Critical or High findings after cancellation deadlines/IPC, canonical bundle hashing, convergent schema migration, lock-before-engine startup, and the disposable resilience harness were made explicit.
- Scope boundary: remote push, merge to `main`, live database replacement, and live container restart are not implementation steps; they require the finishing/deployment approval after evidence review.
