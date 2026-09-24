# MNEMOS Evidence Receipts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create durable evidence receipts for completed AIPAM MNEMOS comparison answers and make each receipt directly accessible from chat and navigable in AIPAM history/detail views.

**Architecture:** The FastAPI chat completion persistence path will write a JSON receipt to an AIPAM-configured directory on the existing persistent logs volume and persist its ID in assistant metadata and response metadata. Authenticated FastAPI history/detail endpoints will read active and archived receipts with cursor pagination; the existing React app will render answer links and provide history, detail, and authenticated JSON download.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic Settings, pytest/TestClient, React 18, TypeScript, React Router, Playwright, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-24-mnemos-evidence-receipts-design.md`

## Global Constraints

- Create receipts for completed MNEMOS comparison answers only; baseline, pending, and failed turns have no successful receipt.
- Support both JSON and SSE chat completion, and surface the receipt ID in the SSE terminal metadata for an immediate link.
- Store receipts under `/opt/aipam/logs/evidence_receipts` in the API container on the existing persistent `aipam-logs` volume.
- Do not modify or depend on the master MNEMOS checkout at `G:\MNEMOS`.
- Include active and archived receipts in stable paginated history; never silently delete overflow.
- Require AIPAM authentication on receipt API routes; validate IDs and prevent path traversal.
- A receipt filesystem failure must not convert a successful model response into a failed chat request or render a dead link.
- Keep existing chat history backward compatible by storing receipt references in existing assistant `metadata_json`.
- Do not restart live Compose services during unit or browser test runs.

## Review Focus

- **Duplicate/replayed requests:** the same completed assistant turn must resolve to the same receipt ID and file; pin in Task 2 chat tests.
- **SSE completion before UI history refresh:** receipt link appears as soon as the terminal event arrives, even if the history refresh fails; pin in Task 4.
- **Receipt write failure or partial write:** answer stays successful, no dead link is returned, and incomplete temp files are not listed; pin in Tasks 1 and 2.
- **Archive cursor boundaries and equal timestamps:** pagination includes all IDs once across active and archive files while newly added receipts do not shift prior pages; pin in Task 1.
- **Malformed IDs/files and unauthenticated access:** no path escape or private receipt disclosure; pin in Task 3.

---

### Task 1: Receipt storage service and persistent configuration

**Files:**
- Create: `backend/app/services/mnemos_evidence_receipts.py`
- Modify: `backend/app/config_v2.py`
- Modify: `docker-compose.yml` (API `backend` service only)
- Test: `backend/app/tests/test_mnemos_evidence_receipts.py`

**Interfaces:**
- `build_evidence_receipt(*, receipt_id: str, created_at: str, job_id: str, conversation_id: str, assistant_message_id: str, request_id: str | None, query: str, answer: str, model_id: str | None, generation: dict | None, runtime: dict | None, retrieval_status: str | None, citations: list[dict], evidence_refs: list[dict]) -> dict`
- `write_evidence_receipt(receipt_dir: Path, receipt: dict, *, max_files: int = 500) -> Path` atomically writes the receipt and archives overflow.
- `load_evidence_receipt(receipt_dir: Path, receipt_id: str) -> dict | None` validates the ID and reads only active/archive receipt locations.
- `list_evidence_receipts(receipt_dir: Path, *, limit: int = 50, cursor: str | None = None) -> tuple[list[dict], str | None]` orders by `(created_at, receipt_id)` descending and returns the next opaque cursor.
- Add settings `mnemos_evidence_receipt_dir: Path = Path("/opt/aipam/logs/evidence_receipts")` and `mnemos_evidence_receipt_max_files: int = 500`; Compose passes the directory to the API container.

- [ ] **Step 1: Write failing service tests** for canonical receipt fields/hash, safe IDs, active-directory writes, archive overflow, active-plus-archive ordering, cursor pages with tied timestamps, malformed files, missing IDs, atomic-write cleanup, and archive failure retaining active files.
- [ ] **Step 2: Run the focused test module and confirm expected failures.**

Run: `pytest backend/app/tests/test_mnemos_evidence_receipts.py -q`

Expected: FAIL because the receipt service and settings do not exist.

- [ ] **Step 3: Add the service and configuration.** Generate canonical JSON with sorted keys for hashing; write to a unique temporary file in the receipt directory, flush it, and use `os.replace` to publish. Remove any leftover temp file in `finally`. Move oldest active receipt files into `archive/` after a successful new write; on archive failure, log and leave the files in place. Use an opaque base64url cursor containing the last creation-time/ID pair, validate decoded shape, and filter strictly after that pair in descending order. Scan only `*.json` directly inside the active directory and `archive/`.

```python
core = {key: value for key, value in receipt.items() if key != "content_hash"}
receipt["content_hash"] = "sha256:" + hashlib.sha256(
    json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
).hexdigest()

temp_path = None
try:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=receipt_dir, delete=False) as handle:
        json.dump(receipt, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
        temp_path = Path(handle.name)
    os.replace(temp_path, receipt_path)
finally:
    if temp_path is not None:
        temp_path.unlink(missing_ok=True)
```
- [ ] **Step 4: Run storage tests and inspect Compose path wiring.**

Run: `pytest backend/app/tests/test_mnemos_evidence_receipts.py -q`

Expected: PASS; the default path is inside the existing backend `/opt/aipam/logs` persistent mount and no MNEMOS master path is referenced by runtime code.

- [ ] **Step 5: Commit the independently tested storage layer.**

```bash
git add backend/app/services/mnemos_evidence_receipts.py backend/app/config_v2.py docker-compose.yml backend/app/tests/test_mnemos_evidence_receipts.py
git commit -m "feat: add persistent MNEMOS evidence receipt storage"
```

### Task 2: Receipt generation in JSON and streamed chat lifecycle

**Files:**
- Modify: `backend/app/schemas/chat.py`
- Modify: `backend/app/api/chat.py`
- Test: `backend/app/tests/test_api_chat_comparisons.py`
- Test: `backend/app/tests/test_api_chat_mnemos.py`

**Interfaces:**
- Add optional `receipt_id: str | None` to `ChatResponseBody` and to the `type: "meta"` payload emitted by `_persisted_turn_sse_events` and the completed stream producer.
- Add keyword arguments `receipt_dir: Path | None = None` and `receipt_max_files: int = 500` to `_persist_assistant_turn`; successful MNEMOS call sites pass values from `Settings`. Metadata includes `receipt_id` only after a receipt file has been successfully written.
- Completed-turn receipt content is built from the persisted user message, assistant response, conversation/job identity, and `_assistant_metadata` fields so JSON and SSE cannot diverge.

- [ ] **Step 1: Add failing tests** to `test_api_chat_comparisons.py`: a completed MNEMOS JSON answer writes one receipt and returns the same ID in response and stored assistant metadata; duplicate JSON replay returns the same response/ID without another file; a completed SSE answer writes one receipt and its terminal metadata carries the ID; SSE replay returns the same ID; baseline, error, and pending turns have no receipt ID/file; a monkeypatched receipt writer raising `OSError` leaves the successful answer status completed and yields no link.
- [ ] **Step 2: Run the focused chat tests and confirm receipt assertions fail.**

Run: `pytest backend/app/tests/test_api_chat_comparisons.py -q -k "receipt or json_turn_persists_provenance or stream"`

Expected: FAIL because response metadata does not yet include receipt IDs and chat does not write receipts.

- [ ] **Step 3: Integrate receipt creation at assistant persistence.** Resolve the `ChatConversation` and originating user row before persisting. Only when `conversation.mode == "mnemos"` and metadata status is `completed`, build a receipt with a stable ID derived from the newly assigned assistant message ID, write it through Task 1's service, and then add `receipt_id` to assistant metadata before commit. Pass `receipt_dir` and `receipt_max_files` from `Settings` at the JSON and successful stream persistence call sites. Catch/log storage exceptions so they do not escape the persistence path. If an assistant turn already exists, return its persisted metadata and do not create another file.

```python
if conversation.mode == "mnemos" and metadata.get("status") == "completed":
    receipt_id = f"mnemos-{assistant.id}"
    try:
        receipt = build_evidence_receipt(
            receipt_id=receipt_id,
            job_id=conversation.job_id,
            conversation_id=conversation.id,
            assistant_message_id=assistant.id,
            request_id=request_id,
            query=origin.content,
            answer=response_text,
            # Remaining model/retrieval fields come from persisted metadata.
        )
        write_evidence_receipt(receipt_dir, receipt, max_files=receipt_max_files)
        metadata["receipt_id"] = receipt_id
    except OSError:
        logger.exception("Could not write evidence receipt for MNEMOS turn %s", request_id)
```
- [ ] **Step 4: Carry the receipt ID through every response path.** Add it to `_response_for_existing_turn`, `_chat_response`/`ChatResponseBody`, `_persisted_turn_sse_events`, and the final stream event emitted after the background producer persists its answer. Pending and failed response construction leaves it `None`.
- [ ] **Step 5: Run focused API and chat regression tests.**

Run: `pytest backend/app/tests/test_api_chat_comparisons.py backend/app/tests/test_api_chat_mnemos.py -q`

Expected: PASS, including duplicate/replay equality, stream terminal metadata, baseline exclusion, and the storage-failure path.

- [ ] **Step 6: Commit the chat lifecycle integration.**

```bash
git add backend/app/schemas/chat.py backend/app/api/chat.py backend/app/tests/test_api_chat_comparisons.py backend/app/tests/test_api_chat_mnemos.py
git commit -m "feat: write receipts for completed MNEMOS chat turns"
```

### Task 3: Authenticated receipt history and detail API

**Files:**
- Create: `backend/app/api/mnemos_receipts.py`
- Modify: `backend/app/main_v2.py`
- Test: `backend/app/tests/test_api_mnemos_evidence_receipts.py`

**Interfaces:**
- `GET /api/v1/mnemos/evidence-receipts?limit=50&cursor=...` returns `{"items": [...], "page": {"next_cursor": str | null, "has_more": bool}}`.
- `GET /api/v1/mnemos/evidence-receipts/{receipt_id}` returns the full receipt JSON or HTTP 404.
- Both routes use `Depends(verify_token)` and `get_settings()` and call Task 1's list/load functions.

- [ ] **Step 1: Write failing endpoint tests** for valid-token history, active/archive ordering and pagination, detail retrieval, no-token/invalid-token 401, malformed cursor 400, traversal-like ID 404/400, malformed file omission, and absent receipt 404.
- [ ] **Step 2: Run the endpoint tests and verify they fail at route lookup.**

Run: `pytest backend/app/tests/test_api_mnemos_evidence_receipts.py -q`

Expected: FAIL because the router does not exist.

- [ ] **Step 3: Implement the thin router.** Constrain `limit` to 1..100, delegate cursor validation and file access to the service, convert malformed cursors to HTTP 400, use 404 for invalid/missing receipt IDs, and avoid returning filesystem paths. Add the router to `create_app()` in `main_v2.py` under `/api/v1`.

```python
@router.get("/mnemos/evidence-receipts")
def receipt_history(
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    _token: str = Depends(verify_token),
    settings: Settings = Depends(get_settings),
):
    items, next_cursor = list_evidence_receipts(
        settings.mnemos_evidence_receipt_dir, limit=limit, cursor=cursor
    )
    return {"items": items, "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None}}
```
- [ ] **Step 4: Run API tests and relevant auth/API regressions.**

Run: `pytest backend/app/tests/test_api_mnemos_evidence_receipts.py backend/app/tests/test_api_system.py -q`

Expected: PASS; all receipt endpoints enforce the same bearer-token dependency as the rest of AIPAM.

- [ ] **Step 5: Commit the receipt API.**

```bash
git add backend/app/api/mnemos_receipts.py backend/app/main_v2.py backend/app/tests/test_api_mnemos_evidence_receipts.py
git commit -m "feat: expose authenticated MNEMOS receipt history"
```

### Task 4: Chat contracts and immediate answer receipt links

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/chat.ts`
- Modify: `frontend/src/components/ChatPanel.tsx`
- Create: `frontend/tests/e2e/mnemos-chat-receipt-link.spec.ts`

**Interfaces:**
- Add optional `receipt_id` to `ChatResponse`, `ChatStreamTerminalMetadata`, and assistant message metadata.
- Chat API module will export `MnemosEvidenceReceipt`, `MnemosEvidenceReceiptPage`, and functions `listMnemosEvidenceReceipts(limit, cursor?)` and `getMnemosEvidenceReceipt(receiptId)`; both use the existing authenticated transport.
- The `ChatPanel` only renders `/mnemos/receipts/{receipt_id}` when `mode === "mnemos"`, role is assistant, and metadata contains a non-empty `receipt_id`.

- [ ] **Step 1: Add a failing Playwright case** in the new focused test file that streams a MNEMOS answer whose completed `meta` contains a receipt ID and asserts a visible “View evidence receipt” link points to that exact detail route immediately after completion. Add a baseline answer case asserting no receipt link. Add a history-refresh failure case so the terminal ID still yields the link in the optimistic answer state. Keep receipt tests in this new file so the pre-existing uncommitted drawer-resize changes in `mnemos-chat-comparison.spec.ts` are not swept into a receipt commit.
- [ ] **Step 2: Run the focused browser case and confirm the receipt link is missing.**

Run: `cd frontend && npm run test:e2e -- tests/e2e/mnemos-chat-receipt-link.spec.ts`

Expected: FAIL because the frontend stream type/metadata renderer does not recognize the receipt ID.

- [ ] **Step 3: Add receipt API types/functions and render the conditional chat link.** In `ChatPanel.complete`, include `terminal.receipt_id` in optimistic assistant metadata; when history reload succeeds, use the persisted message metadata. Do not attach a link to baseline, pending, or error messages.

```tsx
const receiptId = message.role === "assistant" && mode === "mnemos" && message.metadata?.status === "completed"
  ? message.metadata?.receipt_id
  : undefined;
{typeof receiptId === "string" && receiptId.length > 0 && (
  <Link className="mt-2 inline-block text-xs text-cyan-300 underline" to={`/mnemos/receipts/${encodeURIComponent(receiptId)}`}>
    View evidence receipt
  </Link>
)}
```
- [ ] **Step 4: Run the MNEMOS chat browser suite and typecheck.**

Run: `cd frontend && npm run test:e2e -- tests/e2e/mnemos-chat-receipt-link.spec.ts`

Run: `cd frontend && npx tsc --noEmit`

Expected: PASS; existing comparison flows remain intact and the new answer link is immediate and correctly scoped.

- [ ] **Step 5: Commit chat contract and link behavior.**

```bash
git add frontend/src/api/types.ts frontend/src/api/chat.ts frontend/src/components/ChatPanel.tsx frontend/tests/e2e/mnemos-chat-receipt-link.spec.ts
git commit -m "feat: link MNEMOS answers to evidence receipts"
```

### Task 5: Receipt history and detail UI

**Files:**
- Create: `frontend/src/pages/MnemosReceiptsPage.tsx`
- Create: `frontend/tests/e2e/mnemos-evidence-receipts.spec.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/api/chat.ts` (add the authenticated JSON download helper)
- Modify: `frontend/src/data/pageHelpData.ts` only if route help metadata is required by existing page conventions.

**Interfaces:**
- React Router entries: `/mnemos/receipts` and `/mnemos/receipts/:receiptId`; a shared page may render list/detail based on the optional `receiptId` route parameter.
- Global `NAV_ITEMS` gains one “MNEMOS Receipts” entry pointing to `/mnemos/receipts`.
- List view loads the first 50 items and appends pages using `next_cursor`; detail view loads one receipt, links to history, and calls `downloadMnemosEvidenceReceipt(receiptId)` for JSON export. This task adds that helper to the API module established in Task 4.

- [ ] **Step 1: Write failing Playwright tests** with mocked receipt API responses: global navigation opens history, page displays summaries including archived receipt rows, “Load more” requests the next cursor and appends without duplicates, answer link opens detail, detail renders all receipt sections and timestamp/hash, raw JSON download contains the selected receipt, and loading/empty/error/404 states are clear.
- [ ] **Step 2: Run the focused UI tests and verify the routes/entry are absent.**

Run: `cd frontend && npm run test:e2e -- tests/e2e/mnemos-evidence-receipts.spec.ts`

Expected: FAIL because receipt pages and routes do not exist.

- [ ] **Step 3: Build the receipt history/detail view.** Render query preview, model, retrieval status, source count, creation time, and receipt ID in history. Detail renders question, answer, citations/evidence refs, model/generation/runtime, retrieval status, and content hash. Use explicit loading, empty, API error, and not-found states. Load-more preserves current rows and cursor.
- [ ] **Step 4: Implement authenticated raw JSON download and wire routes/navigation.** Add `downloadMnemosEvidenceReceipt(receiptId: string): Promise<void>` to `frontend/src/api/chat.ts`. Fetch receipt JSON using the API transport (which adds the Bearer token), serialize it as formatted JSON into a Blob, and trigger a download with the receipt ID as filename. Never use an unauthenticated `window.open` to the API route.

```ts
const receipt = await get<MnemosEvidenceReceipt>(`/mnemos/evidence-receipts/${encodeURIComponent(receiptId)}`);
const url = URL.createObjectURL(new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" }));
const anchor = document.createElement("a");
anchor.href = url;
anchor.download = `${receipt.receipt_id}.json`;
anchor.click();
URL.revokeObjectURL(url);
```
- [ ] **Step 5: Run the full receipt UI suite, frontend API tests, typecheck, and production build.**

Run: `cd frontend && npm run test:e2e -- tests/e2e/mnemos-evidence-receipts.spec.ts`

Run: `cd frontend && npm run test:api`

Run: `cd frontend && npx tsc --noEmit`

Run: `cd frontend && npm run build`

Expected: PASS; global history, direct answer navigation, paginated detail experience, and authorized JSON export work.

- [ ] **Step 6: Commit receipt history/detail UI.**

```bash
git add frontend/src/pages/MnemosReceiptsPage.tsx frontend/src/App.tsx frontend/src/api/chat.ts frontend/tests/e2e/mnemos-evidence-receipts.spec.ts
git commit -m "feat: add MNEMOS evidence receipt history UI"
```

### Task 6: End-to-end persistence and regression verification

**Files:**
- Test: `backend/app/tests/test_api_chat_comparisons.py`
- Test: `backend/app/tests/test_api_mnemos_evidence_receipts.py`
- Test: `frontend/tests/e2e/mnemos-evidence-receipts.spec.ts`

**Interfaces:** Uses the contracts delivered by Tasks 1–5; no new public API.

- [ ] **Step 1: Add a persistence-boundary test** that creates a completed MNEMOS receipt in a temporary configured receipt directory, constructs a fresh receipt service/app instance pointed at the same directory, and verifies history and detail still return the same ID/content/hash. Do not use or mutate the live Docker volume.
- [ ] **Step 2: Run all receipt and chat lifecycle backend tests.**

Run: `pytest backend/app/tests/test_mnemos_evidence_receipts.py backend/app/tests/test_api_chat_comparisons.py backend/app/tests/test_api_chat_mnemos.py backend/app/tests/test_api_mnemos_evidence_receipts.py -q`

Expected: PASS.

- [ ] **Step 3: Run existing MNEMOS comparison and new receipt browser tests.**

Run: `cd frontend && npm run test:e2e -- tests/e2e/mnemos-chat-receipt-link.spec.ts tests/e2e/mnemos-evidence-receipts.spec.ts`

Expected: PASS, including existing chat lifecycle and resize coverage.

- [ ] **Step 4: Run final repository checks and inspect the patch.**

Run: `git diff --check`

Run: `cd frontend && npx tsc --noEmit && npm run build`

Expected: PASS. Confirm `git status` contains only intended receipt changes plus any pre-existing drawer-resize edits; do not stage or commit unrelated changes.

## Coverage Map

- Receipt schema, hash, atomic writes, path safety, overflow archive and complete cursor pagination: Task 1.
- JSON/SSE generation, stable IDs, replay behavior, failed/pending/baseline exclusion, write outage: Task 2.
- Authenticated routes, paging contract, malformed inputs and missing files: Task 3.
- Immediate per-answer link and baseline absence: Task 4.
- Navigable history/detail, pagination UX, authenticated JSON download: Task 5.
- Persistence across fresh service/app construction and existing regression coverage: Task 6.
