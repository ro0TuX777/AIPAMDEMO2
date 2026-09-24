# MNEMOS evidence receipts in AIPAM

Status: spec ready for review. Product scope and conversational design are approved; implementation has not started.

## Purpose

Give analysts a durable, inspectable record of evidence used by AIPAM's MNEMOS comparison answers. Analysts must be able to open the receipt directly from its answer and browse prior receipts later, including receipts archived after storage rollover. This feature belongs to AIPAM's local MNEMOS integration and must not modify or depend on the master MNEMOS checkout at `G:\MNEMOS`.

## Agreed product behavior

- Generate receipts for completed MNEMOS comparison answers only. Baseline AI Chat answers do not claim MNEMOS retrieval provenance and do not receive these receipts.
- Both normal JSON chat completion and SSE-stream completion paths produce equivalent receipts.
- Every generated receipt is directly accessible through a visible link on the corresponding MNEMOS answer.
- Provide a navigable receipt history and a detail view inside AIPAM's existing React application.
- History includes current receipts and receipts under `archive/`, with pagination rather than a fixed newest-100 cap.
- Persist receipts across container restarts using AIPAM's existing persistent `aipam-logs` volume. Do not mount or write to `G:\MNEMOS`.

## Reference behavior and AIPAM adaptation

The MNEMOS reference at `G:\MNEMOS` and AIPAM's local copy under `mnemos-service/` contain `write_evidence_receipt`, `_finalize_result`, and `_finalize_stream_suffix` in the OpenWebUI proxy. Completed eligible proxy responses write receipt JSON, append a receipt URL when the footer is enabled, and expose HTML and JSON receipt routes. Its Research UI lists and renders receipt history/detail from the shared receipt directory. Receipt overflow is archived, but the reference list currently scans only the active directory and returns at most 100 files.

AIPAM's chat does not use that proxy for answer generation: `backend/app/api/chat.py` owns JSON and SSE chat completion, persists assistant messages and provenance metadata, and the React `ChatPanel` renders baseline and MNEMOS conversations. Copying the standalone Flask pages would create a second, disconnected UI. Instead, AIPAM will adapt the receipt schema and lifecycle to its FastAPI persistence boundary, authenticated API conventions, chat metadata, and React routes.

## Architecture

Add a focused backend receipt service that owns receipt ID validation, canonical serialization/hash generation, atomic JSON writes, active/archive discovery, pagination, and loading. Store receipts under a configurable `MNEMOS_EVIDENCE_RECEIPT_DIR`, defaulting in the container to `/opt/aipam/logs/evidence_receipts`, which is already covered by the API container's persistent `aipam-logs` mount. The writer archives overflow without deleting it. The reader scans both the active directory and its `archive/` child and orders entries deterministically by creation time and receipt ID.

On successful completion of a MNEMOS turn, the shared completion/persistence path creates a stable receipt ID, writes one JSON artifact, and associates that ID with the assistant message's existing `metadata_json`. The receipt contains schema version, receipt ID, UTC creation time, job/conversation/assistant-message/request IDs, user query, assistant answer, model ID, generation settings/runtime provenance, retrieval status, citations, evidence references, and a SHA-256 content hash over the canonical factual receipt content. Include the receipt ID in the JSON response and in the SSE terminal metadata so the frontend can show the link as soon as generation completes; persisted history continues to expose it in message metadata. Retries and replay of a persisted turn must return the same receipt ID and must not create duplicates. No receipt is created for baseline turns, pending turns, or failed turns.

Add authenticated FastAPI endpoints for paginated receipt history and receipt detail. A cursor represents the last `(created, receipt_id)` ordering key so new receipts do not shift older pages. Reject unsafe IDs rather than allowing a path to escape the configured directory. Missing receipts return 404. A receipt-write failure is logged and must not convert an otherwise successful model response into HTTP 500; in that case the assistant message has no receipt link. The response remains available, and history only lists receipt files that were actually written.

Extend the existing React chat message rendering to show a direct internal link for assistant messages with `metadata.receipt_id`. Add an AIPAM receipt-history route in the application navigation and a detail route that presents the stored query, answer, citations/evidence refs, model/generation/retrieval metadata, timestamp, and content hash. Include a link back to history and a raw JSON download/access link for the receipt. Existing chat and MNEMOS comparison behavior remains unchanged.

## Routes and UI entry points

Proposed API routes (under `/api/v1` and protected by `verify_token`):

- `GET /mnemos/evidence-receipts?limit=50&cursor=...` returns a paginated summary and next cursor across active and archived receipt files.
- `GET /mnemos/evidence-receipts/{receipt_id}` returns the receipt JSON for detail rendering and raw access.

Proposed React routes and entry points:

- `/mnemos/receipts` shows paginated receipt history and is linked from global navigation.
- `/mnemos/receipts/:receiptId` shows the full receipt, links back to history, and offers raw JSON download through the authenticated AIPAM API client.
- Each completed MNEMOS assistant answer links directly to `/mnemos/receipts/:receiptId`.

## Failure handling and compatibility

Receipt storage is supporting evidence capture, not the model-generation transaction: filesystem failures are logged without hiding a successful response. The frontend only renders a receipt link when a persisted receipt ID is present. Invalid IDs are rejected, missing files return 404, malformed JSON files are skipped in history and return 404 in detail, and archive failures retain receipts in the active directory rather than deleting them. API authentication is required because receipts contain analyst prompts, answers, and evidence excerpts. Existing conversation/message schema remains backward compatible because the receipt reference fits the existing assistant metadata JSON.

## Verification

- Unit-test canonical receipt fields/hash, safe IDs, atomic writes, persistence path configuration, archive overflow, active-plus-archive ordering, stable cursor pagination, malformed/missing files, and no deletion on archive failure.
- API-test authenticated list/detail, pagination over archive and active files, and 404/unsafe-ID behavior.
- Chat-test successful MNEMOS JSON and SSE completions create one receipt and persist its ID in assistant metadata; replay/retry returns the same link without duplication; baseline, pending, and failed turns produce none; receipt write failure does not fail a successful answer.
- Frontend-test the receipt link on MNEMOS answers, absence on baseline answers, history/detail navigation, and raw JSON access.
- Verify a receipt is readable from the configured persistent path after the application is recreated or restarted in the test environment. Do not restart live Compose services as part of unit/browser testing.

## Acceptance criteria

1. Every successfully completed MNEMOS comparison answer through either JSON or SSE has one durable JSON receipt with a stable ID stored in its assistant-message metadata.
2. An analyst can click the receipt link on that exact MNEMOS answer immediately after streamed or non-streamed completion and reach its detail view; raw JSON can be downloaded from the detail view using the authenticated API client.
3. Receipt history in AIPAM includes active and archived receipts and supports stable pagination beyond 100 entries.
4. Receipt storage uses the AIPAM API's persistent volume and remains separate from the master MNEMOS checkout and its data.
5. Duplicate/replayed chat requests do not create duplicate receipts or change the answer-to-receipt association.
6. Baseline, pending, and failed chat turns do not get successful evidence receipts.
7. A receipt-storage outage does not turn a successful model answer into a failed chat request or expose a dead receipt link.
8. API routes require AIPAM authentication, safely validate IDs, and return a clear 404 for missing receipts.
9. Existing MNEMOS chat, standard chat, and comparison UI behavior pass their applicable regression tests.
