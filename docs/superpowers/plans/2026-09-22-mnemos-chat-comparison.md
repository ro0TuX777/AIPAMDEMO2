# MNEMOS Chat Comparison Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let customers compare normal job chat with a saved MNEMOS-augmented chat that recalls analyst-confirmed findings from other jobs without compromising the existing chat's evidence boundary.

**Architecture:** Add a conversation-group model that owns one baseline conversation and zero or more MNEMOS branches. The backend owns snapshot/copy cutoffs, retrieves and validates historical MNEMOS evidence only for MNEMOS branches, and emits the same provenance through JSON and SSE. The frontend coordinates the baseline panel and a responsive MNEMOS drawer, including draft-only Copy to MNEMOS actions.

**Tech Stack:** FastAPI, SQLAlchemy/Alembic with SQLite, Pydantic, React 18, TypeScript, Tailwind, SSE, pytest, Node test runner, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-22-mnemos-chat-comparison-design.md`

## Global Constraints

- Baseline chat must use current-job evidence only and must make no MNEMOS search call.
- MNEMOS retrieval searches analyst-confirmed historical findings across the instance, excluding the active job; a historical similarity is supporting context, never proof about the current job.
- A source must be revalidated as an existing, currently confirmed finding before it is passed to the LLM or returned to the UI.
- MNEMOS timeouts, disabled configuration, malformed responses, and authentication failures are retryable MNEMOS errors; never silently fall back to baseline chat.
- The model and generation configuration must be identical for the two panes and be persisted with the answer metadata.
- The server validates all conversation ownership, source-message cutoffs, request IDs, and history construction. The client never supplies raw history.
- Existing conversations remain usable after migration. Hiding the MNEMOS pane never deletes data; deleting a root deletes its paired MNEMOS branches transactionally.
- Preserve unrelated dirty-worktree changes, especially the ongoing `frontend/src/api/` split.

---

## Target file structure

| Path | Responsibility |
| --- | --- |
| `backend/alembic/versions/<revision>_add_chat_comparison_groups.py` | Adds groups, branches, request idempotency, message sequence, and response metadata without rewriting existing conversations. |
| `backend/app/models/chat.py` | ORM representation of comparison groups, conversation mode/provenance, message ordering, and saved response metadata. |
| `backend/app/schemas/chat.py` | Additive request/response/history/citation models for mode, source links, retrieval status, and comparison creation. |
| `backend/app/services/chat_comparisons.py` | Validates and creates groups/branches, snapshots history by message ID, and provides stable prompt history. |
| `backend/app/services/mnemos_chat_retrieval.py` | Async MNEMOS search, hit validation against the database, bounded historical context, and source citation construction. |
| `backend/app/forensic_memory.py` | Uses stable source IDs when indexing confirmed findings and provides idempotent reconciliation input. |
| `backend/app/cli.py` | Adds an explicit operator command that reconciles confirmed findings into MNEMOS. |
| `backend/app/api/chat.py` | Routes requests through comparison preparation, mode-specific prompts, retrieval status, SSE metadata, and idempotent turn persistence. |
| `frontend/src/api/types.ts`, `frontend/src/api/chat.ts` | Typed comparison contracts and creation/restore calls. |
| `frontend/src/components/ChatPanel.tsx` | Reusable, controlled single conversation renderer that exposes Copy to MNEMOS events and has no automatic cross-mode fallback. |
| `frontend/src/components/MnemosChatDrawer.tsx` | Drawer and branch selector, source status, retry, and draft handling. |
| `frontend/src/pages/ChatPage.tsx` | Owns paired conversation state, first-open snapshot, restore, and responsive layout. |

### Task 1: Make confirmed-finding MNEMOS records stable and retrievable

**Files:**
- Create: `backend/app/services/mnemos_chat_retrieval.py`
- Modify: `backend/app/forensic_memory.py`
- Modify: `backend/app/mnemos_boundary.py`
- Modify: `backend/app/cli.py`
- Modify: `backend/app/tests/test_mnemos_boundary.py`
- Create: `backend/app/tests/test_mnemos_chat_retrieval.py`

**Interfaces:**
- Consumes: `MnemosBoundaryClient.search(query, *, top_k, filters) -> list[dict] | None`, `Finding`, `Job`, and a SQLAlchemy `Session`.
- Produces: `async def retrieve_historical_findings(db: Session, *, current_job_id: str, query: str, top_k: int = 5) -> MnemosRetrievalResult` where `status` is `"used" | "no_matches" | "unavailable" | "error"` and `citations` have `type="historical_finding"`, `id`, `snippet`, `source_job_id`, `source_project_id`, and `href`.
- Produces: `def mnemos_document_for_finding(finding: Finding, *, project_id: str | None) -> dict[str, Any]` with `id == f"finding:{finding.job_id}:{finding.finding_id}"`.

- [ ] **Step 1: Write failing boundary and retrieval tests**

```python
def test_search_rejects_healthy_payload_without_a_results_list() -> None:
    client = MnemosBoundaryClient("http://mnemos", request=lambda *a, **k: _Response({"status": "healthy"}))
    assert client.search("confirmed C2") is None


def test_retrieval_excludes_current_or_unconfirmed_or_missing_sources(session, monkeypatch) -> None:
    monkeypatch.setattr(retrieval, "get_mnemos_client", lambda: FakeMnemos([
        hit("current", "job-current", "F-1"),
        hit("stale", "job-old", "F-stale"),
        hit("confirmed", "job-old", "F-2"),
    ]))
    result = asyncio.run(retrieval.retrieve_historical_findings(session, current_job_id="job-current", query="C2"))
    assert result.status == "used"
    assert [citation.id for citation in result.citations] == ["F-2"]
    assert result.citations[0].href == "/jobs/job-old/findings/F-2"
```

- [ ] **Step 2: Run the focused tests to verify the new contract fails**

Run: `pytest backend/app/tests/test_mnemos_boundary.py backend/app/tests/test_mnemos_chat_retrieval.py -q`

Expected: FAIL because healthy malformed results are treated as empty and `mnemos_chat_retrieval` does not exist.

- [ ] **Step 3: Implement the boundary distinction and stable index document**

```python
@dataclass(frozen=True)
class MnemosRetrievalResult:
    status: Literal["used", "no_matches", "unavailable", "error"]
    context: str
    citations: list[HistoricalFindingCitation]


def mnemos_document_for_finding(finding: Finding, *, project_id: str | None) -> dict[str, Any]:
    return {
        "id": f"finding:{finding.job_id}:{finding.finding_id}",
        "content": finding_to_text(finding),
        "source": "aipam.forensic_memory",
        "neuro_tags": ["forensic_finding", "confirmed"],
        "metadata": {
            "collection": DEFAULT_COLLECTION,
            "job_id": finding.job_id,
            "finding_id": finding.finding_id,
            "project_id": project_id or "",
            "content_sha256": finding_content_sha256(finding),
        },
    }
```

Require a healthy response with a list-valued `results`; return `None` for a malformed payload so caller code can surface an error. Offload the existing synchronous boundary call with `asyncio.to_thread`. Resolve each hit by `(job_id, finding_id)`, check `analyst_status == "confirmed"`, exclude `current_job_id`, deduplicate by the stable pair, cap both number of records and total prompt characters, and return `no_matches` if nothing eligible remains. Do not call the legacy local Chroma fallback in this service.

Project data is not present on the V2 `Job` model. Derive it when a BlueScrub lineage exists; otherwise store and display `source_project_id=None` as “No project assigned.” This preserves every cross-job source without fabricating a project relationship.

- [ ] **Step 4: Add operator reconciliation**

Add `aipam reconcile-mnemos-findings` to enumerate all database `Finding` rows with `analyst_status == "confirmed"`, derive nullable project lineage, construct stable documents, and upsert in bounded batches. Print only counts: discovered, indexed, skipped, and failed. Return non-zero if MNEMOS is unavailable or a batch fails. Re-running must send the same IDs and not create duplicates.

- [ ] **Step 5: Run focused tests to verify the contract passes**

Run: `pytest backend/app/tests/test_mnemos_boundary.py backend/app/tests/test_mnemos_chat_retrieval.py -q`

Expected: PASS, including unavailable versus no-match, historical-source validation, stable metadata, and idempotent reconciliation batching.

- [ ] **Step 6: Commit the focused retrieval work**

```powershell
git add backend/app/mnemos_boundary.py backend/app/forensic_memory.py backend/app/services/mnemos_chat_retrieval.py backend/app/cli.py backend/app/tests/test_mnemos_boundary.py backend/app/tests/test_mnemos_chat_retrieval.py
git commit -m "feat: add validated mnemos chat retrieval"
```

### Task 2: Persist paired conversations, immutable provenance, and idempotent requests

**Files:**
- Create: `backend/alembic/versions/<revision>_add_chat_comparison_groups.py`
- Modify: `backend/app/models/chat.py`
- Modify: `backend/app/models/__init__.py`
- Modify: `backend/app/schemas/chat.py`
- Create: `backend/app/services/chat_comparisons.py`
- Create: `backend/app/tests/test_chat_comparisons.py`

**Interfaces:**
- Consumes: a root `ChatConversation`, `ChatMessage.id`, and `ChatMessage.sequence`.
- Produces: `create_mnemos_snapshot(db, *, root_conversation_id: str) -> ChatComparisonBranch`; `create_mnemos_copy_branch(db, *, root_conversation_id: str, source_message_id: str) -> ChatComparisonBranch`; and `prompt_history_for_branch(db, branch_id) -> list[dict[str, str]]`.
- Produces: `ChatRequestBody.mode: Literal["baseline", "mnemos"] = "baseline"`, `request_id: str | None`, and `comparison_source_message_id: str | None`.

- [ ] **Step 1: Write failing persistence and history-isolation tests**

```python
def test_copy_branch_contains_only_messages_before_the_source_question(session) -> None:
    root, question, answer, later = seed_baseline_turns(session)
    branch = create_mnemos_copy_branch(session, root_conversation_id=root.id, source_message_id=question.id)
    assert prompt_history_for_branch(session, branch.id) == []
    assert branch.source_message_id == question.id
    assert branch.history_cutoff_sequence == question.sequence - 1


def test_copy_source_must_be_a_user_message_in_the_selected_root(session) -> None:
    root, _question, answer, _later = seed_baseline_turns(session)
    with pytest.raises(ComparisonValidationError, match="user message"):
        create_mnemos_copy_branch(session, root_conversation_id=root.id, source_message_id=answer.id)
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `pytest backend/app/tests/test_chat_comparisons.py -q`

Expected: FAIL because groups, sequences, and comparison helpers do not exist.

- [ ] **Step 3: Add the migration and ORM model**

Create `chat_comparison_groups` with `id`, `job_id`, `root_conversation_id`, `title`, `active_branch_id`, `created_at`, and `updated_at`. Add `comparison_group_id`, immutable `mode`, `parent_branch_id`, `source_message_id`, `history_cutoff_sequence`, and `request_id` to `chat_conversations`; add non-null `sequence` and nullable `metadata_json` to `chat_messages`. Backfill every existing conversation as its own baseline group, preserve its title, set sequences deterministically by `(created_at, id)`, and assign `mode="baseline"`. Add unique indexes for `(comparison_group_id, mode)` only for the single baseline root and `(conversation_id, request_id)` where request ID is present. Include reversible downgrade operations.

`ChatComparisonBranch` is a dedicated model for branch display state: `id`, `group_id`, `conversation_id`, `label`, `source_message_id`, `history_cutoff_sequence`, `created_at`, and `updated_at`. A snapshot branch has a cutoff at the latest completed root sequence. A copied branch has a cutoff immediately before the source user question. Persist the copied prompt only when the user submits; draft text stays in the browser.

- [ ] **Step 4: Implement the server-owned comparison service**

Validate job ownership, root mode, and completed source message. Create the first snapshot exactly once per root. Create a distinct copy branch only when the user submits an explicit copy, preserving earlier branches. Build model history from the baseline root up to `history_cutoff_sequence` plus that branch's own completed messages, never from post-cutoff root messages or another branch. Order by `sequence`, not timestamps. Use the exact same cutoff history for summary generation to prevent leakage through `_summarize_older_messages`.

- [ ] **Step 5: Run focused tests to verify it passes**

Run: `pytest backend/app/tests/test_chat_comparisons.py -q`

Expected: PASS for snapshots, copy validation, no-answer leakage, branch preservation, migration backfill, and duplicate request identity.

- [ ] **Step 6: Commit the persistence work**

```powershell
git add backend/alembic/versions backend/app/models/chat.py backend/app/models/__init__.py backend/app/schemas/chat.py backend/app/services/chat_comparisons.py backend/app/tests/test_chat_comparisons.py
git commit -m "feat: persist paired mnemos chat conversations"
```

### Task 3: Make chat preparation mode-aware with honest MNEMOS result states

**Files:**
- Modify: `backend/app/api/chat.py`
- Modify: `backend/app/services/chat_comparisons.py`
- Modify: `backend/app/services/mnemos_chat_retrieval.py`
- Modify: `backend/app/services/chat_citations.py`
- Modify: `backend/app/tests/test_api_chat_grounding.py`
- Create: `backend/app/tests/test_api_chat_mnemos.py`

**Interfaces:**
- Consumes: `PreparedChatTurn` with `mode`, server-resolved history, current-job context, and `MnemosRetrievalResult`.
- Produces: `async def prepare_chat_turn(...) -> PreparedChatTurn` and `ChatResponseBody.retrieval_status`, `model_id`, `generation`, and typed historical citations.

- [ ] **Step 1: Write failing baseline-isolation and MNEMOS-grounding tests**

```python
def test_baseline_prepare_never_calls_mnemos(monkeypatch, session) -> None:
    monkeypatch.setattr(chat, "retrieve_historical_findings", lambda **_: pytest.fail("unexpected MNEMOS call"))
    prepared = asyncio.run(chat.prepare_chat_turn(session, job_id="job-1", body=ChatRequestBody(message="What happened?")))
    assert prepared.retrieval_status is None


def test_mnemos_prompt_labels_historical_context_as_non_current_evidence(monkeypatch, session) -> None:
    monkeypatch.setattr(chat, "retrieve_historical_findings", lambda **_: used_result("Historical F-2"))
    prepared = asyncio.run(chat.prepare_chat_turn(session, job_id="job-1", body=ChatRequestBody(message="Is this C2?", mode="mnemos")))
    system = prepared.messages[0]["content"]
    assert "HISTORICAL CONFIRMED FINDINGS" in system
    assert "not proof about the current job" in system
    assert prepared.citations[0].type == "historical_finding"
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `pytest backend/app/tests/test_api_chat_grounding.py backend/app/tests/test_api_chat_mnemos.py -q`

Expected: FAIL because preparation is not mode-aware and response metadata is absent.

- [ ] **Step 3: Extract shared preparation and update the prompt policy**

Refactor the duplicated JSON/SSE setup into `prepare_chat_turn`. Keep current-job sensor, scoped bundle, structured retrieval, and job-scoped KB construction unchanged for both modes. Baseline continues to use the current `SYSTEM_PROMPT`. MNEMOS mode adds an explicit, bounded block:

```text
=== HISTORICAL CONFIRMED FINDINGS (supporting context only) ===
These findings came from earlier jobs. They may suggest a similarity, but are not evidence that the same event occurred in this job. State the historical source when discussing it. Do not infer current-job facts from it without current-job support.
=== END HISTORICAL CONFIRMED FINDINGS ===
```

For `used`, include validated citations and context. For `no_matches`, include an instruction to state that no relevant historical confirmed findings were found. For `unavailable` or `error`, raise `MnemosUnavailableError` before any LLM request. Preserve the stricter current-job citation checks; do not let historical source text satisfy a current-job assertion. Extend citation rendering so historical entries explicitly show project/job/finding and their link metadata.

- [ ] **Step 4: Run focused tests to verify they pass**

Run: `pytest backend/app/tests/test_api_chat_grounding.py backend/app/tests/test_api_chat_mnemos.py -q`

Expected: PASS for baseline isolation, no-match text, unavailable failure, historical labels, and existing anti-hallucination behavior.

- [ ] **Step 5: Commit the mode-aware preparation**

```powershell
git add backend/app/api/chat.py backend/app/services/chat_comparisons.py backend/app/services/mnemos_chat_retrieval.py backend/app/services/chat_citations.py backend/app/tests/test_api_chat_grounding.py backend/app/tests/test_api_chat_mnemos.py
git commit -m "feat: prepare mnemos chat with historical evidence"
```

### Task 4: Add paired-chat API and safe SSE/JSON turn semantics

**Files:**
- Modify: `backend/app/api/chat.py`
- Modify: `backend/app/schemas/chat.py`
- Modify: `backend/app/services/chat_comparisons.py`
- Create: `backend/app/tests/test_api_chat_comparisons.py`

**Interfaces:**
- Produces: `POST /jobs/{job_id}/chat/comparisons` to create/restore a snapshot; `GET /jobs/{job_id}/chat/comparisons/{group_id}` to restore group, branches, and active branch; `POST /jobs/{job_id}/chat/comparisons/{group_id}/branches` to submit a copied question branch.
- Produces: SSE `meta` payload containing `conversation_id`, `branch_id`, `retrieval_status`, `citations`, `model_id`, and `generation`.

- [ ] **Step 1: Write failing endpoint and stream tests**

```python
def test_opening_mnemos_twice_restores_one_snapshot(client) -> None:
    first = client.post("/jobs/job-1/chat/comparisons", json={"root_conversation_id": "root-1"})
    second = client.post("/jobs/job-1/chat/comparisons", json={"root_conversation_id": "root-1"})
    assert first.json()["snapshot_branch_id"] == second.json()["snapshot_branch_id"]


def test_mnemos_stream_outage_returns_retryable_error_without_llm(client, monkeypatch) -> None:
    monkeypatch.setattr(chat, "retrieve_historical_findings", lambda **_: unavailable_result())
    response = client.post("/jobs/job-1/chat/stream", json={"message": "compare", "mode": "mnemos", "request_id": "req-1"})
    assert response.status_code == 503
    assert response.json()["code"] == "MNEMOS_UNAVAILABLE"
```

- [ ] **Step 2: Run endpoint tests to verify they fail**

Run: `pytest backend/app/tests/test_api_chat_comparisons.py -q`

Expected: FAIL because comparison endpoints, metadata, and explicit MNEMOS errors do not exist.

- [ ] **Step 3: Implement API contracts and idempotency**

Use a 503 structured error with code `MNEMOS_UNAVAILABLE` for unavailable/failed MNEMOS preparation; return no assistant message and make no LLM call. Do not encode an outage as an assistant answer. Make initial comparison creation idempotent by root ID. Require a UUID `request_id` for new UI requests; on a duplicate `(conversation_id, request_id)`, return the persisted turn/status rather than inserting another user message. Persist `retrieval_status`, source citations, model ID, temperature `0.3`, and relevant runtime configuration into the assistant message metadata before emitting terminal success.

Do not use the current stream-to-JSON automatic fallback for any request whose stream obtained a server response or whose mode is MNEMOS. The client may retry only through an explicit user action with the same request ID. A disconnect leaves the detached producer running; the restore endpoint must show the persisted completed answer. Keep JSON and SSE paths on the same `prepare_chat_turn` and persistence helper.

The list endpoint returns comparison roots only. Rename updates group display title. Delete root deletes the group, branches, conversations, and messages in one transaction after existing ownership validation.

- [ ] **Step 4: Run endpoint tests to verify they pass**

Run: `pytest backend/app/tests/test_api_chat_comparisons.py backend/app/tests/test_api_chat_mnemos.py -q`

Expected: PASS for snapshot idempotency, branch creation, source ownership validation, no silent fallback, duplicate request handling, restored metadata, and transactional deletion.

- [ ] **Step 5: Commit the API work**

```powershell
git add backend/app/api/chat.py backend/app/schemas/chat.py backend/app/services/chat_comparisons.py backend/app/tests/test_api_chat_comparisons.py
git commit -m "feat: add paired mnemos chat api"
```

### Task 5: Refactor the frontend chat panel into a controlled, typed conversation view

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/chat.ts`
- Modify: `frontend/src/components/ChatPanel.tsx`
- Create: `frontend/tests/api/chat-comparisons.test.mjs`
- Create: `frontend/src/components/chatTypes.ts`

**Interfaces:**
- Produces: `ChatPanelProps` with `conversation`, `mode`, `onCopyToMnemos(messageId, content)`, `onRetry()`, and `onConversationChanged()`; it must not independently select the most recent conversation.
- Produces: `ChatComparisonGroup`, `ChatComparisonBranch`, `HistoricalFindingCitation`, and `MnemosRetrievalStatus` TypeScript interfaces matching the API schema.

- [ ] **Step 1: Write failing API-contract and panel behavior tests**

```javascript
test("create comparison posts only the root conversation id", async () => {
  await chatApi.openComparison("job-1", "root-1");
  assert.deepEqual(calls[0], { method: "POST", path: "/jobs/job-1/chat/comparisons", body: { root_conversation_id: "root-1" } });
});
```

Add a component-level test using the repository's chosen React test setup, or introduce a narrowly scoped Playwright component-equivalent page test if no React test runner exists. It must assert that Copy to MNEMOS invokes the callback and does not call the chat endpoint.

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `npm --prefix frontend run test:api -- --test-name-pattern="comparison"`

Expected: FAIL because the API method and typed contracts do not exist.

- [ ] **Step 3: Implement typed contracts and controlled panel behavior**

Replace `messages: any[]` with a typed message model containing `id`, `sequence`, citations, retrieval status, and saved metadata. Accept conversation identity/history from `ChatPage`; keep only display input, loading, and scroll state inside `ChatPanel`. Make an original user message render an accessible `Copy to MNEMOS` button. Do not render it in MNEMOS mode. Preserve current normal-chat rendering and context hints.

Generate a UUID request ID before send, include it in stream/JSON payloads, and retain it until the terminal response. A stream transport failure before any HTTP response may retain baseline fallback behavior only if the request is baseline; MNEMOS errors remain visible in the MNEMOS panel with `Retry MNEMOS`. Parse terminal SSE meta metadata into the matching assistant message rather than treating it as content.

- [ ] **Step 4: Run frontend API checks and build**

Run: `npm --prefix frontend run test:api`

Expected: PASS, including existing API tests and comparison serialization.

Run: `npm --prefix frontend run build`

Expected: PASS with no TypeScript errors.

- [ ] **Step 5: Commit the frontend conversation foundation**

```powershell
git add frontend/src/api/types.ts frontend/src/api/chat.ts frontend/src/components/ChatPanel.tsx frontend/src/components/chatTypes.ts frontend/tests/api/chat-comparisons.test.mjs
git commit -m "feat: add typed paired chat client"
```

### Task 6: Build the MNEMOS drawer and paired-chat page coordination

**Files:**
- Create: `frontend/src/components/MnemosChatDrawer.tsx`
- Modify: `frontend/src/pages/ChatPage.tsx`
- Modify: `frontend/src/components/ChatPanel.tsx`
- Create: `frontend/tests/e2e/mnemos-chat-comparison.spec.ts`

**Interfaces:**
- Consumes: `ChatComparisonGroup`, `ChatComparisonBranch`, and controlled `ChatPanel` callbacks from Task 5.
- Produces: a customer-visible MNEMOS toggle, responsive drawer, branch selector, historical source links, no-match state, and retryable unavailable state.

- [ ] **Step 1: Write failing end-to-end scenarios**

```typescript
test("copy opens an editable MNEMOS draft without sending", async ({ page }) => {
  await page.getByRole("button", { name: "Copy to MNEMOS" }).first().click();
  await expect(page.getByRole("complementary", { name: "MNEMOS comparison" })).toBeVisible();
  await expect(page.getByLabel("MNEMOS message")).toHaveValue("Was this C2 activity?");
  await expect(page.getByText("Historical confirmed findings")).toHaveCount(0);
});

test("unavailable MNEMOS exposes retry and no baseline answer", async ({ page }) => {
  await page.getByRole("button", { name: "Send to MNEMOS" }).click();
  await expect(page.getByText("MNEMOS is unavailable. Try again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toBeVisible();
});
```

- [ ] **Step 2: Run the scenarios to verify they fail**

Run: `npm --prefix frontend run test:e2e -- mnemos-chat-comparison.spec.ts`

Expected: FAIL because no MNEMOS toggle, drawer, or copy interaction exists.

- [ ] **Step 3: Implement coordinated drawer behavior**

`ChatPage` loads comparison roots as the user selects baseline history. Toggling on calls `openComparison`; toggling off unmounts/hides only the drawer while group IDs and unsent draft persist in page state. On reload, restore the group, its snapshot branch, active branch, messages, metadata, and citations. When Copy to MNEMOS is clicked, request/create the copy branch only on submit, set an editable draft and source label, and do not alter existing branch selection until submit succeeds.

On desktop show baseline chat beside a sliding pane. On narrow screens render an accessible drawer/view switch labelled “MNEMOS comparison,” with focus return to the toggle on close. Show three distinct states: “Historical confirmed findings used,” “No relevant historical confirmed findings found,” and “MNEMOS is unavailable. Try again.” Historical sources link to the source finding route and show job plus nullable project label. Never overwrite a non-empty user draft; require the user to choose whether to replace it before applying another copied prompt.

- [ ] **Step 4: Run targeted UI verification**

Run: `npm --prefix frontend run build`

Expected: PASS.

Run: `npm --prefix frontend run test:e2e -- mnemos-chat-comparison.spec.ts`

Expected: PASS for first snapshot, copy-without-send, fair history cutoff, branch preservation, reload restoration, no-match, unavailable/retry, source link, and narrow viewport drawer behavior.

- [ ] **Step 5: Commit the UI experience**

```powershell
git add frontend/src/components/MnemosChatDrawer.tsx frontend/src/components/ChatPanel.tsx frontend/src/pages/ChatPage.tsx frontend/tests/e2e/mnemos-chat-comparison.spec.ts
git commit -m "feat: add mnemos chat comparison drawer"
```

### Task 7: Verify migration, end-to-end evidence, and operational documentation

**Files:**
- Modify: `mnemos-service/docs/chat_integration_evidence_contract.md`
- Modify: `README.md` or the established deployment operations document if it already owns runtime configuration
- Create: `backend/app/tests/test_chat_comparison_migration.py`
- Modify: `docs/superpowers/specs/2026-09-22-mnemos-chat-comparison-design.md` only if implementation discoveries require an approved design correction

**Interfaces:**
- Consumes: every API and UI contract from Tasks 1–6.
- Produces: a reproducible local operator procedure for MNEMOS health, reconciliation, comparison testing, and expected evidence labels.

- [ ] **Step 1: Write a migration regression test**

```python
def test_upgrade_backfills_a_legacy_conversation_as_a_baseline_group(alembic_db) -> None:
    seed_legacy_conversation(alembic_db, conversation_id="legacy-1")
    upgrade_to_head(alembic_db)
    group = fetch_group(alembic_db, root_conversation_id="legacy-1")
    assert group is not None
    assert fetch_conversation(alembic_db, "legacy-1").mode == "baseline"
    assert message_sequences(alembic_db, "legacy-1") == [1, 2]
```

- [ ] **Step 2: Run the migration test to verify it fails before applying the migration implementation**

Run: `pytest backend/app/tests/test_chat_comparison_migration.py -q`

Expected: FAIL on the unmodified schema; after Task 2 implementation it becomes a permanent regression test and must PASS.

- [ ] **Step 3: Document the operator and customer verification path**

Document the exact safe sequence: confirm the backend reports MNEMOS enabled, run `aipam reconcile-mnemos-findings`, confirm indexed count, create two completed jobs with a confirmed historical finding, ask a baseline question, open MNEMOS, copy the question, submit, inspect distinct historical citation, reload, and verify both conversations remain. Document that a no-match is healthy while an unavailable service is an error, and that historical findings do not establish current-job facts.

- [ ] **Step 4: Run complete verification**

Run: `pytest backend/app/tests/test_mnemos_boundary.py backend/app/tests/test_mnemos_chat_retrieval.py backend/app/tests/test_chat_comparisons.py backend/app/tests/test_api_chat_grounding.py backend/app/tests/test_api_chat_mnemos.py backend/app/tests/test_api_chat_comparisons.py backend/app/tests/test_chat_comparison_migration.py -q`

Expected: PASS.

Run: `npm --prefix frontend run test:api; npm --prefix frontend run build; npm --prefix frontend run test:e2e -- mnemos-chat-comparison.spec.ts`

Expected: PASS.

Run the repository's required DAWN release verification after these focused checks, and record its exact command/output in the evidence receipt. If the suite is unavailable in the local environment, record the blocking dependency and do not claim a release audit passed.

- [ ] **Step 5: Commit verification and documentation**

```powershell
git add backend/app/tests/test_chat_comparison_migration.py mnemos-service/docs/chat_integration_evidence_contract.md README.md
git commit -m "docs: add mnemos chat comparison verification"
```

## Plan self-review

- Spec coverage: Tasks 1 and 3 cover cross-job confirmed-only retrieval, boundaries, sources, and no-match/outage semantics. Tasks 2 and 4 cover persistence, snapshots, copy cutoffs, separate branches, reload, idempotency, and deletion. Tasks 5 and 6 cover the comparison UI and responsive behavior. Task 7 covers migrations, reconciliation, and operational evidence.
- Placeholder scan: no `TBD`, `TODO`, or deferred implementation markers are present.
- Type consistency: all backend chat preparation uses `MnemosRetrievalResult`; all comparison sources use stable `ChatMessage.id` plus sequence cutoffs; frontend API contracts use `ChatComparisonGroup`, `ChatComparisonBranch`, and `HistoricalFindingCitation` from Task 5.
- Scope note: V2 jobs have no universal project relationship. The implementation must expose nullable project provenance through existing BlueScrub lineage and label ordinary jobs accurately, rather than inventing project data.
