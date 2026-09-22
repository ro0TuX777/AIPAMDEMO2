# MNEMOS chat comparison

Status: design draft for review. Product decisions below were agreed in conversation; implementation details are proposals. No application changes have been made for this feature.

## Purpose

Let a customer compare existing post-job chat with chat augmented by MNEMOS recall of previous analyst-confirmed findings. Preserve both conversations and make historical sources visible. This is a qualitative customer comparison, not a controlled benchmark or a promise that MNEMOS always improves an answer.

## Agreed product behavior

- Existing chat is the default and continues using current-job evidence.
- A MNEMOS toggle opens a sliding pane with its own editable input and submit action.
- First opening copies the conversation so far. Subsequent messages in each pane are independent.
- MNEMOS adds previous confirmed findings across all projects in this AIPAM instance, with source project, job, and finding references.
- Historical similarities support interpretation; they are not evidence that the same event occurred in the current job.
- Both conversations persist together. Closing the pane hides it; reopening restores its saved history rather than copying again.
- Each original-chat question has Copy to MNEMOS. It fills the input without submitting. The user can edit before sending.
- A copied question uses only the original history preceding that question; the original answer and later messages are excluded.
- Use the same model and generation settings in both modes.
- MNEMOS failure produces an error and retry action. No silent ordinary-chat fallback.
- A successful search with no relevant historical matches may answer from current-job evidence, explicitly reporting no historical matches.

## Existing implementation and implications

Paths are relative to the repository root.

| Artifact | Finding and implication |
| --- | --- |
| `frontend/src/pages/ChatPage.tsx`, `frontend/src/components/ChatPanel.tsx` | Existing job chat uses a stateful panel with conversation selection and SSE. A second unmodified panel would independently select the latest conversation; explicitly coordinate paired identities instead. |
| `backend/app/models/chat.py` | Conversations and messages persist, but lack mode, pairing, and branch provenance. Extend with a migration; existing conversations become baseline. |
| `backend/app/schemas/chat.py`, `frontend/src/api/types.ts` | No mode or comparison source in the request contract. Extend additively. |
| `backend/app/api/chat.py` | Both JSON and SSE routes build current-job context. The system prompt explicitly prohibits external memory. MNEMOS needs a mode-specific evidence policy and matching citation finalization. History responses currently omit message IDs. |
| `backend/app/mnemos_boundary.py` | Existing HTTP index/search boundary can be reused. It distinguishes unavailable (`None`) from empty results, but malformed successful responses can currently become empty results; tighten response validation for comparison. |
| `backend/app/forensic_memory.py` | Confirmed findings can already be written to MNEMOS. General retrieval falls back to local memory, which is inappropriate for the explicitly labelled MNEMOS comparison. Indexed metadata lacks stable finding identity, and document IDs use list positions. |
| `docker-compose.yml` | MNEMOS and its dependencies are configured, with feature enablement defaulting to true in Compose. This is configuration evidence, not verification of the running service or indexed data. |

## Approach

Use the existing AIPAM LLM and chat endpoints, adding MNEMOS retrieval in a shared preparation service for the MNEMOS mode. Keep current-job retrieval common to both modes. Append a separately labelled historical evidence block only after successful MNEMOS retrieval and source validation.

Alternatives considered: routing the whole chat through a separate MNEMOS chat proxy would introduce another generation path and make comparison harder to interpret; changing the mode of one shared conversation would mix answers and violate independent histories. Paired conversations through the existing backend best fit the agreed behavior.

## Conversation and comparison semantics

The original conversation is the saved pair's root. Its default MNEMOS conversation stores a snapshot of completed messages at first opening and the source cutoff. Copied messages retain their original provenance and are not presented as newly generated MNEMOS answers. Do not snapshot an in-flight assistant response; allow opening after that turn completes.

Copy to MNEMOS selects a different history point from ordinary follow-up chat. Proposed resolution: each submitted copied question starts a saved comparison branch linked to the original question and root conversation. Its history contains the original prefix before that question, followed by the edited prompt and new MNEMOS answer. It excludes all existing MNEMOS answers as well as the original answer being compared. Follow-ups continue that branch. Preserve earlier branches and offer a compact selector in the pane; copying alone creates only a draft and never resets saved history.

The normal conversation selector lists roots rather than mixing baseline and MNEMOS entries. Selecting a root restores its paired pane and last active branch. Rename applies to the pair's display title. Proposed deletion behavior: the existing explicit delete action names that it deletes the original conversation and saved MNEMOS comparisons, then removes the group transactionally. Hiding the pane never deletes anything.

Backend-controlled source IDs and ordered message positions define snapshots; do not trust arbitrary client-provided history. Validate that a copied source is a user message in the selected original conversation and job. Store stable message ordering in addition to timestamps.

## Retrieval and source provenance

Search the AIPAM confirmed-findings collection across projects, excluding the current job from the historical block. Resolve hits to stable database finding IDs and recheck their current analyst status before including them. Deleted, unconfirmed, or unresolvable findings are excluded even if stale vectors remain. Preserve existing access checks when resolving sources; cross-project retrieval does not bypass access controls.

Introduce stable document identity based on source job and finding ID. Include source project/job/finding IDs and source revision or content hash in indexed metadata. Reconcile existing confirmed findings into the new representation with an idempotent indexing/backfill operation; avoid retrieving duplicate legacy records. Ensure future confirmations and content changes update the index. Read-time validation handles revoked confirmations immediately.

Each historical citation records its source IDs, a bounded evidence excerpt, and the source version used. Link to the existing finding route `/jobs/{jobId}/findings/{findingId}` and label it as historical with project/job context. Distinguish current-job citations visually and in prompt context. Source deletion later must produce an unavailable-source indication rather than a broken assumption about current validity.

Bound historical context and retrieval time. MNEMOS is reached by the backend only. The existing synchronous HTTP boundary must not block FastAPI's event loop; use an async adapter or offload calls. Retrieved text is evidence, not instructions. Chat answers are not automatically indexed as confirmed findings.

## API, persistence, and errors

Add persisted conversation mode, root relationship, snapshot/copy source, and active branch relationship. Return stable message IDs and provenance in history. Add mode and retrieval status to response metadata, and persist the same metadata with the assistant message so reloads preserve labels and sources.

Baseline requests without new fields retain their current behavior. Once created, a conversation's mode is immutable; reject a request whose mode conflicts with its conversation. Provide backend operations to create/restore the initial MNEMOS conversation and submit a comparison against a validated source message. Both SSE and JSON endpoints use the same preparation, validation, and error policy.

For MNEMOS responses distinguish `used`, `no_matches`, and `unavailable`/`error`. A malformed response, timeout, disabled service, or authentication failure must not be reported as an empty successful search. A search returning only stale or unconfirmed hits yields no eligible matches. Errors expose a concise retryable UI message without credentials or raw service internals.

Use a request identity to prevent retries or stream reconnection from creating duplicate turns or branches. The current frontend's automatic streaming-to-JSON retry needs explicit handling for MNEMOS: it must not resubmit on service failure or bypass the mode. An explicit retry reuses the same prompt and history cutoff. Failed/partial output must not become a successful answer or contaminate subsequent model history. Persist completion before signalling success; return stable turn identity early so reload can recover a running/completed turn.

Record the actual model and generation settings per response, along with retrieval outcome and source provenance. Use identical settings for the paired comparison where available. If an older baseline used different settings, disclose that mismatch rather than implying strict experimental parity. Job evidence and retrieval indexes may also evolve between submissions; the initial feature is not an immutable replay benchmark.

## UI behavior

On desktop keep the original chat readable beside the sliding pane. On narrow screens use an accessible drawer or view switch with clear mode labels. Include loading, no-match, unavailable, retry, and restored-history states. Each pane has independent input and pending state. Copying a question visibly identifies the comparison source and leaves submission under user control. Preserve unsent input when hiding the pane; do not silently overwrite an existing draft when copying another question.

## Implementation sequence

1. Validate the live MNEMOS API contract, indexed coverage, and confirmation-to-index call sites. Record sanitized evidence; the planning session has inspected source only.
2. Add conversation/message provenance, branch relationships, request identity, and backward-compatible database migration/API fields.
3. Repair stable finding indexing and provide idempotent reconciliation for existing confirmed findings.
4. Add mode-aware retrieval and citation handling shared by SSE and JSON, with explicit MNEMOS failure semantics.
5. Coordinate paired frontend state, drawer, Copy to MNEMOS, branch selection, source links, and reload/retry behavior.
6. Run focused backend/frontend checks and an end-to-end comparison with seeded confirmed historical evidence, then the applicable repository release checks before merge.

The workspace contains unrelated in-progress changes, including the frontend API module split. Build against the current module structure and preserve those changes.

## Acceptance criteria

1. MNEMOS off makes no MNEMOS chat retrieval calls and retains existing current-job grounding behavior.
2. First opening snapshots completed baseline history exactly once; later submissions remain independent.
3. Copy to MNEMOS fills an editable draft without a request to generate an answer. Submission excludes the copied question's original answer and every later message from model input, including through history summarization.
4. Copying another question preserves existing MNEMOS branches. Reload restores the pair, active branch, answers, retrieval status, and sources.
5. A relevant confirmed finding from a different project can be retrieved and cited with a working source link. Unconfirmed, revoked, deleted, and unresolvable findings cannot enter the historical context.
6. Confirmed findings predating rollout are searchable after reconciliation; repeated reconciliation is duplicate-safe.
7. Empty search answers from current-job evidence with a no-match label. Timeout, malformed service response, and service failure show error/retry without baseline fallback.
8. Retry, disconnect, and repeated submit do not duplicate turns or lose a completed answer. SSE and JSON paths have matching mode and provenance semantics.
9. Current-job assertions remain grounded in current-job evidence; historical similarity is labelled distinctly in responses and citations.
10. Existing conversation migration, root selection, rename/delete, context hints, and normal chat remain functional. Desktop and narrow-screen pane behavior is verified.

## Review focus

Product choices are settled. The additional branch-preservation behavior above is a proposed resolution of the interaction between persistent independent histories and replaying earlier questions. Review that behavior before producing the detailed implementation plan.
