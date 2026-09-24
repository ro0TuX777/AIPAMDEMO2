import { expect, test, type Page, type Route } from "@playwright/test";

const jobId = "mnemos-receipt-link-e2e";
const now = "2026-09-22T00:00:00Z";
const msg = (id: string, sequence: number, role: string, content: string, metadata: any = null) => ({ id, sequence, role, content, citations: [], metadata, request_id: metadata?.request_id ?? null, timestamp: now });
const history = (id: string, messages: any[]) => ({ id, job_id: jobId, created_at: now, updated_at: now, messages });

async function setup(page: Page, options: { baseline?: boolean; failHistory?: boolean; jsonReceipt?: boolean } = {}) {
  const root = "root-chat";
  const group = { group_id: "group-1", job_id: jobId, root_conversation_id: root, title: null, snapshot_branch_id: "snapshot", active_branch_id: "snapshot", conversation_id: "branch-chat", created_at: now, updated_at: now,
    branches: [{ id: "snapshot", conversation_id: "branch-chat", label: "MNEMOS snapshot", source_message_id: null, request_id: null, history_cutoff_sequence: 0, inherited_root_conversation_id: root, inherited_cutoff_sequence: 0, inherited_messages: [], messages: [], created_at: now, updated_at: now }] };
  const messages = [msg("q1", 1, "user", "Previous question"), msg("a1", 2, "assistant", "Previous answer", options.baseline ? { status: "completed", receipt_id: "receipt-should-not-link" } : null)];
  const calls = { history: 0 };
  const json = (route: Route, data: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(data) });
  await page.route("**/api/v1/**", async route => {
    const req = route.request(); const path = new URL(req.url()).pathname.replace(`/api/v1/jobs/${jobId}`, ""); const body = req.postDataJSON();
    if (path.endsWith("/settings/setup_status")) return json(route, { model_configured: true });
    if (path === "") return json(route, { job: { job_id: jobId, status: "completed", created_at: now, stages: [], sensors: [], pcaps: [], metrics: { durations: {}, pcap_stats: {} } } });
    if (path === "/conversations") return json(route, [{ id: root, job_id: jobId, created_at: now, updated_at: now, title: root, message_count: messages.length }]);
    if (path === "/conversations/root-chat") { calls.history++; if (options.failHistory && calls.history > 1) return route.fulfill({ status: 503 }); return json(route, history(root, messages)); }
    if (path === "/chat/comparisons") return json(route, group);
    if (path === "/chat/comparisons/group-1") return json(route, group);
    if (path === "/chat/stream") {
      if (options.jsonReceipt) return route.fulfill({ contentType: "text/event-stream", body: `data: ${JSON.stringify({ type: "meta", conversation_id: "branch-chat", request_id: body.request_id, status: "pending", citations: [] })}\n\n` });
      const conversationId = body.conversation_id ?? "branch-chat";
      const receiptId = options.baseline ? undefined : "receipt-immediate-123";
      const user = msg("user-new", 1, "user", body.message, { request_id: body.request_id });
      const assistant = msg("assistant-new", 2, "assistant", "Completed MNEMOS answer", { request_id: body.request_id, status: "completed", receipt_id: receiptId });
      messages.push(user, assistant);
      const meta = { type: "meta", conversation_id: conversationId, request_id: body.request_id, branch_id: "snapshot", status: "completed", retrieval_status: "no_matches", citations: [], ...(receiptId ? { receipt_id: receiptId } : {}) };
      return route.fulfill({ contentType: "text/event-stream", body: `data: ${JSON.stringify({ type: "token", content: "Completed MNEMOS answer" })}\n\ndata: ${JSON.stringify(meta)}\n\ndata: [DONE]\n\n` });
    }
    if (path === "/chat") return json(route, { response: "JSON MNEMOS answer", citations: [], conversation_id: "branch-chat", request_id: body.request_id, status: "completed", receipt_id: "receipt-from-json-response" });
    if (path.endsWith("/library/config")) return json(route, { admin_required: false });
    return json(route, { items: [] });
  });
  return calls;
}

async function ask(page: Page) {
  await page.goto(`/jobs/${jobId}/chat`);
  const toggle = page.getByRole("button", { name: "MNEMOS comparison", exact: true });
  await expect(toggle).toBeEnabled(); await toggle.click();
  await page.getByLabel("MNEMOS message").fill("Summarize this evidence");
  await page.getByRole("button", { name: "Send to MNEMOS" }).click();
}

test("completed MNEMOS answer links immediately using terminal receipt ID if history refresh fails", async ({ page }) => {
  await setup(page, { failHistory: true }); await ask(page);
  const link = page.getByRole("link", { name: "View evidence receipt" });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", "/mnemos/receipts/receipt-immediate-123");
});

test("baseline answer does not display a receipt link", async ({ page }) => {
  await setup(page, { baseline: true });
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByRole("button", { name: "MNEMOS comparison", exact: true })).toBeEnabled();
  await expect(page.getByText("Previous answer", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "View evidence receipt" })).toHaveCount(0);
});

test("completed MNEMOS JSON fallback links to its response receipt ID", async ({ page }) => {
  await setup(page, { jsonReceipt: true }); await ask(page);
  const link = page.getByRole("link", { name: "View evidence receipt" });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", "/mnemos/receipts/receipt-from-json-response");
});
