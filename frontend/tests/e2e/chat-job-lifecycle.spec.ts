import { expect, test, type Page, type Route } from "@playwright/test";
import { isActiveJobStatus, isChatReadyJobStatus, isTerminalJobStatus } from "../../src/api/jobStatus";

const jobId = "chat-lifecycle-e2e";
const now = "2026-09-23T00:00:00Z";
type Status = "queued" | "running" | "canceling" | "deleting" | "completed" | "completed_with_errors" | "failed" | "canceled" | "deleted";
function gate() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; }
const message = (id: string, content: string) => ({ id, sequence: 1, role: "assistant", content, citations: [], metadata: null, request_id: null, timestamp: now });
const history = (id: string, content: string) => ({ id, job_id: jobId, created_at: now, updated_at: now, messages: [message(`${id}-answer`, content)] });
const summary = (id: string) => ({ id, job_id: jobId, title: `${id} conversation`, created_at: now, updated_at: now, message_count: 1 });
const kbDoc = (id: string) => ({ id, job_id: jobId, name: id, doc_type: "reference", description: "", chunk_count: 1, status: "ready", created_at: now, updated_at: now });
const group = (root: string) => ({ group_id: `${root}-group`, job_id: jobId, root_conversation_id: root, title: null, snapshot_branch_id: `${root}-snapshot`, active_branch_id: `${root}-snapshot`, conversation_id: `${root}-snapshot-chat`, branches: [{ id: `${root}-snapshot`, conversation_id: `${root}-snapshot-chat`, label: "MNEMOS snapshot", source_message_id: null, request_id: null, history_cutoff_sequence: 1, inherited_root_conversation_id: root, inherited_cutoff_sequence: 1, inherited_messages: [], messages: [], created_at: now, updated_at: now }], created_at: now, updated_at: now });

function job(status: Status, error_summary: string | null = null) {
  return { schema_version: "2.0", job: {
    job_id: jobId, status, error_summary, created_at: now, started_at: now,
    completed_at: status === "completed" ? now : null, execution_profile: "standard",
    priority: "normal", stages: [], sensors: [], pcaps: [], metrics: { durations: {}, pcap_stats: {} },
    heartbeat_at: now, cancel_requested_at: status === "canceling" ? now : null,
  } };
}

async function fixture(page: Page, statuses: Status[], error_summary: string | null = null) {
  const calls = { job: 0, conversations: 0, kb: 0, comparison: 0 };
  let failNextJob = false;
  await page.route("**/api/v1/**", async (route: Route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
    if (path.endsWith("/settings/setup_status")) return json({ model_configured: true });
    if (path === `/api/v1/jobs/${jobId}`) {
      calls.job++;
      if (failNextJob) { failNextJob = false; return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "Temporarily unavailable" }) }); }
      return json(job(statuses[Math.min(calls.job - 1, statuses.length - 1)], error_summary));
    }
    if (path.includes("/conversations")) {
      calls.conversations++;
      return json(path.endsWith("/conversations") ? [{ id: "root", job_id: jobId, title: "Previous chat", created_at: now, updated_at: now, message_count: 0 }] : { id: "root", job_id: jobId, created_at: now, updated_at: now, messages: [] });
    }
    if (path.includes("/kb/")) calls.kb++;
    if (path.includes("/chat/comparisons")) calls.comparison++;
    if (path.endsWith("/library/config")) return json({ admin_required: false });
    return json({ items: [] });
  });
  return { calls, failNext: () => { failNextJob = true; } };
}

test("shared status predicates distinguish active, terminal, and chat-ready states", () => {
  expect(isActiveJobStatus("queued")).toBe(true);
  expect(isActiveJobStatus("running")).toBe(true);
  expect(isActiveJobStatus("canceling")).toBe(true);
  expect(isActiveJobStatus("deleting")).toBe(true);
  expect(isActiveJobStatus("failed")).toBe(false);
  expect(isTerminalJobStatus("failed")).toBe(true);
  expect(isTerminalJobStatus("canceled")).toBe(true);
  expect(isTerminalJobStatus("deleted")).toBe(true);
  expect(isChatReadyJobStatus("failed")).toBe(false);
  expect(isChatReadyJobStatus("completed_with_errors")).toBe(true);
});

test("queued and running jobs poll into completed chat without early hydration", async ({ page }) => {
  const { calls } = await fixture(page, ["queued", "running", "completed"]);
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Analysis queued")).toBeVisible();
  expect(calls.conversations).toBe(0);
  expect(calls.kb).toBe(0);
  await expect(page.getByText("Analysis in progress")).toBeVisible({ timeout: 5_000 });
  expect(calls.conversations).toBe(0);
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible({ timeout: 5_000 });
  await expect.poll(() => calls.conversations).toBeGreaterThan(0);
  await expect.poll(() => calls.kb).toBeGreaterThan(0);
  const terminalCount = calls.job;
  await page.waitForTimeout(2_300);
  expect(calls.job).toBe(terminalCount);
});

test("canceling polls to canceled, never hydrates chat, and offers rerun navigation", async ({ page }) => {
  const { calls } = await fixture(page, ["running", "canceling", "canceled"]);
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Analysis in progress")).toBeVisible();
  await expect(page.getByText("Cancellation requested")).toBeVisible({ timeout: 5_000 });
  await expect(page.getByText("Analysis canceled")).toBeVisible({ timeout: 5_000 });
  await expect(page.getByRole("link", { name: /rerun/i })).toHaveAttribute("href", `/jobs/${jobId}`);
  expect(calls.conversations).toBe(0);
  expect(calls.kb).toBe(0);
  expect(calls.comparison).toBe(0);
  const terminalCount = calls.job;
  await page.waitForTimeout(2_300);
  expect(calls.job).toBe(terminalCount);
});

test("deleting polls to deleted without hydrating chat", async ({ page }) => {
  const { calls } = await fixture(page, ["deleting", "deleted"]);
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Job deletion in progress")).toBeVisible();
  await expect(page.getByText("Job deleted")).toBeVisible({ timeout: 5_000 });
  expect(calls.conversations).toBe(0);
  expect(calls.kb).toBe(0);
});

for (const status of ["failed", "deleted", "completed_with_errors"] as const) test(`${status} stops job polling`, async ({ page }) => {
  const { calls } = await fixture(page, [status]);
  await page.goto(`/jobs/${jobId}/chat`);
  if (status === "completed_with_errors") await expect(page.getByText(/partial analysis/i)).toBeVisible();
  else await expect(page.getByRole("status")).toBeVisible();
  const terminalCount = calls.job;
  await page.waitForTimeout(2_300);
  expect(calls.job).toBe(terminalCount);
});

test("active job continues polling while its tab is in the background", async ({ page }) => {
  const { calls } = await fixture(page, ["queued", "running", "completed"]);
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Analysis queued")).toBeVisible();
  const foreground = await page.context().newPage();
  await foreground.goto("about:blank");
  await foreground.bringToFront();
  await expect.poll(() => calls.job, { timeout: 7_000 }).toBeGreaterThanOrEqual(3);
  await page.bringToFront();
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible();
});

test("failed job shows bounded public summary and no chat dependencies", async ({ page }) => {
  const { calls } = await fixture(page, ["running", "failed"], "Analysis stopped after sensor timeout");
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Analysis failed")).toBeVisible({ timeout: 5_000 });
  await expect(page.getByText("Analysis stopped after sensor timeout")).toBeVisible();
  expect(calls.conversations).toBe(0);
  expect(calls.kb).toBe(0);
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toHaveCount(0);
});

test("failed job limits the summary shown in the browser", async ({ page }) => {
  await fixture(page, ["failed"], "A".repeat(400));
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("A".repeat(240), { exact: true })).toBeVisible();
  await expect(page.getByText("A".repeat(400), { exact: true })).toHaveCount(0);
});

test("query error can be retried before chat dependencies load", async ({ page }) => {
  const { calls, failNext } = await fixture(page, ["completed"]);
  failNext();
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Could not load job status")).toBeVisible();
  expect(calls.conversations).toBe(0);
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible();
  await expect.poll(() => calls.conversations).toBeGreaterThan(0);
});

test("opening Analysis cannot retry a failed ChatPage job query", async ({ page }) => {
  const { calls, failNext } = await fixture(page, ["completed"]);
  failNext();
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText("Could not load job status")).toBeVisible();
  await page.getByTestId("job-nav-group-analysis").click();
  await expect(page.getByText("Could not load job status")).toBeVisible();
  await page.waitForTimeout(2_300);
  expect(calls.job).toBe(1);
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible();
  expect(calls.job).toBe(2);
});

test("delayed baseline history cannot commit after readiness is revoked and the same job rehydrates", async ({ page }) => {
  const oldHistory = gate();
  const nextList = gate();
  let phase: "old" | "new" = "old";
  const calls = { list: 0, oldHistory: 0, newHistory: 0 };
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
    if (path === `/api/v1/jobs/${jobId}`) return json(job("completed"));
    if (path.endsWith("/conversations")) {
      calls.list++;
      if (phase === "new") { await nextList.promise; return json([summary("new")]); }
      return json([summary("old")]);
    }
    if (path.endsWith("/conversations/old")) { calls.oldHistory++; await oldHistory.promise; return json(history("old", "Stale answer")); }
    if (path.endsWith("/conversations/new")) { calls.newHistory++; return json(history("new", "Fresh answer")); }
    if (path.endsWith("/library/config")) return json({ admin_required: false });
    return json({ items: [] });
  });
  try {
    await page.goto("/tests/e2e/fixtures/chat-lifecycle-harness.html");
    await expect.poll(() => calls.oldHistory).toBeGreaterThan(0);
    await page.evaluate(() => window.setHarnessJobStatus("running"));
    await expect(page.getByText("Analysis in progress")).toBeVisible();
    phase = "new";
    oldHistory.release();
    await page.waitForTimeout(100);
    await page.evaluate(() => window.setHarnessJobStatus("completed"));
    await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible();
    await expect(page.getByText("Stale answer")).toHaveCount(0);
    nextList.release();
    await expect(page.getByText("Fresh answer")).toBeVisible();
    expect(calls.newHistory).toBeGreaterThan(0);
  } finally { oldHistory.release(); nextList.release(); }
});

test("delayed conversation list and KB documents cannot populate a later ready epoch", async ({ page }) => {
  const oldResponses = gate();
  const newResponses = gate();
  let phase: "old" | "new" = "old";
  const calls = { list: 0, kb: 0 };
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
    if (path === `/api/v1/jobs/${jobId}`) return json(job("completed"));
    if (path.endsWith("/conversations")) { calls.list++; const requestedPhase = phase; await (requestedPhase === "old" ? oldResponses : newResponses).promise; return json([summary(requestedPhase)]); }
    if (path.includes("/kb/documents")) { calls.kb++; const requestedPhase = phase; await (requestedPhase === "old" ? oldResponses : newResponses).promise; return json({ items: [kbDoc(`${requestedPhase}-doc`)] }); }
    if (path.endsWith("/library/config")) return json({ admin_required: false });
    return json({ items: [] });
  });
  try {
    await page.goto("/tests/e2e/fixtures/chat-lifecycle-harness.html");
    await expect.poll(() => calls.list).toBeGreaterThan(0);
    await expect.poll(() => calls.kb).toBeGreaterThan(0);
    await page.evaluate(() => window.setHarnessJobStatus("deleting"));
    await expect(page.getByText("Job deletion in progress")).toBeVisible();
    phase = "new";
    oldResponses.release();
    await page.waitForTimeout(100);
    await page.evaluate(() => window.setHarnessJobStatus("completed"));
    await expect(page.getByTitle("Open Knowledge Base")).toBeVisible();
    await page.getByTitle("Open Knowledge Base").click();
    await expect(page.getByText("old-doc", { exact: true })).toHaveCount(0);
    await expect(page.getByText("old conversation", { exact: true })).toHaveCount(0);
    newResponses.release();
    await expect(page.getByText("new-doc", { exact: true })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Baseline conversation" })).toBeVisible();
  } finally { oldResponses.release(); newResponses.release(); }
});

test("delayed MNEMOS open cannot reopen after readiness is revoked", async ({ page }) => {
  const oldComparison = gate();
  let phase: "old" | "new" = "old";
  let comparisonCalls = 0;
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
    if (path === `/api/v1/jobs/${jobId}`) return json(job("completed"));
    if (path.endsWith("/conversations")) return json([summary(phase)]);
    if (path.endsWith("/conversations/old")) return json(history("old", "Old baseline answer"));
    if (path.endsWith("/conversations/new")) return json(history("new", "New baseline answer"));
    if (path.endsWith("/chat/comparisons")) { comparisonCalls++; const root = phase; if (root === "old") await oldComparison.promise; return json(group(root)); }
    if (path.endsWith("/library/config")) return json({ admin_required: false });
    return json({ items: [] });
  });
  try {
    await page.goto("/tests/e2e/fixtures/chat-lifecycle-harness.html");
    await expect(page.getByText("Old baseline answer")).toBeVisible();
    await page.getByRole("button", { name: "MNEMOS comparison" }).click();
    await expect.poll(() => comparisonCalls).toBe(1);
    await page.evaluate(() => window.setHarnessJobStatus("running"));
    await expect(page.getByText("Analysis in progress")).toBeVisible();
    phase = "new";
    oldComparison.release();
    await page.waitForTimeout(100);
    await page.evaluate(() => window.setHarnessJobStatus("completed"));
    await expect(page.getByText("New baseline answer")).toBeVisible();
    await expect(page.getByRole("complementary", { name: "MNEMOS comparison" })).toHaveCount(0);
    await page.getByRole("button", { name: "MNEMOS comparison" }).click();
    await expect(page.getByRole("complementary", { name: "MNEMOS comparison" })).toBeVisible();
    expect(comparisonCalls).toBe(2);
  } finally { oldComparison.release(); }
});

test("completed with errors keeps chat enabled and warns about partial analysis", async ({ page }) => {
  const { calls } = await fixture(page, ["completed_with_errors"], "One sensor failed");
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText(/partial analysis/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible();
  await expect.poll(() => calls.conversations).toBeGreaterThan(0);
});
