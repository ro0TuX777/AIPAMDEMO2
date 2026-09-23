import { expect, test, type Page, type Route } from "@playwright/test";
import { isActiveJobStatus, isChatReadyJobStatus, isTerminalJobStatus } from "../../src/api/jobStatus";

const jobId = "chat-lifecycle-e2e";
const now = "2026-09-23T00:00:00Z";
type Status = "queued" | "running" | "canceling" | "deleting" | "completed" | "completed_with_errors" | "failed" | "canceled" | "deleted";

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

test("completed with errors keeps chat enabled and warns about partial analysis", async ({ page }) => {
  const { calls } = await fixture(page, ["completed_with_errors"], "One sensor failed");
  await page.goto(`/jobs/${jobId}/chat`);
  await expect(page.getByText(/partial analysis/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeVisible();
  await expect.poll(() => calls.conversations).toBeGreaterThan(0);
});
