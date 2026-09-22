import { expect, test } from "@playwright/test";

const jobId = "mnemos-comparison-e2e";
const now = "2026-09-22T00:00:00Z";

async function stubChatPage(page: import("@playwright/test").Page, unavailable = false) {
  await page.route(`**/api/v1/jobs/${jobId}`, route => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ job: { job_id: jobId, status: "completed", created_at: now, stages: [], sensors: [], pcaps: [], metrics: { durations: {}, pcap_stats: {} } } }),
  }));
  await page.route(`**/api/v1/jobs/${jobId}/conversations`, route => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify([{ id: "baseline-1", job_id: jobId, created_at: now, updated_at: now, title: "Baseline", message_count: 2 }]),
  }));
  await page.route(`**/api/v1/jobs/${jobId}/conversations/baseline-1`, route => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ id: "baseline-1", job_id: jobId, created_at: now, updated_at: now, messages: [
      { id: "baseline-question", sequence: 1, role: "user", content: "Was this C2 activity?", citations: [], metadata: null, request_id: null, timestamp: now },
      { id: "baseline-answer", sequence: 2, role: "assistant", content: "Baseline response", citations: [], metadata: null, request_id: null, timestamp: now },
    ] }),
  }));
  await page.route(`**/api/v1/jobs/${jobId}/chat/comparisons`, route => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ group_id: "group-1", job_id: jobId, root_conversation_id: "baseline-1", snapshot_branch_id: "snapshot-1", active_branch_id: "snapshot-1", conversation_id: "mnemos-snapshot", created_at: now, updated_at: now, branches: [{ id: "snapshot-1", conversation_id: "mnemos-snapshot", label: "MNEMOS snapshot", history_cutoff_sequence: 2, created_at: now, updated_at: now, messages: [] }] }),
  }));
  await page.route(`**/api/v1/jobs/${jobId}/chat/stream`, route => route.fulfill({
    contentType: "text/event-stream",
    body: unavailable
      ? `data: ${JSON.stringify({ type: "error", content: "MNEMOS unavailable" })}\n\ndata: ${JSON.stringify({ type: "meta", conversation_id: "mnemos-snapshot", request_id: "request-1", status: "error", retrieval_status: "unavailable", citations: [] })}\n\ndata: [DONE]\n\n`
      : `data: ${JSON.stringify({ type: "meta", conversation_id: "mnemos-snapshot", request_id: "request-1", status: "completed", retrieval_status: "no_matches", citations: [] })}\n\ndata: [DONE]\n\n`,
  }));
  await page.route("**/api/v1/library/config", route => route.fulfill({ contentType: "application/json", body: JSON.stringify({ admin_required: false }) }));
  await page.route("**/api/v1/library/documents", route => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [] }) }));
  await page.route(`**/api/v1/jobs/${jobId}/kb/documents`, route => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [] }) }));
}

test("copy opens an editable MNEMOS draft without sending", async ({ page }) => {
  await stubChatPage(page);
  await page.setViewportSize({ width: 390, height: 844 });
  let chatRequests = 0;
  page.on("request", request => { if (request.url().includes("/chat/stream")) chatRequests += 1; });
  await page.goto(`/jobs/${jobId}/chat`);
  await page.getByRole("button", { name: "Copy to MNEMOS" }).click();
  await expect(page.getByRole("complementary", { name: "MNEMOS comparison" })).toBeVisible();
  await expect(page.getByLabel("MNEMOS message")).toHaveValue("Was this C2 activity?");
  await expect(page.getByText("Historical confirmed findings")).toHaveCount(0);
  expect(chatRequests).toBe(0);
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click();
  await expect(page.getByRole("button", { name: "MNEMOS comparison" })).toBeFocused();
});

test("unavailable MNEMOS exposes retry and no baseline answer", async ({ page }) => {
  await stubChatPage(page, true);
  const requestIds: string[] = [];
  page.on("request", request => {
    if (request.url().includes("/chat/stream")) requestIds.push(JSON.parse(request.postData() || "{}").request_id);
  });
  await page.goto(`/jobs/${jobId}/chat`);
  await page.getByRole("button", { name: "MNEMOS comparison" }).click();
  await page.getByLabel("MNEMOS message").fill("Check history");
  await page.getByRole("button", { name: "Send to MNEMOS" }).click();
  await expect(page.getByText("MNEMOS is unavailable. Try again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toBeVisible();
  await page.getByRole("button", { name: "Retry MNEMOS" }).click();
  await expect.poll(() => requestIds.length).toBe(2);
  expect(requestIds[1]).toBe(requestIds[0]);
});
