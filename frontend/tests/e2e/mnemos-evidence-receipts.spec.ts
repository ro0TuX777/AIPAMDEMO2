import { expect, test, type Page, type Route } from "@playwright/test";

const receipt = (receiptId: string, overrides: Record<string, unknown> = {}) => ({
  schema_version: 1,
  receipt_id: receiptId,
  created_at: "2026-09-22T00:00:00Z",
  job_id: "job-archived",
  conversation_id: "conversation-1",
  assistant_message_id: "assistant-1",
  request_id: "request-1",
  query: "Summarize the key findings",
  answer: "The key finding is suspicious DNS activity.",
  model_id: "qwen-local",
  generation: { duration_ms: 900 },
  runtime: { provider: "ollama", timeout_seconds: 120, local_adapter_model_name: "qwen3:8b", local_adapter_quantization: "Q4_K_M" },
  retrieval_status: "matched",
  citations: [{ source: "alert-1", title: "DNS alert" }],
  evidence_refs: [{ kind: "alert", id: "alert-1" }],
  content_hash: "sha256:abc123",
  ...overrides,
});

async function setup(page: Page, options: { missingDetail?: boolean; failList?: boolean } = {}) {
  const calls: string[] = [];
  await page.addInitScript(() => localStorage.setItem("aipam_token", "e2e-auth-token"));
  await page.route("**/api/v1/**", async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace("/api/v1", "");
    calls.push(`${path}${url.search}`);
    if (path === "/settings/setup_status") return route.fulfill({ json: { model_configured: true } });
    if (path === "/mnemos/evidence-receipts") {
      if (options.failList) return route.fulfill({ status: 503, json: { detail: "Receipt service unavailable" } });
      if (url.searchParams.get("cursor") === "next-page") {
        return route.fulfill({ json: { items: [receipt("receipt-active", { job_id: "job-active", query: "Active receipt preview" }), receipt("receipt-newest", { query: "Second page receipt" })], page: { next_cursor: null, has_more: false } } });
      }
      return route.fulfill({ json: { items: [receipt("receipt-archived", { query: "Archived receipt preview" }), receipt("receipt-active", { job_id: "job-active", query: "Active receipt preview" })], page: { next_cursor: "next-page", has_more: true } } });
    }
    if (path.startsWith("/mnemos/evidence-receipts/")) {
      if (options.missingDetail) return route.fulfill({ status: 404, json: { detail: "Not found" } });
      const id = decodeURIComponent(path.split("/").at(-1)!);
      return route.fulfill({ json: receipt(id) });
    }
    return route.fulfill({ json: {} });
  });
  return calls;
}

async function setupDelayedPagination(page: Page) {
  let captureCursorRoute!: (route: Route) => void;
  const cursorRoute = new Promise<Route>(resolve => { captureCursorRoute = resolve; });
  let signalCursorStarted!: () => void;
  const cursorStarted = new Promise<void>(resolve => { signalCursorStarted = resolve; });
  await page.addInitScript(() => localStorage.setItem("aipam_token", "e2e-auth-token"));
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace("/api/v1", "");
    if (path === "/settings/setup_status") return route.fulfill({ json: { model_configured: true } });
    if (path === "/mnemos/evidence-receipts" && url.searchParams.get("cursor") === "next-page") {
      signalCursorStarted();
      captureCursorRoute(route);
      return;
    }
    if (path === "/mnemos/evidence-receipts") {
      return route.fulfill({ json: { items: [receipt("receipt-archived", { query: "Archived receipt preview" }), receipt("receipt-active", { job_id: "job-active", query: "Active receipt preview" })], page: { next_cursor: "next-page", has_more: true } } });
    }
    if (path.startsWith("/mnemos/evidence-receipts/")) {
      return route.fulfill({ json: receipt(decodeURIComponent(path.split("/").at(-1)!)) });
    }
    return route.fulfill({ json: {} });
  });
  return { cursorRoute, cursorStarted };
}

for (const outcome of ["failure", "success"] as const) {
  test(`late pagination ${outcome} cannot overwrite history after leaving and returning`, async ({ page }) => {
    const pending = await setupDelayedPagination(page);
    await page.goto("/mnemos/receipts");
    await expect(page.getByText("Archived receipt preview")).toBeVisible();
    await page.getByRole("button", { name: "Load more" }).click();
    await pending.cursorStarted;
    await page.getByRole("link", { name: "Archived receipt preview" }).click();
    await expect(page.getByRole("heading", { name: "Evidence Receipt" })).toBeVisible();
    await expect(page.getByText("The key finding is suspicious DNS activity.")).toBeVisible();
    await page.getByRole("link", { name: "Back to receipt history" }).click();
    await expect(page.getByRole("heading", { name: "MNEMOS Evidence Receipts" })).toBeVisible();
    await expect(page.getByText("Archived receipt preview")).toBeVisible();

    const lateRoute = await pending.cursorRoute;
    if (outcome === "failure") {
      await lateRoute.fulfill({ status: 503, json: { detail: "Delayed page failed" } });
    } else {
      await lateRoute.fulfill({ json: { items: [receipt("stale-page-item", { query: "Stale page item" })], page: { next_cursor: null, has_more: false } } });
    }
    await expect(page.getByRole("button", { name: "Load more" })).toBeVisible();
    await expect(page.getByText("Could not load the next page of evidence receipts")).toHaveCount(0);
    await expect(page.getByText("Stale page item")).toHaveCount(0);
    await expect(page.getByText("Archived receipt preview")).toBeVisible();
  });
}

test("global navigation opens paginated history with archived receipts", async ({ page }) => {
  const calls = await setup(page);
  await page.goto("/jobs");
  await page.getByTestId("nav-mnemos-receipts").click();
  await expect(page).toHaveURL(/\/mnemos\/receipts$/);
  await expect(page.getByRole("heading", { name: "MNEMOS Evidence Receipts" })).toBeVisible();
  await expect(page.getByText("Archived receipt preview")).toBeVisible();
  await expect(page.getByText("Active receipt preview")).toBeVisible();
  await expect(page.getByText("Active and archived receipts", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load more" }).click();
  await expect(page.getByText("Second page receipt")).toBeVisible();
  await expect(page.getByText("Archived receipt preview")).toHaveCount(1);
  await expect(page.getByText("Active receipt preview")).toHaveCount(1);
  expect(calls.some(call => call.includes("cursor=next-page"))).toBe(true);
});

test("receipt detail renders evidence sections and authenticated JSON download", async ({ page }) => {
  const calls = await setup(page);
  const receiptRequests: string[] = [];
  page.on("request", request => {
    if (request.url().includes("/mnemos/evidence-receipts/receipt-archived")) receiptRequests.push(request.headers()["authorization"] ?? "");
  });
  await page.goto("/mnemos/receipts/receipt-archived");
  await expect(page.getByRole("heading", { name: "Evidence Receipt" })).toBeVisible();
  await expect(page.getByText("Summarize the key findings")).toBeVisible();
  await expect(page.getByText("The key finding is suspicious DNS activity.")).toBeVisible();
  await expect(page.getByText("sha256:abc123")).toBeVisible();
  await expect(page.getByText("DNS alert")).toBeVisible();
  await expect(page.getByText("ollama", { exact: true })).toBeVisible();
  await expect(page.getByText("120", { exact: true })).toBeVisible();
  await expect(page.getByText("qwen3:8b", { exact: true })).toBeVisible();
  await expect(page.getByText("Q4_K_M", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Back to receipt history" })).toHaveAttribute("href", "/mnemos/receipts");

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download JSON" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("receipt-archived.json");
  expect(calls.some(call => call === "/mnemos/evidence-receipts/receipt-archived")).toBe(true);
  await expect.poll(() => receiptRequests.length).toBeGreaterThanOrEqual(2);
  expect(receiptRequests.length).toBeGreaterThanOrEqual(2);
  expect(receiptRequests.every(header => header === "Bearer e2e-auth-token")).toBe(true);
});

test("JSON download failures are shown without navigating away", async ({ page }) => {
  await setup(page);
  await page.goto("/mnemos/receipts/receipt-archived");
  await expect(page.getByRole("heading", { name: "Evidence Receipt" })).toBeVisible();
  await page.route("**/api/v1/mnemos/evidence-receipts/receipt-archived", route => route.fulfill({ status: 503, json: { detail: "Download unavailable" } }));
  await page.getByRole("button", { name: "Download JSON" }).click();
  await expect(page.getByText("Could not download evidence receipt JSON")).toBeVisible();
  await expect(page).toHaveURL(/\/mnemos\/receipts\/receipt-archived$/);
});

test("receipt history and detail show clear API error and not-found states", async ({ page }) => {
  await setup(page, { failList: true });
  await page.goto("/mnemos/receipts");
  await expect(page.getByText("Could not load evidence receipts")).toBeVisible();

  await setup(page, { missingDetail: true });
  await page.goto("/mnemos/receipts/missing-receipt");
  await expect(page.getByText("Evidence receipt not found")).toBeVisible();
});

test("empty receipt history has an explicit empty state", async ({ page }) => {
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/settings/setup_status")) return route.fulfill({ json: { model_configured: true } });
    if (path.endsWith("/mnemos/evidence-receipts")) return route.fulfill({ json: { items: [], page: { next_cursor: null, has_more: false } } });
    return route.fulfill({ json: {} });
  });
  await page.goto("/mnemos/receipts");
  await expect(page.getByText("No evidence receipts yet")).toBeVisible();
});
