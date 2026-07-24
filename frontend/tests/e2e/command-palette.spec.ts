import { test, expect } from "@playwright/test";

const jobs = {
  schema_version: "2.0",
  page: { has_more: false },
  items: [
    { job_id: "aaaa1111-2222-3333-4444-555566667777", job_name: "Cobalt Strike capture", pcap_filename: "cs.pcap", status: "completed", execution_profile: "deep", created_at: new Date().toISOString() },
    { job_id: "bbbb1111-2222-3333-4444-555566667777", job_name: "Recon sweep", pcap_filename: "recon.pcap", status: "failed", execution_profile: "standard", created_at: new Date().toISOString() },
  ],
};

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/settings/setup_status", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", model_configured: true }) }));
  await page.route("**/api/v1/jobs?**", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(jobs) }));
  await page.route("**/api/v1/hosts?**", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", page: { has_more: false }, items: [{ ip: "10.0.0.5", hostname: "WS-05", job_count: 3, total_alerts: 2, total_findings: 1, seen_as_internal: true }] }) }));
});

test("opens with Ctrl+K, lists nav + jobs, and navigates on Enter", async ({ page }) => {
  await page.goto("/jobs");
  await expect(page.getByTestId("nav-jobs")).toBeVisible();

  await page.keyboard.press("Control+k");
  const palette = page.getByTestId("command-palette");
  await expect(palette).toBeVisible();

  // Nav destinations and jobs both present with no query.
  await expect(page.getByTestId("command-item-nav-settings")).toBeVisible();
  await expect(palette.getByText("Cobalt Strike capture")).toBeVisible();

  // Type to filter jobs (server-side q).
  await page.getByTestId("command-input").fill("recon");
  await expect(palette.getByText("Recon sweep")).toBeVisible();

  // Enter opens the first result's job.
  await page.getByTestId("command-input").press("Enter");
  await expect(page).toHaveURL(/\/jobs\/(aaaa|bbbb)1111/);
  await expect(page.getByTestId("command-palette")).toHaveCount(0);
});

test("the header search button opens the same palette", async ({ page }) => {
  await page.goto("/jobs");
  await page.getByTestId("open-command-palette").click();
  await expect(page.getByTestId("command-palette")).toBeVisible();
  await expect(page.getByTestId("command-input")).toBeFocused();
});

test("Escape closes it; a host query surfaces global hosts", async ({ page }) => {
  await page.goto("/jobs");
  await expect(page.getByTestId("nav-jobs")).toBeVisible();
  await page.keyboard.press("Control+k");
  await page.getByTestId("command-input").fill("10.0.0.5");
  await expect(page.getByTestId("command-palette").getByText("WS-05")).toBeVisible();

  await page.getByTestId("command-input").press("Escape");
  await expect(page.getByTestId("command-palette")).toHaveCount(0);
});
