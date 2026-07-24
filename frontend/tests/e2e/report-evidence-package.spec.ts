import { test, expect } from "@playwright/test";
const jobId = "rep-job-1";
const now = new Date().toISOString();

test("Report page can generate an evidence package", async ({ page }) => {
  await page.route("**/api/v1/settings/setup_status", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", model_configured: true }) }));
  await page.route(`**/api/v1/jobs/${jobId}`, (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", job: {
      job_id: jobId, status: "completed", created_at: now, started_at: now, completed_at: now,
      execution_profile: "standard", priority: "normal", pcap_filename: "c.pcap", stages: [], sensors: [], pcaps: [],
      metrics: { durations: {}, pcap_stats: {} } } }) }));
  // Everything else the report loads → empty.
  await page.route("**/api/v1/jobs/**", (r) => {
    if (r.request().url().includes("/artifacts") && r.request().method() === "POST") {
      return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", status: "ok" }) });
    }
    return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", items: [], page: { has_more: false } }) });
  });

  let pkgCalled = false;
  await page.route(`**/api/v1/jobs/${jobId}/artifacts/evidence-package`, (r) => { pkgCalled = true; r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", status: "ok" }) }); });

  await page.goto(`/jobs/${jobId}/report`);
  const btn = page.getByTestId("report-evidence-package");
  await expect(btn).toBeVisible();
  await btn.click();
  // A toast confirms and links to Exports.
  await expect(page.getByText("Evidence package generated")).toBeVisible({ timeout: 8000 });
});
