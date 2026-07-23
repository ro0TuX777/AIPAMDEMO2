import { test, expect, Page } from "@playwright/test";

const jobId = "e2e-events-001";
const now = new Date().toISOString();

const EVENT = {
  event_id: "ev-1",
  event_type: "auth",
  timestamp: "2026-03-15T14:30:00.000Z",
  source_type: "log_bundle",
  source_system: "windows_security",
  hostname: "WORKSTATION-01",
  username: "jdoe",
  src_ip: "10.0.0.5",
  src_port: 49152,
  dest_ip: "10.0.0.10",
  dest_port: 445,
  proto: "tcp",
  evidence_status: "corroborated",
  tags: ["lateral"],
  data: { logon_type: "10", event_id: 4624 },
};

async function stubJob(page: Page) {
  await page.route(`**/api/v1/jobs/${jobId}`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        job: {
          job_id: jobId, status: "completed", created_at: now, started_at: now,
          completed_at: now, execution_profile: "standard", priority: "normal",
          pcap_filename: "c.pcap", stages: [], sensors: [], pcaps: [],
          metrics: { durations: {}, pcap_stats: {} },
        },
      }),
    }));
}

test("search events and expand a row to see the normalized payload", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/raw-events?**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [EVENT], total: 1, limit: 100, offset: 0 }),
    }));

  await page.goto(`/jobs/${jobId}/raw-events`);

  await expect(page.getByTestId("events-table")).toContainText("WORKSTATION-01");
  await expect(page.getByTestId("events-table")).toContainText("10.0.0.5:49152 → 10.0.0.10:445");

  // Row expands to the raw JSON.
  await page.getByText("WORKSTATION-01").click();
  await expect(page.getByText(/"logon_type"/)).toBeVisible();
});

test("breakdown renders bars and drilling down filters the event list", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/raw-events/aggregate**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", field: "event_type", total_events: 150,
        buckets: [
          { value: "connection", count: 90 },
          { value: "auth", count: 40 },
          { value: "dns", count: 20 },
        ],
      }),
    }));
  await page.route(`**/api/v1/jobs/${jobId}/raw-events?**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [EVENT], total: 1, limit: 100, offset: 0 }),
    }));

  await page.goto(`/jobs/${jobId}/raw-events?mode=breakdown`);
  await expect(page.getByTestId("bucket-bar-chart")).toBeVisible();

  // A table view exists alongside the chart (accessibility relief).
  await page.getByRole("button", { name: "Show table" }).click();
  await expect(page.getByTestId("events-agg-table")).toContainText("60.0%");
  await page.getByRole("button", { name: "Show chart" }).click();

  // Clicking a bar filters the event list by that value.
  await page.getByTestId("bucket-bar-chart").getByText("auth", { exact: true }).click();
  await expect(page).toHaveURL(/event_type=auth/);
  await expect(page).toHaveURL(/mode=events/);
  await expect(page.getByTestId("events-active-filters")).toContainText("auth");
});

test("flow diagram renders nodes with a legend and always-on labels", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/raw-events/flow**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", flows_considered: 130,
        nodes: [
          { id: "src:10.0.0.5", label: "10.0.0.5", kind: "src" },
          { id: "host:203.0.113.9", label: "203.0.113.9", kind: "host" },
          { id: "port:443", label: "443", kind: "port" },
        ],
        links: [
          { source: 0, target: 1, value: 90 },
          { source: 1, target: 2, value: 90 },
        ],
      }),
    }));

  await page.goto(`/jobs/${jobId}/raw-events?mode=flow`);

  await expect(page.getByTestId("flow-diagram")).toBeVisible();
  // Identity is never colour-alone: legend plus direct labels on every node.
  await expect(page.getByTestId("flow-legend")).toContainText("Source IP");
  await expect(page.getByTestId("flow-legend")).toContainText("Destination port");
  await expect(page.getByTestId("flow-diagram")).toContainText("10.0.0.5");
  await expect(page.getByTestId("flow-diagram")).toContainText("443");
});

test("flow warns when a stage is saturated at the top-N cap", async ({ page }) => {
  await stubJob(page);
  // 50 src nodes each with one src→host link = stage 1 at the top-N cap (50).
  const FLOW_LIMIT = 50;
  const nodes: any[] = [{ id: "host:h", label: "10.0.0.10", kind: "host" }];
  const links: any[] = [];
  for (let i = 0; i < FLOW_LIMIT; i++) {
    nodes.push({ id: `src:${i}`, label: `10.0.0.${i}`, kind: "src" });
    links.push({ source: i + 1, target: 0, value: FLOW_LIMIT - i });
  }
  await page.route(`**/api/v1/jobs/${jobId}/raw-events/flow**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", nodes, links, flows_considered: 5000 }),
    }));

  await page.goto(`/jobs/${jobId}/raw-events?mode=flow`);
  await expect(page.getByTestId("flow-truncated")).toContainText(/highest-volume paths/);
});

test("empty flow explains itself rather than rendering a blank canvas", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/raw-events/flow**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", nodes: [], links: [], flows_considered: 0 }),
    }));

  await page.goto(`/jobs/${jobId}/raw-events?mode=flow`);
  await expect(page.getByText(/no flow to draw/i)).toBeVisible();
});
