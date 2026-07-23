import { test, expect, Page } from "@playwright/test";

const jobId = "e2e-streams-001";
const now = new Date().toISOString();

const CONN = {
  connection_id: "c-1",
  ts: now,
  src_ip: "10.0.0.5",
  src_port: 49152,
  dest_ip: "203.0.113.9",
  dest_port: 80,
  proto: "tcp",
  service: "http",
  bytes_sent: 1024,
  bytes_recv: 4096,
};

async function stubJob(page: Page) {
  await page.route(`**/api/v1/jobs/${jobId}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        job: {
          job_id: jobId, status: "completed", created_at: now, started_at: now,
          completed_at: now, execution_profile: "standard", priority: "normal",
          pcap_filename: "capture.pcap", stages: [], sensors: [], pcaps: [],
          metrics: { durations: {}, pcap_stats: {} },
        },
      }),
    }));

  await page.route(`**/api/v1/jobs/${jobId}/streams`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        items: [{ name: "capture.pcap", size_bytes: 2048, label: "capture" }],
      }),
    }));

  await page.route(`**/api/v1/jobs/${jobId}/hosts?**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        items: [{ ip: "10.0.0.5", role: "internal", conn_count: 1, alert_count: 0 }],
        page: { has_more: false },
      }),
    }));

  await page.route(`**/api/v1/jobs/${jobId}/hosts/10.0.0.5/connections**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [CONN], page: { has_more: false } }),
    }));
}

test("follow a stream: pick a host, follow a conversation, read the transcript", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/streams/ascii**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", protocol: "tcp",
        transcript: "GET /payload.bin HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        truncated: false, byte_count: 52,
      }),
    }));

  await page.goto(`/jobs/${jobId}/streams`);

  // Nothing selected yet.
  await expect(page.getByTestId("stream-empty-state")).toBeVisible();

  await page.getByTestId("stream-host-select").selectOption("10.0.0.5");
  await expect(page.getByTestId("stream-connection-rows")).toContainText("10.0.0.5:49152 → 203.0.113.9:80");

  await page.getByRole("button", { name: "Follow" }).click();

  // The tuple is pushed into the URL so the view is shareable.
  await expect(page).toHaveURL(/src=10\.0\.0\.5.*sport=49152.*dst=203\.0\.113\.9.*dport=80.*proto=tcp/);

  await expect(page.getByTestId("stream-viewer")).toBeVisible();
  await expect(page.getByTestId("stream-transcript")).toContainText("GET /payload.bin HTTP/1.1");
});

test("deep link opens a stream directly and hexdump view renders packets", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/streams/hexdump**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", protocol: "tcp", truncated: false,
        packets: [{ header: "12:00:00.1 IP 10.0.0.5.49152 > 203.0.113.9.80", lines: ["0x0000:  4500 003c"] }],
      }),
    }));
  await page.route(`**/api/v1/jobs/${jobId}/streams/ascii**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", protocol: "tcp", transcript: "hello", truncated: false, byte_count: 5,
      }),
    }));

  // Land straight on a followed stream, as the host-page "Follow" link does.
  await page.goto(
    `/jobs/${jobId}/streams?src=10.0.0.5&sport=49152&dst=203.0.113.9&dport=80&proto=tcp`,
  );

  await expect(page.getByTestId("stream-viewer")).toBeVisible();

  await page.getByTestId("stream-view-hex").click();
  await expect(page.getByTestId("stream-hexdump")).toContainText("0x0000:  4500 003c");
});

test("surfaces a truncation warning and backend errors", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/streams/ascii**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", protocol: "tcp",
        transcript: "x".repeat(200), truncated: true, byte_count: 100000,
      }),
    }));

  await page.goto(
    `/jobs/${jobId}/streams?src=10.0.0.5&sport=49152&dst=203.0.113.9&dport=80&proto=tcp`,
  );
  await expect(page.getByText(/Transcript truncated/)).toBeVisible();

  // 503 is what the server returns when tshark is absent — a real air-gapped case.
  await page.route(`**/api/v1/jobs/${jobId}/streams/ascii**`, (route) =>
    route.fulfill({
      status: 503, contentType: "application/json",
      body: JSON.stringify({ detail: "Required tool 'tshark' is not installed on the server" }),
    }));
  await page.reload();
  await expect(page.getByTestId("stream-error")).toBeVisible();
});

test("warns when the host or connection picker is truncated", async ({ page }) => {
  await stubJob(page);
  // has_more on the host list — more hosts than the picker fetched.
  await page.unroute(`**/api/v1/jobs/${jobId}/hosts?**`);
  await page.route(`**/api/v1/jobs/${jobId}/hosts?**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        items: [{ ip: "10.0.0.5", role: "internal", conn_count: 999, alert_count: 0 }],
        page: { has_more: true },
      }),
    }));
  // has_more on the connection list too.
  await page.unroute(`**/api/v1/jobs/${jobId}/hosts/10.0.0.5/connections**`);
  await page.route(`**/api/v1/jobs/${jobId}/hosts/10.0.0.5/connections**`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [CONN], page: { has_more: true } }),
    }));

  await page.goto(`/jobs/${jobId}/streams`);
  await expect(page.getByTestId("stream-hosts-truncated")).toBeVisible();
  await page.getByTestId("stream-host-select").selectOption("10.0.0.5");
  await expect(page.getByTestId("stream-conns-truncated")).toBeVisible();
});

test("host connections table deep-links into the stream viewer", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/hosts/10.0.0.5`, (route) =>
    route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        host: { ip: "10.0.0.5", role: "internal", conn_count: 1, alert_count: 0 },
      }),
    }));

  await page.goto(`/jobs/${jobId}/hosts/10.0.0.5/connections`);
  await page.getByRole("link", { name: "Follow" }).click();

  await expect(page).toHaveURL(/\/streams\?src=10\.0\.0\.5/);
  await expect(page.getByTestId("stream-viewer")).toBeVisible();
});
