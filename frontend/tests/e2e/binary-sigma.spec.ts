import { test, expect, Page } from "@playwright/test";

const jobId = "e2e-bs-001";
const now = new Date().toISOString();

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

const ANALYSIS = {
  file_id: "f-1",
  filename: "payload.bin",
  size_bytes: 48128,
  sha256: "a".repeat(64),
  sha1: "b".repeat(40),
  md5: "c".repeat(32),
  entropy: 7.84,
  format: "PE32 executable",
  artifact_class: "binary",
  yara_matches: [
    {
      rule: "SUSP_Packed_UPX",
      tags: ["packer", "evasion"],
      meta: { author: "aipam", description: "UPX packed sample" },
      strings: ["$upx0 at 0x1000", "$upx1 at 0x2000"],
    },
  ],
};

// ── Binary ────────────────────────────────────────────────────────────────

test("binary: analyzing a file shows hashes, entropy and YARA matches", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/binary**`, async (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({
        status: 201, contentType: "application/json",
        body: JSON.stringify({
          schema_version: "2.0", yara_available: true, rules_compiled: true,
          findings_created: 1, analysis: ANALYSIS,
        }),
      });
    }
    return route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [], total: 0 }),
    });
  });

  await page.goto(`/jobs/${jobId}/binary`);
  await page.getByTestId("binary-file-input").setInputFiles({
    name: "payload.bin", mimeType: "application/octet-stream", buffer: Buffer.from("MZ\x90\x00"),
  });

  await expect(page.getByTestId("yara-matches")).toContainText("SUSP_Packed_UPX");
  await expect(page.getByText("likely packed or encrypted")).toBeVisible();
  await expect(page.getByText("UPX packed sample")).toBeVisible();
});

test("binary: stateless inspection does not persist and is labelled as such", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/binary**`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [], total: 0 }),
    }));

  let persistedCalled = false;
  await page.route("**/api/v1/binary/inspect**", (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", yara_available: true, rules_compiled: true,
        analysis: { ...ANALYSIS, yara_matches: [] },
      }),
    }));
  page.on("request", (req) => {
    if (req.method() === "POST" && req.url().includes(`/jobs/${jobId}/binary`)) persistedCalled = true;
  });

  await page.goto(`/jobs/${jobId}/binary`);
  await page.getByTestId("binary-persist").uncheck();
  await page.getByTestId("binary-file-input").setInputFiles({
    name: "sample.exe", mimeType: "application/octet-stream", buffer: Buffer.from("MZ"),
  });

  await expect(page.getByTestId("binary-scratch-result")).toBeVisible();
  await expect(page.getByText("not saved")).toBeVisible();
  expect(persistedCalled).toBe(false);
});

test("binary: warns when the YARA engine is unavailable", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/binary**`, async (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({
        status: 201, contentType: "application/json",
        body: JSON.stringify({
          schema_version: "2.0", yara_available: false, rules_compiled: false,
          findings_created: 0, analysis: { ...ANALYSIS, yara_matches: [] },
        }),
      });
    }
    return route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [], total: 0 }),
    });
  });

  await page.goto(`/jobs/${jobId}/binary`);
  await page.getByTestId("binary-file-input").setInputFiles({
    name: "x.bin", mimeType: "application/octet-stream", buffer: Buffer.from("x"),
  });

  await expect(page.getByTestId("yara-engine-warning")).toContainText("yara module is not installed");
});

// ── Sigma ─────────────────────────────────────────────────────────────────

test("sigma: running rules reports the run and lists detections", async ({ page }) => {
  await stubJob(page);
  let listCalls = 0;
  await page.route(`**/api/v1/jobs/${jobId}/sigma`, (r) => {
    listCalls += 1;
    return r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0",
        total: listCalls > 1 ? 1 : 0,
        items: listCalls > 1
          ? [{
              finding_id: "sigma-r1-ev1", rule_id: "r1", title: "Suspicious PowerShell",
              severity: "high", category: "execution", tags: ["attack.execution"],
              event_id: "ev1", hostname: "WS-01", timestamp: "2026-03-15T14:30:00Z",
            }]
          : [],
      }),
    });
  });
  await page.route(`**/api/v1/jobs/${jobId}/sigma/analyze`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", rules_evaluated: 42, events_scanned: 1500,
        detections_created: 1, detections_total: 1, items: [],
      }),
    }));

  await page.goto(`/jobs/${jobId}/sigma`);
  await expect(page.getByTestId("sigma-empty")).toBeVisible();

  await page.getByTestId("sigma-run").click();
  await expect(page.getByTestId("sigma-run-summary")).toContainText("42");
  await expect(page.getByTestId("sigma-run-summary")).toContainText("1,500");
  await expect(page.getByText("Suspicious PowerShell")).toBeVisible();

  // Detections are findings, so the detail route already handles them.
  await expect(page.getByRole("link", { name: "View finding" }))
    .toHaveAttribute("href", `/jobs/${jobId}/findings/sigma-r1-ev1`);
});

test("sigma: explains a zero-event scan rather than looking broken", async ({ page }) => {
  await stubJob(page);
  await page.route(`**/api/v1/jobs/${jobId}/sigma`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ schema_version: "2.0", items: [], total: 0 }),
    }));
  await page.route(`**/api/v1/jobs/${jobId}/sigma/analyze`, (r) =>
    r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({
        schema_version: "2.0", rules_evaluated: 42, events_scanned: 0,
        detections_created: 0, detections_total: 0, items: [],
      }),
    }));

  await page.goto(`/jobs/${jobId}/sigma`);
  await page.getByTestId("sigma-run").click();
  await expect(page.getByText(/No normalized events exist for this job/)).toBeVisible();
});
