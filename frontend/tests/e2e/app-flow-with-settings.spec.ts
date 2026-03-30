import { test, expect } from '@playwright/test';

// Cross-page flow: Dashboard -> New Analysis (upload) -> Job Detail -> Settings.

test('@requires-backend app flow: upload analysis then navigate to settings', async ({ page }) => {
  const jobId = 'e2e-nav-job-001';

  const uploadId = 'e2e-upload-nav-001';

  // Stub upload endpoint.
  await page.route('**/api/v1/uploads', async (route) => {
    if (route.request().method() === 'POST' && !route.request().url().includes('/validate')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          schema_version: '2.0',
          upload_id: uploadId,
          filename: 'dummy.pcap',
          size_bytes: 1024,
          sha256: 'abc123',
        }),
      });
    } else {
      await route.fallback();
    }
  });

  // Stub upload validation.
  await page.route(`**/api/v1/uploads/${uploadId}/validate`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: '2.0',
        is_valid: true,
        format: 'pcap',
        packet_count: 100,
      }),
    });
  });

  // Stub job creation.
  await page.route('**/api/v1/jobs', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ schema_version: '2.0', job_id: jobId }),
      });
    } else {
      await route.fallback();
    }
  });

  await page.route(`**/api/v1/jobs/${jobId}`, async (route) => {
    const now = new Date().toISOString();
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: '2.0',
        job: {
          job_id: jobId,
          status: 'completed',
          created_at: now,
          started_at: now,
          completed_at: now,
          execution_profile: 'standard',
          priority: 'normal',
          pcap_filename: 'test.pcap',
          stages: [],
          sensors: [],
          pcaps: [],
          metrics: { durations: {}, pcap_stats: {} },
        },
      }),
    });
  });

  await page.route(`**/api/v1/jobs/${jobId}/summary`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: '2.0',
        job_id: jobId,
        headline: 'Analysis complete.',
        alert_count: 0,
        finding_count: 0,
        ioc_count: 0,
        host_count: 0,
        top_signals: [],
        recommendations: [],
      }),
    });
  });

  // Stub settings endpoints so the Settings page works in this flow.
  await page.route('**/api/v1/settings', async (route) => {
    if (route.request().method() === 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          llm_endpoint: 'http://localhost:11434/v1/chat/completions',
          llm_model_name: 'local-llm',
          file_storage_path: '/srv/aipam/storage',
        }),
      });
    } else if (route.request().method() === 'PUT') {
      const json = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(json),
      });
    } else {
      await route.fallback();
    }
  });

  await page.route('**/api/v1/settings/test_llm', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true }),
    });
  });

  // Start from Jobs list.
  await page.goto('/');
  await expect(page.getByTestId('nav-jobs')).toBeVisible();

  // Navigate to New Analysis via nav.
  await page.getByTestId('nav-new-analysis').click();
  await expect(page.getByTestId('main-content')).toBeVisible();

  // Run a minimal upload analysis.
  await page.getByTestId('input-pcap-files').setInputFiles('tests/fixtures/dummy.pcap');
  await page.getByTestId('btn-start-analysis').click();

  // Land on Job Detail.
  await page.waitForURL(`**/jobs/${jobId}`);
  await expect(page.getByText('Job Detail')).toBeVisible();

  // From here, navigate to Settings using the main nav.
  await page.getByTestId('nav-settings').click();
  await expect(page.getByTestId('page-settings')).toBeVisible();

  // Smoke-check that saving + LLM test work in this integrated flow.
  await page.getByTestId('btn-save-settings').click();
  await expect(page.getByText('Settings saved')).toBeVisible();

  await page.getByTestId('btn-test-llm').click();
  await expect(page.getByText('LLM connection OK')).toBeVisible();
});

