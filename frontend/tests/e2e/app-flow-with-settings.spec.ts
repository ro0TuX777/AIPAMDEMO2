import { test, expect } from '@playwright/test';

// Cross-page flow: Dashboard -> New Analysis (upload) -> Job Detail -> Settings.

test('app flow: upload analysis then navigate to settings', async ({ page }) => {
  const jobId = 'e2e-nav-job-001';

  // Stub backend APIs for upload job lifecycle.
  await page.route('http://localhost:8000/api/v1/jobs', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ job_id: jobId, status: 'queued' }),
      });
    } else {
      await route.fallback();
    }
  });

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}`, async (route) => {
    const now = new Date().toISOString();
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        job_id: jobId,
        status: 'completed',
        created_at: now,
        updated_at: now,
        steps: [
          { name: 'ingest', status: 'completed', message: 'ok' },
          { name: 'parse', status: 'completed', message: 'ok' },
          { name: 'aggregate', status: 'completed', message: 'ok' },
          { name: 'llm_analysis', status: 'completed', message: 'ok' },
          { name: 'report', status: 'completed', message: 'ok' },
        ],
      }),
    });
  });

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/result`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        job_id: jobId,
        status: 'completed',
        summary: {
          severity: 'low',
          key_findings: [],
          mitre_techniques: [],
        },
        hosts: [],
        raw: {},
        report_urls: {},
      }),
    });
  });

  // Stub settings endpoints so the Settings page works in this flow.
  await page.route('http://localhost:8000/api/v1/settings', async (route) => {
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

  await page.route('http://localhost:8000/api/v1/settings/test_llm', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true }),
    });
  });

  // Start from Dashboard.
  await page.goto('/');
  await expect(page.getByTestId('nav-dashboard')).toBeVisible();

  // Navigate to New Analysis via nav.
  await page.getByTestId('nav-new-analysis').click();
  await expect(page.getByTestId('main-content')).toBeVisible();

  // Run a minimal upload analysis.
  await page.getByTestId('input-pcap-files').setInputFiles('tests/fixtures/dummy.pcap');
  await page.getByTestId('select-analysis-mode').selectOption('single_window');
  await page.getByTestId('btn-start-analysis').click();

  // Land on Job Detail.
  await page.waitForURL(`**/jobs/${jobId}`);
  await expect(page.getByText('Analysis Report')).toBeVisible();

  // From here, navigate to Settings using the main nav.
  await page.getByTestId('nav-settings').click();
  await expect(page.getByTestId('page-settings')).toBeVisible();

  // Smoke-check that saving + LLM test work in this integrated flow.
  await page.getByTestId('btn-save-settings').click();
  await expect(page.getByText('Settings saved')).toBeVisible();

  await page.getByTestId('btn-test-llm').click();
  await expect(page.getByText('LLM connection OK')).toBeVisible();
});

