import { test, expect } from '@playwright/test';

// End-to-end flow: start a new upload analysis and land on the Job Detail page.

test('can start a new upload analysis and see job detail', async ({ page }) => {
  const jobId = 'e2e-job-123';

  // Stub backend API for job creation and status/result polling.
  await page.route('http://localhost:8000/api/v1/jobs', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ job_id: jobId, status: 'queued' }),
    });
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

  // Go to New Analysis page.
  await page.goto('/new');

  // Upload a dummy PCAP file from the fixtures directory.
  await page.getByTestId('input-pcap-files').setInputFiles('tests/fixtures/dummy.pcap');

  // Choose baseline vs exploit mode.
  await page.getByTestId('select-analysis-mode').selectOption('baseline_vs_exploit');

  // Submit the form.
  await page.getByTestId('btn-start-analysis').click();

  // We should navigate to the Job Detail page for this job id.
  await page.waitForURL(`**/jobs/${jobId}`);

  await expect(page.getByText('Analysis Report')).toBeVisible();
  await expect(page.getByText(`ID: ${jobId}`)).toBeVisible();
  await expect(page.getByText('Executive Summary')).toBeVisible();
});

