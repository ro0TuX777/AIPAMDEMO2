import { test, expect } from '@playwright/test';

// Focused coverage for Job Detail tabs (Overview, Hosts, Raw JSON, Report).

test('job detail tabs render and switch correctly', async ({ page }) => {
  const jobId = 'e2e-job-tabs-001';

  // Stub job status
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

  // Stub job result with hosts and report URLs
  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/result`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        job_id: jobId,
        status: 'completed',
        summary: {
          severity: 'high',
          key_findings: [
            { stage: 'initial_access', description: 'Phishing email with malicious attachment.' },
          ],
          mitre_techniques: [
            { id: 'T1566', name: 'Phishing' },
          ],
        },
        hosts: [
          {
            ip: '10.0.0.10',
            role: 'victim',
            findings: ['Suspected initial compromise via phishing.', 'Outbound C2 beaconing detected.'],
          },
        ],
        raw: { some: 'raw-data' },
        report_urls: {
          html: '/reports/job-e2e-job-tabs-001.html',
          markdown: '/reports/job-e2e-job-tabs-001.md',
        },
      }),
    });
  });

  await page.goto(`/jobs/${jobId}`);

  // Header basics still there
  await expect(page.getByText('Analysis Report')).toBeVisible();
  await expect(page.getByText(`ID: ${jobId}`)).toBeVisible();

  // Overview tab is active by default
  await expect(page.getByTestId('tab-panel-overview')).toBeVisible();
  await expect(page.getByText('Executive Summary')).toBeVisible();
  await expect(page.getByText('Overall Severity')).toBeVisible();
  await expect(page.getByText('high', { exact: false })).toBeVisible();

  // Switch to Hosts tab and verify table content
  await page.getByTestId('tab-hosts').click();
  await expect(page.getByTestId('tab-panel-hosts')).toBeVisible();
  await expect(page.getByText('Host Findings')).toBeVisible();
  await expect(page.getByText('10.0.0.10')).toBeVisible();
  await expect(page.getByText('victim')).toBeVisible();
  await expect(page.getByText('Suspected initial compromise via phishing.')).toBeVisible();

  // Raw JSON tab shows pretty-printed JSON
  await page.getByTestId('tab-raw-json').click();
  await expect(page.getByTestId('tab-panel-raw-json')).toBeVisible();
  await expect(page.getByText('some')).toBeVisible();

  // Report tab exposes links
  await page.getByTestId('tab-report').click();
  await expect(page.getByTestId('tab-panel-report')).toBeVisible();
  await expect(page.getByTestId('link-report-html')).toBeVisible();
  await expect(page.getByTestId('link-report-markdown')).toBeVisible();
});

