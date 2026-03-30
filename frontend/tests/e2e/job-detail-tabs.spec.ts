import { test, expect } from '@playwright/test';

// Focused coverage for Job Detail page header, summary, and sub-page navigation links.

test('@requires-backend job detail page renders header and navigation links', async ({ page }) => {
  const jobId = 'e2e-job-tabs-001';

  // Stub job detail
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

  // Stub job summary (separate endpoint)
  await page.route(`**/api/v1/jobs/${jobId}/summary`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: '2.0',
        job_id: jobId,
        headline: 'Test analysis complete.',
        alert_count: 2,
        finding_count: 5,
        ioc_count: 1,
        host_count: 3,
        top_signals: ['Signal A'],
        recommendations: ['Check host 10.0.0.1'],
      }),
    });
  });

  await page.goto(`/jobs/${jobId}`);

  // Header
  await expect(page.getByText('Job Detail')).toBeVisible();
  await expect(page.getByText(`ID: ${jobId}`)).toBeVisible();

  // Summary card
  await expect(page.getByText('Summary')).toBeVisible();
  await expect(page.getByText('Test analysis complete.')).toBeVisible();

  // Sub-page navigation links exist (scoped to jobdetail-tabs to avoid nav sidebar matches)
  const tabs = page.getByTestId('jobdetail-tabs');
  await expect(tabs).toBeVisible();
  await expect(tabs.getByRole('link', { name: 'Theories' })).toBeVisible();
  await expect(tabs.getByRole('link', { name: 'Hosts' })).toBeVisible();
  await expect(tabs.getByRole('link', { name: 'Alerts' })).toBeVisible();
  await expect(tabs.getByRole('link', { name: 'Report' })).toBeVisible();
});

