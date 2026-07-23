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

  // Sub-page navigation is grouped: a group row, plus the open group's tabs.
  const tabs = page.getByTestId('jobdetail-tabs');
  await expect(tabs).toBeVisible();

  for (const group of ['triage', 'evidence', 'analysis', 'output']) {
    await expect(page.getByTestId(`job-nav-group-${group}`)).toBeVisible();
  }

  // Triage opens by default on the job detail page.
  await expect(tabs.getByRole('link', { name: '🔎 Investigate' })).toBeVisible();

  // Selecting a group reveals its pages without navigating away.
  await page.getByTestId('job-nav-group-evidence').click();
  await expect(tabs.getByRole('link', { name: 'Hosts' })).toBeVisible();
  await expect(tabs.getByRole('link', { name: 'Alerts' })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/jobs/${jobId}$`));

  await page.getByTestId('job-nav-group-analysis').click();
  await expect(tabs.getByRole('link', { name: 'Theories' })).toBeVisible();

  await page.getByTestId('job-nav-group-output').click();
  await expect(tabs.getByRole('link', { name: 'Report' })).toBeVisible();

  // Compare is temporal-only and this job has a single PCAP.
  await expect(tabs.getByRole('link', { name: '🔬 Compare' })).toHaveCount(0);
});

test('@requires-backend compare tab is reachable from any sub-page of a temporal job', async ({ page }) => {
  const jobId = 'e2e-job-temporal-001';
  const now = new Date().toISOString();

  await page.route(`**/api/v1/jobs/${jobId}`, async (route) => {
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
          pcap_filename: 'before.pcap',
          stages: [],
          sensors: [],
          // Two PCAPs → temporal job → Compare must be offered.
          pcaps: [
            { id: 1, filename: 'before.pcap', label: 'before' },
            { id: 2, filename: 'after.pcap', label: 'after' },
          ],
          metrics: { durations: {}, pcap_stats: {} },
        },
      }),
    });
  });
  await page.route(`**/api/v1/jobs/${jobId}/timeline*`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ schema_version: '2.0', items: [], page: { has_more: false } }),
    });
  });

  // Land on Timeline — a page in a *different* group from Compare. Previously
  // Compare vanished from the nav everywhere except the job detail page.
  await page.goto(`/jobs/${jobId}/timeline`);

  const nav = page.getByTestId('job-subpage-nav');
  await expect(nav).toBeVisible();

  await page.getByTestId('job-nav-group-analysis').click();
  await expect(nav.getByRole('link', { name: '🔬 Compare' })).toBeVisible();
});

