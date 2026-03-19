import { test, expect } from '@playwright/test';

// End-to-end flow: start a new upload analysis and land on the Job Detail page.

test('@requires-backend can start a new upload analysis and see job detail', async ({ page }) => {
  const jobId = 'e2e-job-123';

  const uploadId = 'e2e-upload-001';

  // Stub upload endpoint (XHR-based multipart upload).
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

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}`, async (route) => {
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

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/summary`, async (route) => {
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

  // Go to New Analysis page.
  await page.goto('/new');

  // Upload a dummy PCAP file from the fixtures directory.
  await page.getByTestId('input-pcap-files').setInputFiles('tests/fixtures/dummy.pcap');

  // Submit the form.
  await page.getByTestId('btn-start-analysis').click();

  // We should navigate to the Job Detail page for this job id.
  await page.waitForURL(`**/jobs/${jobId}`);

  await expect(page.getByText('Job Detail')).toBeVisible();
  await expect(page.getByText(`ID: ${jobId}`)).toBeVisible();
});



// End-to-end flow: start a new Security Onion analysis and land on the Job Detail page.

test('@requires-backend can start a new Security Onion analysis and see job detail', async ({ page }) => {
  const jobId = 'e2e-so-job-456';

  await page.route('http://localhost:8000/api/v1/jobs/from_security_onion', async (route) => {
    await route.fulfill({
      status: 201,
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
        schema_version: '2.0',
        job: {
          job_id: jobId,
          status: 'completed',
          created_at: now,
          started_at: now,
          completed_at: now,
          execution_profile: 'standard',
          priority: 'normal',
          pcap_filename: 'so-capture.pcap',
          stages: [],
          sensors: [],
          pcaps: [],
          metrics: { durations: {}, pcap_stats: {} },
        },
      }),
    });
  });

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/summary`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: '2.0',
        job_id: jobId,
        headline: 'Security Onion analysis complete.',
        alert_count: 0,
        finding_count: 0,
        ioc_count: 0,
        host_count: 0,
        top_signals: [],
        recommendations: [],
      }),
    });
  });

  await page.goto('/new');

  await page.getByTestId('tab-security-onion').click();

  await page.getByTestId('input-so-start').fill('2025-05-01T10:00');
  await page.getByTestId('input-so-end').fill('2025-05-01T11:00');
  await page.getByTestId('input-so-sensors').fill('sensor1,sensor2');
  await page.getByTestId('select-so-mode').selectOption('single_window');
  await page.getByTestId('input-so-exercise-id').fill('ex-so-e2e');
  await page.getByTestId('input-so-notes').fill('E2E SO test');

  await page.getByTestId('btn-start-so-analysis').click();

  await page.waitForURL(`**/jobs/${jobId}`);

  await expect(page.getByText('Job Detail')).toBeVisible();
  await expect(page.getByText(`ID: ${jobId}`)).toBeVisible();
});



// End-to-end flow: start a new Arkime analysis and land on the Job Detail page.

test('@requires-backend can start a new Arkime analysis and see job detail', async ({ page }) => {
  const jobId = 'e2e-arkime-job-789';

  await page.route('http://localhost:8000/api/v1/jobs/from_arkime', async (route) => {
    await route.fulfill({
      status: 201,
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
        schema_version: '2.0',
        job: {
          job_id: jobId,
          status: 'completed',
          created_at: now,
          started_at: now,
          completed_at: now,
          execution_profile: 'standard',
          priority: 'normal',
          pcap_filename: 'arkime-capture.pcap',
          stages: [],
          sensors: [],
          pcaps: [],
          metrics: { durations: {}, pcap_stats: {} },
        },
      }),
    });
  });

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/summary`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: '2.0',
        job_id: jobId,
        headline: 'Arkime analysis complete.',
        alert_count: 0,
        finding_count: 0,
        ioc_count: 0,
        host_count: 0,
        top_signals: [],
        recommendations: [],
      }),
    });
  });

  await page.goto('/new');

  await page.getByTestId('tab-arkime').click();

  await page.getByTestId('input-arkime-start').fill('2025-05-01T10:00');
  await page.getByTestId('input-arkime-end').fill('2025-05-01T11:00');
  await page.getByTestId('input-arkime-filter').fill('ip.src == 10.0.0.1');
  await page.getByTestId('select-arkime-mode').selectOption('single_window');
  await page.getByTestId('input-arkime-exercise-id').fill('ex-arkime-e2e');
  await page.getByTestId('input-arkime-notes').fill('E2E Arkime test');

  await page.getByTestId('btn-start-arkime-analysis').click();

  await page.waitForURL(`**/jobs/${jobId}`);

  await expect(page.getByText('Job Detail')).toBeVisible();
  await expect(page.getByText(`ID: ${jobId}`)).toBeVisible();
});
