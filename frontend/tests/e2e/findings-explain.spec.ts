import { test, expect } from '@playwright/test';

const jobId = 'e2e-findings-job-001';
const findingId = 'finding-explain-001';
const findingsUrl = `http://localhost:8000/api/v1/jobs/${jobId}/findings?limit=200`;
const findingDetailUrl = `http://localhost:8000/api/v1/jobs/${jobId}/findings/${findingId}`;
const explainUrl = `http://localhost:8000/api/v1/jobs/${jobId}/findings/${findingId}/explain`;

function buildExplainResponse(format: 'markdown' | 'text', requestNumber: number) {
  const body = `${format.toUpperCase()} explanation request ${requestNumber}`;
  return {
    schema_version: 'v1',
    format,
    content: body,
    source: 'deterministic',
    warning: null,
    explanation_feedback: null,
    sections: [
      {
        id: 'assessment',
        title: 'Assessment',
        body,
        bullets: [],
        citations: ['finding.summary'],
      },
      {
        id: 'why_it_matters',
        title: 'Why this matters',
        body: `Why ${body}`,
        bullets: [],
        citations: ['finding.sensor'],
      },
      {
        id: 'recommended_next_steps',
        title: 'Recommended next steps',
        bullets: [`Review ${format} explanation ${requestNumber}`],
        citations: ['finding.evidence.example'],
      },
    ],
    evidence_items: [
      {
        label: 'Example',
        value: `${format} evidence ${requestNumber}`,
        citation: 'finding.evidence.example',
      },
    ],
  };
}

async function mockFindingsList(page: Parameters<typeof test>[0]['page']) {
  await page.route(findingsUrl, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'v1',
        items: [
          {
            finding_id: findingId,
            title: 'Suspicious beaconing activity',
            severity: 'medium',
            category: 'command_and_control',
            sensor: 'suricata',
            pcap_label: 'sample.pcap',
            summary: 'Beaconing pattern detected.',
            evidence: { example: 'value' },
            feedback: null,
          },
        ],
        page: { next_cursor: null, has_more: false },
      }),
    });
  });
}

async function mockFindingDetail(page: Parameters<typeof test>[0]['page']) {
  await page.route(findingDetailUrl, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        finding_id: findingId,
        title: 'Suspicious beaconing activity',
        severity: 'medium',
        category: 'command_and_control',
        sensor: 'suricata',
        pcap_label: 'sample.pcap',
        summary: 'Beaconing pattern detected.',
        evidence: { example: 'value' },
        feedback: null,
        confidence: 0.72,
        community_id: '1:abc',
        explanation_feedback: null,
        related_hosts: [],
        related_alerts: [],
        related_connections: [],
      }),
    });
  });
}

function buildBusyExplainError(status: 429 | 503, retryAfterSeconds: number) {
  return {
    status,
    contentType: 'application/json',
    headers: {
      'Retry-After': String(retryAfterSeconds),
    },
    body: JSON.stringify({
      schema_version: '1.0',
      error: status === 503 ? 'Analysis queue full, retry shortly.' : 'LLM busy, retry shortly.',
      code: status === 503 ? 'LLM_QUEUE_FULL' : 'LLM_BUSY',
      details: { retry_after: retryAfterSeconds },
    }),
  };
}

test('findings explain supports format switching and regenerate reuses selected format', async ({ page }) => {
  const explainFormats: string[] = [];

  await mockFindingsList(page);

  await page.route(explainUrl, async (route) => {
    const body = route.request().postDataJSON() as { format: 'markdown' | 'text' };
    explainFormats.push(body.format);
    await page.waitForTimeout(150);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(buildExplainResponse(body.format, explainFormats.length)),
    });
  });

  await page.goto(`/jobs/${jobId}/findings`);

  await expect(page.getByText('Suspicious beaconing activity')).toBeVisible();

  await page.getByTestId(`btn-explain-${findingId}`).click();
  const explainPanel = page.getByTestId(`explain-panel-${findingId}`);
  await expect(explainPanel).toBeVisible();
  await expect(explainPanel.getByText('MARKDOWN explanation request 1', { exact: true })).toBeVisible();
  await expect(page.getByTestId(`btn-explain-format-markdown-${findingId}`)).toBeDisabled();
  expect(explainFormats).toEqual(['markdown']);

  await page.getByTestId(`btn-explain-format-text-${findingId}`).click();
  await expect(explainPanel.getByText('Regenerating text grounded explanation…', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('MARKDOWN explanation request 1', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('TEXT explanation request 2', { exact: true })).toBeVisible();
  await expect(page.getByTestId(`btn-explain-format-text-${findingId}`)).toBeDisabled();
  expect(explainFormats).toEqual(['markdown', 'text']);

  await page.getByTestId(`btn-explain-regenerate-${findingId}`).click();
  await expect(explainPanel.getByText('Regenerating text grounded explanation…', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('TEXT explanation request 2', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('TEXT explanation request 3', { exact: true })).toBeVisible();
  expect(explainFormats).toEqual(['markdown', 'text', 'text']);
});

test('finding detail reuses cached explanation across queue navigation', async ({ page }) => {
  let requestCount = 0;

  await mockFindingsList(page);
  await mockFindingDetail(page);

  await page.route(explainUrl, async (route) => {
    requestCount += 1;
    const body = route.request().postDataJSON() as { format: 'markdown' | 'text' };
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(buildExplainResponse(body.format, requestCount)),
    });
  });

  await page.goto(`/jobs/${jobId}/findings`);
  await page.getByTestId(`btn-explain-${findingId}`).click();
  await expect(page.getByText('MARKDOWN explanation request 1', { exact: true })).toBeVisible();
  expect(requestCount).toBe(1);

  await page.getByTestId(`link-finding-detail-${findingId}`).click();
  await expect(page).toHaveURL(new RegExp(`/jobs/${jobId}/findings/${findingId}$`));
  await expect(page.getByText('Grounded explanation')).toBeVisible();
  await expect(page.getByText('MARKDOWN explanation request 1', { exact: true })).toBeVisible();
  expect(requestCount).toBe(1);

  await page.getByRole('link', { name: 'Back to queue' }).click();
  await expect(page).toHaveURL(new RegExp(`/jobs/${jobId}/findings$`));
  await page.getByTestId(`btn-explain-${findingId}`).click();
  await expect(page.getByText('MARKDOWN explanation request 1', { exact: true })).toBeVisible();
  expect(requestCount).toBe(1);
});

test('findings explain auto-retries on 429 busy responses with countdown messaging', async ({ page }) => {
  const explainFormats: string[] = [];
  let requestCount = 0;

  await mockFindingsList(page);
  await page.route(explainUrl, async (route) => {
    const body = route.request().postDataJSON() as { format: 'markdown' | 'text' };
    explainFormats.push(body.format);
    requestCount += 1;

    if (requestCount === 1) {
      await route.fulfill(buildBusyExplainError(429, 1));
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(buildExplainResponse(body.format, requestCount)),
    });
  });

  await page.goto(`/jobs/${jobId}/findings`);
  await page.getByTestId(`btn-explain-${findingId}`).click();

  const explainPanel = page.getByTestId(`explain-panel-${findingId}`);
  const retryBanner = page.getByTestId(`text-explain-retry-status-${findingId}`);
  await expect(explainPanel).toBeVisible();
  await expect(retryBanner).toContainText('LLM busy, retrying in 1s');
  await expect(page.getByTestId(`btn-explain-regenerate-${findingId}`)).toBeVisible();
  await expect(explainPanel.getByText('MARKDOWN explanation request 2', { exact: true })).toBeVisible({ timeout: 3000 });
  expect(explainFormats).toEqual(['markdown', 'markdown']);
});

test('findings explain auto-retries on 503 queue-full responses with countdown messaging', async ({ page }) => {
  const explainFormats: string[] = [];
  let requestCount = 0;

  await mockFindingsList(page);
  await page.route(explainUrl, async (route) => {
    const body = route.request().postDataJSON() as { format: 'markdown' | 'text' };
    explainFormats.push(body.format);
    requestCount += 1;

    if (requestCount === 1) {
      await route.fulfill(buildBusyExplainError(503, 1));
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(buildExplainResponse(body.format, requestCount)),
    });
  });

  await page.goto(`/jobs/${jobId}/findings`);
  await page.getByTestId(`btn-explain-${findingId}`).click();

  const explainPanel = page.getByTestId(`explain-panel-${findingId}`);
  const retryBanner = page.getByTestId(`text-explain-retry-status-${findingId}`);
  await expect(explainPanel).toBeVisible();
  await expect(retryBanner).toContainText('Analysis queue full, retrying in 1s');
  await expect(page.getByTestId(`btn-explain-regenerate-${findingId}`)).toBeVisible();
  await expect(explainPanel.getByText('MARKDOWN explanation request 2', { exact: true })).toBeVisible({ timeout: 3000 });
  expect(explainFormats).toEqual(['markdown', 'markdown']);
});