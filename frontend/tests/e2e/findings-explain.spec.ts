import { test, expect } from '@playwright/test';

const jobId = 'e2e-findings-job-001';
const findingId = 'finding-explain-001';

function buildExplainResponse(format: 'markdown' | 'text', requestNumber: number) {
  const body = `${format.toUpperCase()} explanation request ${requestNumber}`;
  return {
    schema_version: 'v1',
    format,
    content: body,
    duration_ms: requestNumber * 25,
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

test('findings explain supports format switching and regenerate reuses selected format', async ({ page }) => {
  const explainFormats: string[] = [];

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/findings?limit=200`, async (route) => {
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

  await page.route(`http://localhost:8000/api/v1/jobs/${jobId}/findings/${findingId}/explain`, async (route) => {
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
  await expect(page.getByTestId(`text-explain-duration-${findingId}`)).toHaveText('25 ms');
  await expect(page.getByTestId(`btn-explain-format-markdown-${findingId}`)).toBeDisabled();
  expect(explainFormats).toEqual(['markdown']);

  await page.getByTestId(`btn-explain-format-text-${findingId}`).click();
  await expect(explainPanel.getByText('Regenerating text grounded explanation…', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('MARKDOWN explanation request 1', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('TEXT explanation request 2', { exact: true })).toBeVisible();
  await expect(page.getByTestId(`text-explain-duration-${findingId}`)).toHaveText('50 ms');
  await expect(page.getByTestId(`btn-explain-format-text-${findingId}`)).toBeDisabled();
  expect(explainFormats).toEqual(['markdown', 'text']);

  await page.getByTestId(`btn-explain-regenerate-${findingId}`).click();
  await expect(explainPanel.getByText('Regenerating text grounded explanation…', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('TEXT explanation request 2', { exact: true })).toBeVisible();
  await expect(explainPanel.getByText('TEXT explanation request 3', { exact: true })).toBeVisible();
  await expect(page.getByTestId(`text-explain-duration-${findingId}`)).toHaveText('75 ms');
  expect(explainFormats).toEqual(['markdown', 'text', 'text']);
});