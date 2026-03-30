import { test, expect } from '@playwright/test';

test('settings page surfaces explain configuration', async ({ page }) => {
  await page.route('**/api/v1/settings', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({}),
    });
  });

  await page.route('**/api/v1/models/available', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ models: [] }),
    });
  });

  await page.route('**/api/v1/system/explain-telemetry', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'v1',
        explain_response_counts: { deterministic: 0, llm: 0, fallback: 0 },
        explain_latency_ms: { count: 0, average_ms: 0, min_ms: 0, max_ms: 0, last_ms: 0 },
      }),
    });
  });

  await page.route('**/api/v1/system/config', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'v1',
        aipam_version: '2.0.0',
        max_upload_bytes: 1048576,
        profiles_enabled: ['triage', 'standard', 'deep'],
        default_limits: {
          sensor_timeout_seconds: 600,
          max_extracted_bytes: 4096,
          max_job_disk_bytes: 1048576,
        },
        explain_configuration: {
          mode: 'llm',
          llm_enabled: true,
          llm_model_name: 'demo-model:latest',
          llm_endpoint: 'http://ollama.internal/v1/chat/completions',
        },
      }),
    });
  });

  await page.goto('/settings');

  // Expand the Advanced section (collapsed by default).
  await page.getByText('Advanced').click();

  await expect(page.getByTestId('section-explain-config')).toBeVisible();
  await expect(page.getByTestId('text-explain-config-mode')).toHaveText('LLM-enabled');
  await expect(page.getByTestId('text-explain-config-model')).toHaveText('demo-model:latest');
  await expect(page.getByTestId('text-explain-config-endpoint')).toHaveText(
    'http://ollama.internal/v1/chat/completions',
  );
  await expect(page.getByTestId('text-explain-config-mode-description')).toContainText(
    'try the configured LLM first',
  );
});