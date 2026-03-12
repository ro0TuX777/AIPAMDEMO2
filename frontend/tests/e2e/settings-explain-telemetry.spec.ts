import { test, expect } from '@playwright/test';

test('settings page surfaces explain telemetry and refreshes counts', async ({ page }) => {
  const initialTelemetryResponse = {
    schema_version: 'v1',
    explain_response_counts: { deterministic: 2, llm: 1, fallback: 0 },
    explain_latency_ms: { count: 3, average_ms: 42, min_ms: 20, max_ms: 80, last_ms: 35 },
  };
  const refreshedTelemetryResponse = {
    schema_version: 'v1',
    explain_response_counts: { deterministic: 2, llm: 3, fallback: 1 },
    explain_latency_ms: { count: 6, average_ms: 55, min_ms: 20, max_ms: 120, last_ms: 120 },
  };
  const resetTelemetryResponse = {
    schema_version: 'v1',
    explain_response_counts: { deterministic: 0, llm: 0, fallback: 0 },
    explain_latency_ms: { count: 0, average_ms: 0, min_ms: 0, max_ms: 0, last_ms: 0 },
  };
  let telemetryRequestCount = 0;
  let serveRefreshedTelemetry = false;
  let telemetryWasReset = false;

  await page.route('http://localhost:8000/api/v1/settings', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({}),
    });
  });

  await page.route('http://localhost:8000/api/v1/models/available', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ models: [] }),
    });
  });

  await page.route('http://localhost:8000/api/v1/system/config', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'v1',
        aipam_version: '2.0.0',
        max_upload_bytes: 1000,
        profiles_enabled: ['triage', 'standard', 'deep'],
        default_limits: {
          sensor_timeout_seconds: 600,
          max_extracted_bytes: 1000,
          max_job_disk_bytes: 1000,
        },
        explain_configuration: {
          mode: 'deterministic',
          llm_enabled: false,
          llm_model_name: 'aipam-trafficllm-v8',
          llm_endpoint: 'http://ollama:11434/v1/chat/completions',
        },
      }),
    });
  });

  await page.route('http://localhost:8000/api/v1/system/explain-telemetry', async (route) => {
    telemetryRequestCount += 1;
    await page.waitForTimeout(150);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(
        telemetryWasReset
          ? resetTelemetryResponse
          : serveRefreshedTelemetry
            ? refreshedTelemetryResponse
            : initialTelemetryResponse,
      ),
    });
  });

  await page.route('http://localhost:8000/api/v1/system/explain-telemetry/reset', async (route) => {
    telemetryWasReset = true;
    await page.waitForTimeout(150);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(resetTelemetryResponse),
    });
  });

  await page.goto('/settings');

  await expect(page.getByTestId('section-explain-telemetry')).toBeVisible();
  await expect(page.getByTestId('text-explain-telemetry-total')).toHaveText('3');
  await expect(page.getByTestId('text-explain-telemetry-deterministic')).toHaveText('2');
  await expect(page.getByTestId('text-explain-telemetry-llm')).toHaveText('1');
  await expect(page.getByTestId('text-explain-telemetry-fallback')).toHaveText('0');
  await expect(page.getByTestId('text-explain-telemetry-average-ms')).toHaveText('42 ms');
  await expect(page.getByTestId('text-explain-telemetry-last-ms')).toHaveText('35 ms');
  await expect(page.getByTestId('text-explain-telemetry-min-ms')).toHaveText('20 ms');
  await expect(page.getByTestId('text-explain-telemetry-max-ms')).toHaveText('80 ms');

  serveRefreshedTelemetry = true;
  await page.getByTestId('btn-refresh-explain-telemetry').click();

  await expect(page.getByTestId('text-explain-telemetry-total')).toHaveText('6');
  await expect(page.getByTestId('text-explain-telemetry-deterministic')).toHaveText('2');
  await expect(page.getByTestId('text-explain-telemetry-llm')).toHaveText('3');
  await expect(page.getByTestId('text-explain-telemetry-fallback')).toHaveText('1');
  await expect(page.getByTestId('text-explain-telemetry-average-ms')).toHaveText('55 ms');
  await expect(page.getByTestId('text-explain-telemetry-last-ms')).toHaveText('120 ms');
  await expect(page.getByTestId('text-explain-telemetry-min-ms')).toHaveText('20 ms');
  await expect(page.getByTestId('text-explain-telemetry-max-ms')).toHaveText('120 ms');

  await page.getByTestId('btn-reset-explain-telemetry').click();

  await expect(page.getByTestId('text-explain-telemetry-total')).toHaveText('0');
  await expect(page.getByTestId('text-explain-telemetry-deterministic')).toHaveText('0');
  await expect(page.getByTestId('text-explain-telemetry-llm')).toHaveText('0');
  await expect(page.getByTestId('text-explain-telemetry-fallback')).toHaveText('0');
  await expect(page.getByTestId('text-explain-telemetry-average-ms')).toHaveText('0 ms');
  await expect(page.getByTestId('text-explain-telemetry-last-ms')).toHaveText('0 ms');
  await expect(page.getByTestId('text-explain-telemetry-min-ms')).toHaveText('0 ms');
  await expect(page.getByTestId('text-explain-telemetry-max-ms')).toHaveText('0 ms');
  expect(telemetryRequestCount).toBeGreaterThanOrEqual(2);
});