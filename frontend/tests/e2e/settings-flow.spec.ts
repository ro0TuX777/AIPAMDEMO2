import { test, expect } from '@playwright/test';

// End-to-end flow: load Settings page, modify values, save, and test LLM connection.

test('can load and update settings and test LLM connection', async ({ page }) => {
  // Stub backend GET /settings to provide initial values.
  await page.route('http://localhost:8000/api/v1/settings', async (route) => {
    if (route.request().method() === 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          llm_endpoint: 'http://localhost:11434/v1/chat/completions',
          llm_model_name: 'local-llm',
          llm_max_tokens: 1024,
          llm_temperature: 0.2,
          security_onion_mode: 'filesystem',
          security_onion_base_pcap_path: '/srv/aipam/so-pcaps',
          file_storage_path: '/srv/aipam/storage',
        }),
      });
    } else {
      // Let non-GET fall through to other handlers.
      await route.fallback();
    }
  });

  // Stub PUT /settings to echo back the updated payload.
  await page.route('http://localhost:8000/api/v1/settings', async (route) => {
    if (route.request().method() === 'PUT') {
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

  // Stub POST /settings/test_llm to always report success.
  await page.route('http://localhost:8000/api/v1/settings/test_llm', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true }),
    });
  });

  // Navigate directly to the settings page.
  await page.goto('/settings');

  // Ensure the page loaded.
  await expect(page.getByTestId('page-settings')).toBeVisible();

  // Modify some LLM settings.
  await page.getByTestId('input-llm-endpoint').fill('http://example-llm');
  await page.getByTestId('input-llm-model-name').fill('example-model');
  await page.getByTestId('input-llm-max-tokens').fill('2048');
  await page.getByTestId('input-llm-temperature').fill('0.3');

  // Change Security Onion mode and base path.
  await page.getByTestId('select-so-mode-settings').selectOption('filesystem');
  await page.getByTestId('input-so-base-pcap-path').fill('/srv/aipam/so-pcaps-updated');

  // Change storage path.
  await page.getByTestId('input-file-storage-path').fill('/srv/aipam/storage-updated');

  // Save settings.
  await page.getByTestId('btn-save-settings').click();

  // Expect a success message to appear.
  await expect(page.getByText('Settings saved')).toBeVisible();

  // Test LLM connection.
  await page.getByTestId('btn-test-llm').click();

  // Expect a positive LLM test result message.
  await expect(page.getByText('LLM connection OK')).toBeVisible();
});

