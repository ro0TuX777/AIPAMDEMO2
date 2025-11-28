import { test, expect } from '@playwright/test';

// Debug flow: load Settings page, toggle effective settings debug panel, and load effective runtime settings.

test('can view effective runtime settings debug panel', async ({ page }) => {
  // Stub backend GET /settings to provide initial values; sufficient for page to render.
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
      await route.fallback();
    }
  });

  // Stub admin effective settings endpoint.
  await page.route('http://localhost:8000/api/v1/admin/effective_settings', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        llm_endpoint: 'http://localhost:11434/v1/chat/completions',
        llm_model_name: 'effective-model',
        llm_max_tokens: 4096,
        llm_temperature: 0.4,
        file_storage_path: '/srv/aipam/effective-storage',
        reports_path: '/srv/aipam/effective-storage/reports',
        security_onion_mode: 'filesystem',
        security_onion_base_pcap_path: '/srv/aipam/so-pcaps',
        security_onion_zeek_log_path: '/srv/aipam/so-zeek',
        security_onion_suricata_log_path: '/srv/aipam/so-suricata',
        security_onion_api_url: null,
        security_onion_api_token: null,
        arkime_api_url: 'http://arkime.local/api',
        arkime_api_username: 'admin',
        arkime_api_password: 'secret',
      }),
    });
  });

  await page.goto('/settings');
  await expect(page.getByTestId('page-settings')).toBeVisible();

  // Debug section is present but collapsed by default.
  await expect(page.getByTestId('section-effective-settings-debug')).toBeVisible();

  // Enable debug view.
  await page.getByTestId('toggle-effective-settings-debug').check();

  // Load effective settings.
  await page.getByTestId('btn-load-effective-settings').click();

  // Expect JSON pre block to be visible and contain some key from the stub.
  const pre = page.getByTestId('pre-effective-settings-json');
  await expect(pre).toBeVisible();
  await expect(pre).toContainText('effective-model');
  await expect(pre).toContainText('/srv/aipam/effective-storage');
});

