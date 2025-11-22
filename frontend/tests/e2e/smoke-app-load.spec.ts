import { test, expect } from '@playwright/test';

// Basic smoke test to ensure the app loads and main layout renders.

test('app loads and shows dashboard by default', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByTestId('app-root')).toBeVisible();
  await expect(page.getByTestId('nav-dashboard')).toBeVisible();
  await expect(page.getByTestId('main-content')).toBeVisible();
});

