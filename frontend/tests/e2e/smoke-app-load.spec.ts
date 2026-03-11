import { test, expect } from '@playwright/test';

// Basic smoke test to ensure the app loads and main layout renders.

test('app loads and shows jobs by default', async ({ page }) => {
  await page.goto('/');

  await expect(page).toHaveURL(/\/jobs$/);
  await expect(page.getByTestId('app-root')).toBeVisible();
  await expect(page.getByTestId('nav-jobs')).toBeVisible();
  await expect(page.getByTestId('main-content')).toBeVisible();
});

