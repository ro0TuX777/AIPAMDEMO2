import { test, expect } from '@playwright/test';

// Simple navigation test that uses data-testid selectors on the main nav.

test('can navigate between main pages', async ({ page }) => {
  await page.goto('/');

  // Jobs is the default route
  await expect(page).toHaveURL(/\/jobs$/);
  await expect(page.getByTestId('nav-jobs')).toBeVisible();

  // Go to New Analysis
  await page.getByTestId('nav-new-analysis').click();
  await expect(page).toHaveURL(/\/new$/);
  await expect(page.getByTestId('main-content')).toBeVisible();

  // Go to Settings
  await page.getByTestId('nav-settings').click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByTestId('main-content')).toBeVisible();
});

