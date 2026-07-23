import { test, expect } from "@playwright/test";

// A code-split chunk that 404s (the stale-index.html-after-redeploy case) must
// not blank the whole app — the shell survives and a reload is offered.
test("a failed route chunk shows the error UI, not a blank app", async ({ page }) => {
  // Fail the Settings page's lazy chunk. Vite dev serves the module from a URL
  // containing the source path, so matching on SettingsPage catches it.
  await page.route("**/SettingsPage*", (route) => route.abort());

  await page.goto("/jobs");
  await expect(page.getByTestId("nav-jobs")).toBeVisible();

  await page.getByTestId("nav-settings").click();

  // The boundary renders instead of unmounting the tree.
  await expect(page.getByTestId("route-error")).toBeVisible();
  await expect(page.getByTestId("route-error-reload")).toBeVisible();

  // The app shell is intact — navigation still works.
  await expect(page.getByTestId("nav-jobs")).toBeVisible();
});

test("navigating away from a broken route recovers", async ({ page }) => {
  await page.route("**/SettingsPage*", (route) => route.abort());

  await page.goto("/jobs");
  await page.getByTestId("nav-settings").click();
  await expect(page.getByTestId("route-error")).toBeVisible();

  // Going somewhere whose chunk loads fine clears the error via the resetKey.
  await page.getByTestId("nav-jobs").click();
  await expect(page.getByTestId("route-error")).toHaveCount(0);
  await expect(page).toHaveURL(/\/jobs$/);
});
