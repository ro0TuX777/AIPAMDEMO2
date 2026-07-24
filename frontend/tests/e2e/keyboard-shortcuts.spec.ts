import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  // Catch-all first; the specific setup_status stub is registered last so it
  // wins (Playwright's last-registered matching route takes precedence).
  await page.route("**/api/v1/**", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", items: [], page: { has_more: false } }) }));
  await page.route("**/api/v1/settings/setup_status", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", model_configured: true }) }));
});

test("g-chords jump between sections", async ({ page }) => {
  await page.goto("/jobs");
  await expect(page.getByTestId("nav-jobs")).toBeVisible();

  await page.keyboard.press("g");
  await page.keyboard.press("s");
  await expect(page).toHaveURL(/\/settings$/);

  await page.keyboard.press("g");
  await page.keyboard.press("h");
  await expect(page).toHaveURL(/\/hosts$/);
});

test("? opens the shortcuts help; Escape closes it", async ({ page }) => {
  await page.goto("/jobs");
  await expect(page.getByTestId("nav-jobs")).toBeVisible();

  await page.keyboard.press("?");
  await expect(page.getByTestId("shortcuts-help")).toBeVisible();
  await expect(page.getByText("Open command palette / search")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.getByTestId("shortcuts-help")).toHaveCount(0);
});

test("shortcuts are suppressed while typing in an input", async ({ page }) => {
  await page.goto("/jobs");
  // The jobs search box is a text input.
  const search = page.getByPlaceholder(/Search jobs/);
  await search.click();
  await search.type("gs?");
  // Typing "g", "s", "?" must not navigate away (the search box may add ?q=)
  // or open help.
  await expect(page).toHaveURL(/\/jobs(\?|$)/);
  await expect(page.getByTestId("shortcuts-help")).toHaveCount(0);
  await expect(search).toHaveValue("gs?");
});
