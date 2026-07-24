import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", items: [], page: { has_more: false } }) }));
  await page.route("**/api/v1/settings/setup_status", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", model_configured: true }) }));
});

/** True if the active element is inside the given dialog. */
async function focusInside(page: import("@playwright/test").Page, testid: string) {
  return page.evaluate((id) => {
    const dialog = document.querySelector(`[data-testid="${id}"] [role="dialog"], [data-testid="${id}"]`);
    return !!dialog && dialog.contains(document.activeElement);
  }, testid);
}

test("command palette traps Tab and restores focus on close", async ({ page }) => {
  await page.goto("/jobs");
  const opener = page.getByTestId("open-command-palette");
  await opener.focus();

  await page.keyboard.press("Control+k");
  await expect(page.getByTestId("command-palette")).toBeVisible();
  // Focus moved into the dialog (onto the search input).
  await expect(page.getByTestId("command-input")).toBeFocused();

  // Tab several times — focus must stay inside the dialog, never on the page.
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press("Tab");
    expect(await focusInside(page, "command-palette")).toBe(true);
  }
  // Shift+Tab too.
  await page.keyboard.press("Shift+Tab");
  expect(await focusInside(page, "command-palette")).toBe(true);

  // Close → focus returns to the button that opened it.
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("command-palette")).toHaveCount(0);
  await expect(opener).toBeFocused();
});

test("first-time setup modal is a labelled dialog that traps focus", async ({ page }) => {
  // model_configured:false makes the setup modal appear on boot.
  await page.route("**/api/v1/settings/setup_status", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ schema_version: "2.0", model_configured: false }) }));
  await page.route("**/api/v1/models/available", (r) =>
    r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ models: [{ name: "llama3:8b", size: 4700000000 }, { name: "mistral:7b", size: 4100000000 }] }) }));

  await page.goto("/jobs");
  const modal = page.getByTestId("model-setup-modal");
  await expect(modal).toBeVisible();
  // Proper dialog semantics for assistive tech.
  await expect(modal.getByRole("dialog")).toHaveAttribute("aria-modal", "true");

  // Focus is inside the modal, and Tab keeps it there.
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press("Tab");
    expect(await focusInside(page, "model-setup-modal")).toBe(true);
  }
});

test("shortcuts help traps Tab and restores focus on close", async ({ page }) => {
  await page.goto("/jobs");
  // Give the body a known focus owner to restore to.
  await page.getByTestId("nav-jobs").focus();

  await page.keyboard.press("?");
  await expect(page.getByTestId("shortcuts-help")).toBeVisible();

  for (let i = 0; i < 4; i++) {
    await page.keyboard.press("Tab");
    expect(await focusInside(page, "shortcuts-help")).toBe(true);
  }

  await page.keyboard.press("Escape");
  await expect(page.getByTestId("shortcuts-help")).toHaveCount(0);
  await expect(page.getByTestId("nav-jobs")).toBeFocused();
});
