import { expect, test } from "@playwright/test";

test("full offline demo chat renders legacy history and accepts a new question", async ({ page }) => {
  test.skip(process.env.E2E_DEMO !== "true", "Run against a VITE_AIPAM_DEMO_MODE=true server");
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/jobs/a7f3c2e1-9b04-4d17-8e62-3fc51a0d7b88/chat");
  await expect(page.getByText("What hosts were compromised?", { exact: true })).toBeVisible();
  await expect(page.getByText(/One host is confirmed compromised/)).toBeVisible();
  await page.getByPlaceholder("Ask about the findings...").fill("What should we contain first?");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.getByText(/In order: isolate/)).toBeVisible();
  expect(errors).toEqual([]);
});
