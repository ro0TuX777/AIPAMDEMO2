import { test, expect } from "@playwright/test";

// Screenshots are written only when a test fails (see playwright.config.ts).

function luminance(rgb: string): number {
  const m = rgb.match(/\d+/g)!;
  const [r, g, b] = m.slice(0, 3).map(Number);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

test('light mode: hover states stay readable', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('aipam-theme', 'light'));
  await page.goto('/jobs');
  await page.waitForTimeout(800);

  // A nav link using hover:text-white — previously went white-on-light.
  const link = page.getByTestId('nav-settings');
  const before = await link.evaluate((el) => getComputedStyle(el).color);
  await link.hover();
  await page.waitForTimeout(150);
  const after = await link.evaluate((el) => getComputedStyle(el).color);

  console.log('LIGHT nav link colour: rest =', before, '| hover =', after);
  // Must remain dark text on the light surface, not white.
  expect(luminance(after)).toBeLessThan(128);

});

test('light mode: max-contrast hover on a breadcrumb link is not white-on-light', async ({ page }) => {
  const jobId = 'hover-job-1';
  const now = new Date().toISOString();
  await page.route(`**/api/v1/jobs/${jobId}`, (route) =>
    route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ schema_version: '2.0', job: {
        job_id: jobId, status: 'completed', created_at: now, started_at: now, completed_at: now,
        execution_profile: 'standard', priority: 'normal', pcap_filename: 'c.pcap',
        stages: [], sensors: [], pcaps: [], metrics: { durations: {}, pcap_stats: {} } } }),
    }));

  await page.addInitScript(() => localStorage.setItem('aipam-theme', 'light'));
  await page.goto(`/jobs/${jobId}`);
  await page.waitForTimeout(600);

  // "Brighten on hover" is expressed as slate-50 — the end of the neutral ramp —
  // rather than literal white, which is theme-blind and stayed white-on-light.
  const crumb = page.getByTestId('breadcrumbs').getByRole('link', { name: 'Jobs' });
  await expect(crumb).toHaveClass(/hover:text-slate-50/);
  await crumb.hover();
  await page.waitForTimeout(150);
  const colour = await crumb.evaluate((el) => getComputedStyle(el).color);

  console.log('LIGHT breadcrumb max-contrast hover resolves to', colour);
  expect(luminance(colour)).toBeLessThan(128);
});

test('literal text-white is reserved for coloured buttons, where it stays white', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('aipam-theme', 'light'));
  await page.goto('/jobs');
  await page.waitForTimeout(600);

  // The "New Analysis" CTA sits on an emerald fill in both themes.
  const cta = page.getByRole('link', { name: 'New Analysis' }).last();
  const colour = await cta.evaluate((el) => getComputedStyle(el).color);
  console.log('LIGHT coloured-button text colour =', colour);
  expect(luminance(colour)).toBeGreaterThan(200);
});

test('dark mode: hover states unchanged', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('aipam-theme', 'dark'));
  await page.goto('/jobs');
  await page.waitForTimeout(800);

  const link = page.getByTestId('nav-settings');
  await link.hover();
  await page.waitForTimeout(150);
  const after = await link.evaluate((el) => getComputedStyle(el).color);

  console.log('DARK nav link hover colour =', after);
  // Dark theme is untouched: hover:text-white must still resolve to white.
  expect(luminance(after)).toBeGreaterThan(200);
});
