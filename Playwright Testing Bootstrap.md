Got you. Here’s a reusable “Testing Bootstrap” checklist you can copy-paste to Augment for any future web app.

You can literally send this as a prompt:

⸻

🔧 Standard Playwright Testing Bootstrap Instructions (for Augment)

Goal:
Set up a reusable, automated end-to-end (E2E) testing framework using Playwright for this project, including:
	•	Stable UI selectors via data-testid
	•	Core E2E tests for main flows
	•	A JSON issues report for failures
	•	CI integration to run tests automatically

Follow these steps exactly.

⸻

1. Detect the Frontend App
	1.	Locate the frontend in this repo:
	•	Look for package.json.
	•	Common paths: ./frontend, ./web, ./app, or repo root.
	2.	Once found, treat that directory as the frontend root for all Playwright work.

If there is no frontend, stop.

⸻

2. Install & Initialize Playwright

In the frontend root:
	1.	Ensure dependencies are installed:

npm install


	2.	Install Playwright:

npm install -D @playwright/test
npx playwright install


	3.	Create the E2E test structure:

frontend/
  tests/
    e2e/
      (test files will go here)
    e2e/reporters/
      json-issues-reporter.ts



⸻

3. Add data-testid to Key UI Elements

Update the frontend code to add stable test IDs to important elements:
	•	Primary buttons (create, save, submit, next, cancel)
	•	Navigation links (sidebar, top nav, tabs)
	•	Main forms and critical inputs
	•	Any key state indicators (status badges, toasts, etc.)

Example pattern:

<button data-testid="btn-new-item">New Item</button>
<input data-testid="input-username" ... />
<button data-testid="tab-settings">Settings</button>
<span data-testid="status-badge">Running</span>

Use a clear, consistent naming scheme:
	•	btn-* for buttons
	•	input-* for inputs
	•	tab-* for tabs
	•	row-* for table rows, etc.

All E2E tests must use getByTestId selectors.

⸻

4. Create a Standard Playwright Config

In the frontend root, create playwright.config.ts:

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 60_000,
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  reporter: [
    ['list'],
    ['./tests/e2e/reporters/json-issues-reporter.ts'],
  ],
});


⸻

5. Implement JSON Issues Reporter

In frontend/tests/e2e/reporters/json-issues-reporter.ts, create a custom reporter that writes all test results into playwright-report/playwright-issues.json with this shape:

[
  {
    "test_file": "tests/e2e/example.spec.ts",
    "test_name": "example test name",
    "status": "passed|failed|skipped",
    "error_message": "only if failed",
    "screenshot_path": "optional",
    "trace_path": "optional"
  }
]

Use code similar to:

import type { Reporter, TestCase, TestResult, FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

type IssueEntry = {
  test_file: string;
  test_name: string;
  status: 'passed' | 'failed' | 'skipped';
  error_message?: string;
  screenshot_path?: string;
  trace_path?: string;
};

class JsonIssuesReporter implements Reporter {
  private issues: IssueEntry[] = [];

  onTestEnd(test: TestCase, result: TestResult) {
    const relativeFile = path.relative(process.cwd(), test.location.file);

    const entry: IssueEntry = {
      test_file: relativeFile,
      test_name: test.title,
      status: result.status,
    };

    if (result.status === 'failed') {
      entry.error_message = result.error?.message;
      for (const attachment of result.attachments) {
        if (attachment.name === 'screenshot') {
          entry.screenshot_path = attachment.path || undefined;
        }
        if (attachment.name === 'trace') {
          entry.trace_path = attachment.path || undefined;
        }
      }
    }

    this.issues.push(entry);
  }

  async onEnd(config: FullConfig) {
    const outputDir = path.resolve(process.cwd(), 'playwright-report');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    const issuesPath = path.join(outputDir, 'playwright-issues.json');
    fs.writeFileSync(issuesPath, JSON.stringify(this.issues, null, 2), 'utf-8');
    console.log(`JSON issues report written to: ${issuesPath}`);
  }
}

export default JsonIssuesReporter;


⸻

6. Add Core E2E Tests (Template)

Create at least these tests in frontend/tests/e2e:
	1.	Smoke / App Loads
	•	smoke-app-load.spec.ts:
	•	Visit /.
	•	Assert that a main element loads (e.g., header, key component).
	2.	Navigation
	•	navigation.spec.ts:
	•	Click on main nav items using data-testid.
	•	Assert each page loads (check for some unique content per route).
	3.	Key Business Flows
For each major feature (e.g., “Create Item”, “Submit Job”), create a test:
	•	Go to the start view.
	•	Click “new / create” button.
	•	Fill required inputs.
	•	Submit.
	•	Assert a success signal:
	•	New row appears
	•	A status changes
	•	A toast/snackbar shows up.

Use getByTestId for all interactions:

await page.getByTestId('btn-new-item').click();
await page.getByTestId('input-name').fill('Test item');
await page.getByTestId('btn-submit').click();


⸻

7. Add NPM Scripts

In frontend/package.json, add:

{
  "scripts": {
    "test:e2e": "playwright test",
    "test:e2e:headed": "playwright test --headed",
    "test:e2e:debug": "playwright test --debug"
  }
}


⸻

8. CI Integration Template

Add a CI pipeline (e.g., GitHub Actions) that:
	1.	Checks out the repo.
	2.	Installs frontend deps.
	3.	Starts the frontend (and backend if required).
	4.	Waits for the app to be reachable at a known URL.
	5.	Runs npm run test:e2e.
	6.	Uploads playwright-report/playwright-issues.json as an artifact.

Use this as a template and adapt paths/ports:

name: E2E Tests

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  e2e:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install frontend deps
        working-directory: ./frontend
        run: |
          npm install
          npx playwright install --with-deps

      - name: Start frontend dev server
        working-directory: ./frontend
        run: |
          npm run dev -- --host 0.0.0.0 --port 3000 &
        env:
          # Adjust backend/API base URL as needed for this project
          VITE_API_BASE_URL: http://localhost:8000

      - name: Wait for app
        run: npx wait-on http://localhost:3000

      - name: Run Playwright tests
        working-directory: ./frontend
        env:
          E2E_BASE_URL: http://localhost:3000
        run: npx playwright test

      - name: Upload JSON issues for AI agent
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-issues
          path: frontend/playwright-report/playwright-issues.json


⸻

9. Document How to Use It

Add or update README.md (or TESTING.md) with:
	•	How to start the app locally.
	•	How to run E2E tests:

cd frontend
npm install
npx playwright install
npm run test:e2e


	•	Where to find issues:

playwright-report/playwright-issues.json



⸻

10. For the AI Agent’s Fix Loop

For any future run:
	1.	Read playwright-report/playwright-issues.json.
	2.	For each entry with status: "failed":
	•	Use test_file and test_name to locate the test.
	•	Use error_message to infer what broke.
	•	Optionally inspect screenshots/traces if available.
	3.	Propose and apply code changes to:
	•	Fix the application logic, or
	•	Fix/update brittle tests or selectors.
	4.	Re-run npm run test:e2e until all tests pass.

⸻

