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
      status: result.status as IssueEntry['status'],
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

