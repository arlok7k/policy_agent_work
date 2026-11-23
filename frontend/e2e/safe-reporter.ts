import type { FullResult, Reporter, TestCase, TestError, TestResult } from '@playwright/test/reporter';
import { sanitize } from './redaction';

/** Keep failure diagnostics visible, while masking ephemeral test credentials. */
export default class SafeReporter implements Reporter {
  private reportError(error: TestError): void {
    const diagnostic = sanitize(error.stack ?? error.message ?? 'Playwright reported an unknown error');
    console.error(diagnostic);
    if (process.env.GITHUB_ACTIONS === 'true') {
      const annotation = diagnostic.slice(0, 10000).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
      console.error(`::error title=Playwright smoke::${annotation}`);
    }
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    console.log(`${result.status.toUpperCase()}: ${test.title} (${result.duration} ms)`);
    for (const error of result.errors) this.reportError(error);
  }

  onError(error: TestError): void { this.reportError(error); }
  onEnd(result: FullResult): void { console.log(`Playwright result: ${result.status}`); }
}
