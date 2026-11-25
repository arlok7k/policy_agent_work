import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  timeout: 240_000,
  expect: { timeout: 20_000 },
  reporter: [['./e2e/safe-reporter.ts']],
  outputDir: '/tmp/pb4-playwright-output',
  use: {
    baseURL: process.env.SOC_BASE_URL ?? 'http://127.0.0.1:8080',
    browserName: 'chromium',
    // Traces, videos and screenshots can contain live credentials and cookies.
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },
});
