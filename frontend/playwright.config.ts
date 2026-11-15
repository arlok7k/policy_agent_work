import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  use: { baseURL: process.env.SOC_BASE_URL ?? 'http://127.0.0.1:8080', trace: 'retain-on-failure' },
});
