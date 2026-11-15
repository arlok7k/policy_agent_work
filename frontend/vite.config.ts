import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Browser requests remain relative to this origin; the optional dev proxy is
// server-side only and never exposes a localhost URL to the browser.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    allowedHosts: true,
    ...(process.env.SOC_DEV_API_TARGET
      ? { proxy: { '/api': { target: process.env.SOC_DEV_API_TARGET } } }
      : {}),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    clearMocks: true,
  },
});
