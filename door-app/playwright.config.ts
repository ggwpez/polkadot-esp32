import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './test', timeout: 480_000, workers: 1,
  use: { headless: true, viewport: { width: 1000, height: 900 }, trace: 'off' },
  webServer: { command: 'npm run preview -- --port 4173', url: 'http://localhost:4173', reuseExistingServer: true },
});
