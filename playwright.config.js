const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './playwright/tests',
  timeout: 60_000,
  expect: {
    timeout: 8_000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  outputDir: 'output/playwright/test-results',
  use: {
    baseURL: 'http://127.0.0.1:8000',
    viewport: { width: 1440, height: 960 },
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'env DEBUG=True ALLOWED_HOSTS=127.0.0.1,localhost python3 manage.py runserver 127.0.0.1:8000',
    url: 'http://127.0.0.1:8000',
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
