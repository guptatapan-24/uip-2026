// Playwright configuration for E2E tests
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests-e2e',
  timeout: 30 * 1000,
  expect: { timeout: 5000 },
  reporter: 'list',
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  use: {
    baseURL: 'http://localhost:3001'
  }
});
