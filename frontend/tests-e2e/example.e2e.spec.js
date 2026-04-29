const { test, expect } = require('@playwright/test');

test('homepage loads and shows title', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/Dashboard|Analyst/i);
});
