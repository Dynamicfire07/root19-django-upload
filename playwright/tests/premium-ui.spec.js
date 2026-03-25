const fs = require('fs');
const path = require('path');
const { test, expect } = require('@playwright/test');

const screenshotDir = path.join(process.cwd(), 'output', 'playwright', 'screenshots');

function ensureScreenshotDir() {
  fs.mkdirSync(screenshotDir, { recursive: true });
}

function bindPageErrorCollection(page) {
  const errors = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      errors.push(msg.text());
    }
  });

  page.on('pageerror', (error) => {
    errors.push(error.message);
  });

  return errors;
}

async function assertNoConsoleErrors(errors) {
  expect(errors, errors.join('\n') || 'expected no console errors').toEqual([]);
}

test.describe('premium cursor and polish', () => {
  test('home page renders, enables the premium cursor on desktop, and saves screenshots', async ({ page }) => {
    ensureScreenshotDir();
    const errors = bindPageErrorCollection(page);
    const primaryCta = page.getByRole('link', { name: /explore question bank/i });

    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('navigation')).toBeVisible();
    await expect(page.getByRole('heading', { name: /exam prep sharp, daily/i })).toBeVisible();
    await expect(primaryCta).toBeVisible();
    await page.waitForTimeout(500);
    await assertNoConsoleErrors(errors);

    await expect(page.locator('body')).not.toHaveAttribute('data-premium-cursor', 'enabled');

    await page.screenshot({
      path: path.join(screenshotDir, 'home-default.png'),
      fullPage: true,
    });

    await page.mouse.move(220, 180);
    await page.waitForTimeout(200);

    const cursor = page.getByTestId('custom-cursor');
    await expect(page.locator('body')).toHaveAttribute('data-premium-cursor', 'enabled');
    await expect(cursor).toBeVisible();

    await page.screenshot({
      path: path.join(screenshotDir, 'home-cursor-visible.png'),
      fullPage: true,
    });

    await primaryCta.hover();
    await page.waitForTimeout(200);
    await expect(cursor).toHaveClass(/is-interactive/);

    await page.screenshot({
      path: path.join(screenshotDir, 'home-primary-cta-hover.png'),
      fullPage: true,
    });
  });

  test('question bank page renders key controls and preserves cursor behavior', async ({ page }) => {
    ensureScreenshotDir();
    const errors = bindPageErrorCollection(page);

    await page.goto('/question-bank/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: 'Question Bank' })).toBeVisible();
    await expect(page.getByLabel('Session')).toBeVisible();
    await expect(page.getByTestId('question-bank-start')).toBeVisible();
    await page.waitForTimeout(500);
    await assertNoConsoleErrors(errors);

    await expect(page.locator('body')).not.toHaveAttribute('data-premium-cursor', 'enabled');

    await page.mouse.move(360, 220);
    await page.waitForTimeout(200);
    await page.getByTestId('question-bank-start').hover();
    await expect(page.getByTestId('custom-cursor')).toHaveClass(/is-interactive/);

    await page.screenshot({
      path: path.join(screenshotDir, 'question-bank-overview.png'),
      fullPage: true,
    });
  });
});
