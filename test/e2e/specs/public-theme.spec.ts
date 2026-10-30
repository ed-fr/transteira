// Dark mode (CLAUDE.md section 13.1, threat model T-230 / T-231): the theme follows the system
// setting by default, the footer button switches it and remembers the choice in the technical
// cookie tt_theme, going back to the system value deletes the cookie, and an unknown cookie value
// is ignored. The same button exists on the admin interface.
import type { Page } from '@playwright/test';
import { ORIGINS } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';

const themeOf = (page: Page) => page.evaluate(() => document.documentElement.dataset.theme);
const themeCookie = async (page: Page) =>
  (await page.context().cookies(page.url())).find((c) => c.name === 'tt_theme');

test.describe('theme', () => {
  test('follows the system setting without a cookie', async ({ page, state }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    expect(await themeOf(page)).toBe('dark');
    await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'true');
    expect(await themeCookie(page)).toBeUndefined();
    await checkA11y(page);

    await page.emulateMedia({ colorScheme: 'light' });
    await expect.poll(() => themeOf(page)).toBe('light');
    await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'false');
  });

  test('the button switches the theme, remembers it and goes back to the system', async ({ page, state }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto(`${state.tenants.a.origin}/`);
    const button = page.getByRole('button', { name: 'Dark theme' });
    await expect(button).toHaveAttribute('aria-pressed', 'false');

    await button.click();
    await expect.poll(() => themeOf(page)).toBe('dark');
    await expect(button).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByText('Dark theme on.')).toBeAttached();
    const cookie = await themeCookie(page);
    expect(cookie?.value).toBe('dark');
    expect(cookie?.path).toBe('/');
    expect(cookie?.sameSite).toBe('Lax');
    expect(cookie?.httpOnly).toBe(false);

    // The choice survives a reload, whatever the system says.
    await page.reload();
    expect(await themeOf(page)).toBe('dark');
    await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'true');
    await checkA11y(page);

    // Back to the system value (light): the cookie is deleted and the page follows the system.
    await page.getByRole('button', { name: 'Dark theme' }).click();
    await expect.poll(() => themeOf(page)).toBe('light');
    await expect(page.getByText('Light theme on.')).toBeAttached();
    expect(await themeCookie(page)).toBeUndefined();

    await page.emulateMedia({ colorScheme: 'dark' });
    await expect.poll(() => themeOf(page)).toBe('dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await expect.poll(() => themeOf(page)).toBe('light');
  });

  test('ignores an unknown cookie value (T-231)', async ({ page, context, state }) => {
    await context.addCookies([{ name: 'tt_theme', value: 'darkx', url: state.tenants.a.origin }]);
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    expect(await themeOf(page)).toBe('light');

    for (const value of ['Dark', '<script>', '"dark"']) {
      await context.clearCookies();
      await context.addCookies([{ name: 'tt_theme', value, url: state.tenants.a.origin }]);
      await page.reload();
      expect(await themeOf(page), `value ${value}`).toBe('light');
    }
  });

  test('the admin login page has the same button', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto(`${ORIGINS.admin}/admin/login`);
    await expect(
      page.getByRole('heading', { name: 'Sign in to the administration', level: 1 }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Dark theme' }).click();
    await expect.poll(() => themeOf(page)).toBe('dark');
    expect((await themeCookie(page))?.value).toBe('dark');
    await checkA11y(page);
  });
});
