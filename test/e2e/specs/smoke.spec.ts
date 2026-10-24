// Smoke test of the end-to-end foundation: Caddy proxies the three hosts to the server, the
// seeded tenant serves its public interface, the admin login screen loads, and the saved admin
// storage states reach the dashboard, with every guard (CSP, page errors, foreign requests,
// server and console errors) and axe-core reporting nothing.
import { ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';

test.describe('smoke', () => {
  test('public home of entity A', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    await expect(page.getByLabel(/Your email address/)).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);
  });

  test('admin login page', async ({ page }) => {
    await page.goto(`${ORIGINS.admin}/admin/login`);
    await expect(
      page.getByRole('heading', { name: 'Sign in to the administration', level: 1 }),
    ).toBeVisible();
    await expect(page.getByLabel(/^Username/)).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);
  });

  test.describe('super admin', () => {
    test.use({ storageState: STORAGE_SUPER });

    test('reaches the dashboard', async ({ page }) => {
      await page.goto(`${ORIGINS.admin}/admin/`);
      await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
      await expect(page.getByRole('main').getByText('Entity B').first()).toBeVisible();
      await checkA11y(page);
      await expectCleanStorage(page);
    });
  });

  test.describe('delegated admin', () => {
    test.use({ storageState: STORAGE_DELEGATE });

    test('reaches the home of its entity only', async ({ page }) => {
      await page.goto(`${ORIGINS.admin}/admin/`);
      await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
      await expect(page.getByRole('main').getByText('Entity A').first()).toBeVisible();
      await expect(page.getByText('Entity B')).toHaveCount(0);
      await checkA11y(page);
      await expectCleanStorage(page);
    });
  });
});
