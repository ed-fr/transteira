// Admin sign-in through the real login screen, and the storage states saved once per run by the
// global setup (tests start already signed in with test.use({ storageState: STORAGE_SUPER })).
//
// The storage-state sessions are shared by every test of the run: a test that signs out, lets the
// session expire or changes the account's credentials must sign in in its own browser context
// with loginAsSuperAdmin / loginAsDelegate instead.
import { expect, type Browser, type Page } from '@playwright/test';
import { CLIENT_IP_HEADER, randomInternalIp } from './clientip';
import { ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from './env';
import type { E2EState } from './state';
import { freshTotp } from './totp';

/** Fills the password step of the login screen. */
async function passwordStep(page: Page, username: string, password: string): Promise<void> {
  await page.goto(`${ORIGINS.admin}/admin/login`);
  await page.getByLabel(/^Username/).fill(username);
  await page.getByLabel(/^Password/).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

/** Signs in as the seeded super admin (password, then a fresh TOTP code) and waits for Home. */
export async function loginAsSuperAdmin(page: Page, state: E2EState): Promise<void> {
  await passwordStep(page, state.superAdmin.username, state.superAdmin.password);
  await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
  await page.getByLabel(/^Authentication code/).fill(await freshTotp(state.superAdmin.totpSecret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
}

/** Signs in as the seeded delegated admin of entity A (no TOTP) and waits for Home. */
export async function loginAsDelegate(page: Page, state: E2EState): Promise<void> {
  await passwordStep(page, state.delegate.username, state.delegate.password);
  await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
}

/** Signs both seeded admins in once and saves their browser storage states. */
export async function saveStorageStates(browser: Browser, state: E2EState): Promise<void> {
  for (const [login, file] of [
    [loginAsSuperAdmin, STORAGE_SUPER],
    [loginAsDelegate, STORAGE_DELEGATE],
  ] as const) {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      locale: 'en-US',
      extraHTTPHeaders: { [CLIENT_IP_HEADER]: randomInternalIp() },
    });
    try {
      const page = await context.newPage();
      await login(page, state);
      await context.storageState({ path: file });
    } finally {
      await context.close();
    }
  }
}
