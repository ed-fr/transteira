// Admin authentication through the real sign-in screen (CLAUDE.md section 6.5, threat model
// T-120 to T-129): password then TOTP, one generic message for a wrong username or password,
// sign-out, expiry of the session (the cookie disappears while the interface is open) with the
// return path kept, and the lock after 5 failures of one username from one IP.
//
// Every test signs in its own browser context: the shared storage-state sessions are never
// signed out. The lock test uses a throwaway username (locks are per username and IP, so the
// seeded super admin is never locked out). The recovery codes of the seeded super admin are not
// kept by the seed, so recovery-code sign-in is not covered here.
import type { Page } from '@playwright/test';
import crypto from 'node:crypto';
import { loginAsDelegate } from '../support/auth';
import { ORIGINS } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { freshTotp } from '../support/totp';

/** Failed sign-ins answer 401; locks answer 429. */
const LOGIN_URL = /\/api\/v1\/admin\/auth\/login$/;
const GENERIC_INVALID = 'The username or password is not correct.';

/** Fills and submits the password step of the login screen (already displayed). */
async function submitPassword(page: Page, username: string, password: string): Promise<void> {
  await page.getByLabel(/^Username/).fill(username);
  await page.getByLabel(/^Password/).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test.describe('admin authentication', () => {
  test('signs in with password and TOTP', async ({ newContext, state }) => {
    const context = await newContext();
    const page = await context.newPage();
    await page.goto(`${ORIGINS.admin}/admin/login`);
    await expect(
      page.getByRole('heading', { name: 'Sign in to the administration', level: 1 }),
    ).toBeVisible();
    await checkA11y(page);

    await submitPassword(page, state.superAdmin.username, state.superAdmin.password);
    await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
    await checkA11y(page);
    await page.getByLabel(/^Authentication code/).fill(await freshTotp(state.superAdmin.totpSecret));
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
    await expect(page.getByText(`Signed in as ${state.superAdmin.username}`)).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);

    // The session lives in a host-only, Secure, HttpOnly cookie, never readable by scripts.
    const cookie = (await context.cookies(ORIGINS.admin)).find((c) => c.name === '__Host-tt_admin');
    expect(cookie, 'admin session cookie').toBeDefined();
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.secure).toBe(true);
    expect(cookie!.path).toBe('/');
    expect(await page.evaluate(() => document.cookie)).not.toContain('tt_admin');
  });

  test('a wrong password and an unknown username give the same generic message', async ({
    page,
    state,
    guards,
  }) => {
    guards.allowHttpError(401, LOGIN_URL);
    await page.goto(`${ORIGINS.admin}/admin/login`);

    // One failure for the seeded account from this test's own IP (locks are per username and IP).
    await submitPassword(page, state.superAdmin.username, 'not-the-password-1234');
    const alert = page.getByRole('alert').filter({ hasText: GENERIC_INVALID });
    await expect(alert).toBeVisible();
    // The password field is emptied, the user stays on the password step.
    await expect(page.getByLabel(/^Password/)).toHaveValue('');
    await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toHaveCount(0);
    await checkA11y(page);

    await submitPassword(page, `nobody-${crypto.randomBytes(4).toString('hex')}`, 'not-the-password-1234');
    await expect(alert).toBeVisible();
    // Nothing tells whether the account exists.
    await expect(page.getByText(/does not exist|unknown user|no such/i)).toHaveCount(0);
  });

  // Sign-out and expiry use the seeded delegated admin (no TOTP) in their own context: every
  // TOTP code needs its own 30-second step, so the super admin's codes are kept for the TOTP test.
  test('signs out to the login page with a signed-out message', async ({ newContext, state }) => {
    const context = await newContext();
    const page = await context.newPage();
    await loginAsDelegate(page, state);

    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/admin\/login$/);
    await expect(
      page.getByRole('heading', { name: 'Sign in to the administration', level: 1 }),
    ).toBeVisible();
    await expect(page.getByText('You are signed out.')).toBeVisible();
    await checkA11y(page);
    expect(
      (await context.cookies(ORIGINS.admin)).some((c) => c.name === '__Host-tt_admin' && c.value !== ''),
    ).toBe(false);

    // The session is really closed: a protected page goes back to the login screen.
    await page.goto(`${ORIGINS.admin}/admin/tenants`);
    await expect(page).toHaveURL(/\/admin\/login\?next=%2Ftenants$/);
  });

  test('an expired session goes to the login page and back to the page after sign-in', async ({
    newContext,
    state,
    guards,
  }) => {
    // Once the cookie is gone, the API answers 401 to the calls of the open screen.
    guards.allowHttpError(401, /\/api\/v1\/admin\//);
    const context = await newContext();
    const page = await context.newPage();
    await loginAsDelegate(page, state);

    // The session ends while the interface is open (expiry, revocation): the cookie disappears.
    await context.clearCookies({ name: '__Host-tt_admin' });
    await page
      .getByRole('navigation', { name: 'Main navigation' })
      .getByRole('link', { name: 'Entities' })
      .click();

    // The return path is the page the admin was going to (a delegate with a single entity is
    // sent from the list to the settings of that entity).
    await expect(page).toHaveURL(/\/admin\/login\?next=%2Ftenants/);
    const next = new URL(page.url()).searchParams.get('next')!;
    expect(next).toMatch(/^\/tenants(\/|$)/);
    await expect(page.getByText('Your session has expired. Sign in again to continue.')).toBeVisible();
    await checkA11y(page);

    await submitPassword(page, state.delegate.username, state.delegate.password);
    await expect(page).toHaveURL(`${ORIGINS.admin}/admin${next}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    // A full page load without session keeps the deep link as well.
    await context.clearCookies({ name: '__Host-tt_admin' });
    const deep = `/tenants/${state.tenants.a.id}/network`;
    await page.goto(`${ORIGINS.admin}/admin${deep}`);
    await expect(page).toHaveURL(new RegExp(`/admin/login\\?next=${encodeURIComponent(deep)}$`));
    await submitPassword(page, state.delegate.username, state.delegate.password);
    await expect(page).toHaveURL(new RegExp(`/admin${deep}$`));
    await expect(page.getByRole('heading', { name: 'Network', level: 1 })).toBeVisible();
  });

  test('locks a username for 15 minutes after 5 failures from one IP', async ({ page, guards }) => {
    guards.allowHttpError(401, LOGIN_URL);
    guards.allowHttpError(429, LOGIN_URL);
    // Throwaway username: the lock is per username and IP, never the seeded accounts.
    const username = `locked-${crypto.randomBytes(4).toString('hex')}`;
    await page.goto(`${ORIGINS.admin}/admin/login`);

    for (let i = 1; i <= 4; i++) {
      const answer = page.waitForResponse((r) => LOGIN_URL.test(r.url()));
      await submitPassword(page, username, `wrong-password-${i}`);
      expect((await answer).status()).toBe(401);
      await expect(page.getByRole('alert').filter({ hasText: GENERIC_INVALID })).toBeVisible();
    }
    // The fifth failure sets the lock: a countdown in minutes, the button disabled.
    const answer = page.waitForResponse((r) => LOGIN_URL.test(r.url()));
    await submitPassword(page, username, 'wrong-password-5');
    expect((await answer).status()).toBe(429);
    await expect(page.getByText(/Too many failed attempts\. Try again in 1[45] minutes\./)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeDisabled();
    await checkA11y(page);
  });
});
