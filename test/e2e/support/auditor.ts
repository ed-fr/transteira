// An auditor of an entity (read-only role) signed in through the real login screen, for the
// admin scenarios that compare the roles. The account is created through the admin API and
// activated without a second factor; every call makes a fresh account, so no state is shared.
import { expect, type BrowserContext, type Page } from '@playwright/test';
import { ORIGINS } from './env';
import { createAuditor } from './express';
import type { NewContextOptions } from './fixtures';
import type { E2EState } from './state';
import { superAdminApi } from './state';

/** Opens a context and a page signed in as a new auditor of the tenant, on the admin Home. */
export async function openAsAuditor(
  newContext: (options?: NewContextOptions) => Promise<BrowserContext>,
  state: E2EState,
  tenantId: string,
  options: NewContextOptions = {},
): Promise<Page> {
  const { username, password } = await createAuditor(superAdminApi(), state, tenantId);
  const page = await (await newContext(options)).newPage();
  await page.goto(`${ORIGINS.admin}/admin/login`);
  await page.getByLabel(/^Username/).fill(username);
  await page.getByLabel(/^Password/).fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
  return page;
}
