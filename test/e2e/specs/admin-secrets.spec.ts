// One-time secrets, administration side: the list of an entity (metadata only, never the
// content), deletion before reading (the reveal page then says "deleted"), the read-only view of
// an auditor, and the settings screen (module disabled: no secret tab on the public form).
import crypto from 'node:crypto';
import { request } from '../support/api';
import { internalEmail } from '../support/data';
import { ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { msg } from '../support/i18n';
import { identify } from '../support/publicflow';
import { createSecret, expectGone, expectReady, pressShow, expectRevealed } from '../support/secret';
import { superAdminApi } from '../support/state';

const REVEAL_API = /\/api\/v1\/secret-links\/[^/]+(\/reveal)?$/;

function opsUrl(tenantId: string, screen: string): string {
  return `${ORIGINS.admin}/admin/tenants/${tenantId}/${screen}`;
}

test.describe('admin: one-time secrets list', () => {
  test.describe('delegated admin', () => {
    test.use({ storageState: STORAGE_DELEGATE });

    test('the list shows the secret without its content, deleting it before it is read', async ({
      page,
      state,
      newContext,
      guards,
    }) => {
      guards.allowHttpError(410, REVEAL_API);
      const creator = internalEmail('adm-sec');
      const text = `adm-secret-${crypto.randomBytes(6).toString('hex')}`;
      const author = await (await newContext()).newPage();
      await identify(author, state.tenants.a.origin, creator);
      const link = (await createSecret(author, { text }))!;

      await page.goto(opsUrl(state.tenants.a.id, 'secrets'));
      await expect(page.getByRole('heading', { name: 'One-time secrets', level: 1 })).toBeVisible();
      const filters = page.getByRole('search', { name: 'Filter the secrets' });
      await filters.getByLabel(/^Author address/).fill(creator);
      await filters.getByRole('button', { name: 'Apply' }).click();
      const table = page.getByRole('table', { name: 'One-time secrets' });
      const row = table.getByRole('row').filter({ hasText: creator });
      await expect(row).toHaveCount(1);
      await expect(row).toContainText('Active');
      await expect(row).toContainText('Link to hand over');
      await expect(row).toContainText('Not read');
      await expect(page.getByText(text)).toHaveCount(0);
      expect(await page.content()).not.toContain(link.split('#')[0]!);
      await checkA11y(page);

      await row.getByRole('button', { name: `Delete the secret of ${creator}` }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();
      await checkA11y(page);
      await dialog.getByRole('button', { name: 'Delete the secret', exact: true }).click();
      await expect(dialog).toBeHidden();
      await expect(row).toContainText('Deleted');
      await expect(row.getByRole('button', { name: /^Delete/ })).toHaveCount(0);

      const reader = await (await newContext()).newPage();
      await reader.goto(link);
      await expectGone(reader, 'This secret has been deleted by its sender or by an administrator.');
      await checkA11y(reader);
    });

    test('the settings screen is reachable and accessible', async ({ page, state }) => {
      await page.goto(opsUrl(state.tenants.a.id, 'secret-settings'));
      await expect(page.getByRole('heading', { name: 'Secrets settings', level: 1 })).toBeVisible();
      await expect(page.getByLabel('Enable one-time secrets')).toBeVisible();
      await checkA11y(page);
    });
  });

  test.describe('super admin', () => {
    test.use({ storageState: STORAGE_SUPER });

    test('disabling the module removes the secret tab from the public form', async ({
      page,
      state,
      newContext,
    }) => {
      // Entity B: no other test creates secrets there, so the shared entity A stays untouched.
      const tenant = state.tenants.b;
      const api = superAdminApi();
      const original = await api.ok<Record<string, unknown>>(
        'GET',
        `/admin/tenants/${tenant.id}/secret-settings`,
      );
      try {
        await page.goto(opsUrl(tenant.id, 'secret-settings'));
        const enabled = page.getByLabel('Enable one-time secrets');
        await expect(enabled).toBeChecked();
        await enabled.uncheck();
        await page.getByRole('button', { name: 'Save', exact: true }).click();
        await expect(page.getByText('Secrets settings saved.').first()).toBeVisible();

        const user = await (await newContext()).newPage();
        await identify(user, tenant.origin, internalEmail('sec-off'));
        await expect(user.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
        await expect(user.getByRole('tab', { name: 'Share a secret' })).toHaveCount(0);
        await checkA11y(user);
      } finally {
        await api.ok('PUT', `/admin/tenants/${tenant.id}/secret-settings`, original);
      }

      const user2 = await (await newContext()).newPage();
      await identify(user2, tenant.origin, internalEmail('sec-on'));
      await expect(user2.getByRole('tab', { name: 'Share a secret' })).toBeVisible();
    });
  });

  test('an auditor sees the list read-only, without settings', async ({ page, state, newContext }) => {
    const creator = internalEmail('aud-sec');
    const text = `aud-secret-${crypto.randomBytes(6).toString('hex')}`;
    const author = await (await newContext()).newPage();
    await identify(author, state.tenants.a.origin, creator);
    const link = (await createSecret(author, { text }))!;

    const api = superAdminApi();
    const username = `sec-auditor-${crypto.randomBytes(4).toString('hex')}`;
    const password = `e2e-auditor-${crypto.randomBytes(12).toString('base64url')}`;
    const created = await api.ok<{ activationUrl: string }>(
      'POST',
      '/admin/admins',
      {
        username,
        email: `${username}@example.com`,
        role: 'auditor',
        tenantIds: [state.tenants.a.id],
        requireTotp: false,
      },
      [201],
    );
    const activated = await request(state.serverPort, 'POST', '/api/v1/admin/activation', {
      body: { activationToken: new URL(created.activationUrl).hash.slice(1), password },
      headers: { Origin: ORIGINS.admin, 'Sec-Fetch-Site': 'same-origin' },
    });
    expect(activated.status).toBeLessThan(300);
    await page.goto(`${ORIGINS.admin}/admin/login`);
    await page.getByLabel(/^Username/).fill(username);
    await page.getByLabel(/^Password/).fill(password);
    await page.getByRole('button', { name: msg('en', 'adminAuth.login.submit'), exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();

    await page.goto(opsUrl(state.tenants.a.id, 'secrets'));
    await expect(page.getByRole('heading', { name: 'One-time secrets', level: 1 })).toBeVisible();
    await expect(page.getByText(/read only\. The content is never visible/)).toBeVisible();
    const table = page.getByRole('table', { name: 'One-time secrets' });
    await expect(table.getByRole('row').filter({ hasText: creator })).toHaveCount(1);
    await expect(table.getByRole('button', { name: /^Delete/ })).toHaveCount(0);
    await expect(page.getByLabel(/^Author address/)).toHaveCount(0);
    await expect(page.getByText(text)).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Secrets settings' })).toHaveCount(0);
    await checkA11y(page);

    // The secret is untouched by the consultation.
    const reader = await (await newContext()).newPage();
    await reader.goto(link);
    await expectReady(reader);
    await pressShow(reader);
    await expectRevealed(reader, text);
  });
});
