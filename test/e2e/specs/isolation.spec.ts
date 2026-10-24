// Scenario 10: tenant isolation as seen from a browser (threat model: tenant isolation,
// information disclosure through the admin SPA). The delegated admin of entity A must never
// read, modify or even detect entity B: every entity-B screen of the admin SPA shows the generic
// "Page not found" page without fetching entity-B data, the super-admin areas are not found
// either, direct API calls with the delegate session get 404, and an entity-B transfer id
// opened under entity A is "Transfer not found". On the public side, a tenant host never shows
// the other tenant's identity, and a download link only works on the host of its tenant.
import type { Page, Response } from '@playwright/test';
import { HOSTS, ORIGINS, STORAGE_DELEGATE } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { internalEmail, textFile } from '../support/data';
import { delegateApi, loadState, superAdminApi } from '../support/state';
import { createTenantToken, downloadPath, tokenDeposit } from '../support/deposit';

/** Entity-B transfer created once per worker (as the super admin, through an entity-B token). */
let entityBTransfer: Promise<string> | undefined;
function entityBTransferId(): Promise<string> {
  entityBTransfer ??= (async () => {
    const s = loadState();
    const token = await createTenantToken(s.tenants.b.id, `isolation ${Date.now()}`);
    const transfer = await tokenDeposit(
      token.token,
      internalEmail('isolation-b-sender'),
      {
        recipients: [internalEmail('isolation-b-recipient')],
        files: [textFile('entity-b-secret.txt', 'entity B content')],
      },
      { host: HOSTS.b },
    );
    expect(transfer.status).toBe('available');
    return transfer.id;
  })();
  return entityBTransfer;
}

/** Strings that would reveal entity B (name, FQDN, sender address, identifiers). */
function entityBMarkers(transferId: string): string[] {
  const b = loadState().tenants.b;
  return [b.name, b.fqdn, b.fromAddress, 'entity-b', b.id, transferId];
}

/** Records the answers of the admin API about entity B seen by the page. */
function watchEntityBCalls(page: Page): Response[] {
  const b = loadState().tenants.b;
  const seen: Response[] = [];
  page.on('response', (res) => {
    if (res.url().includes(`/api/v1/admin/tenants/${b.id}`)) seen.push(res);
  });
  return seen;
}

test.describe('tenant isolation (delegated admin of entity A)', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('main navigation offers neither Administrators nor System, entity list shows A only', async ({
    page,
    state,
  }) => {
    await page.goto(`${ORIGINS.admin}/admin/tenants`);
    const nav = page.getByRole('navigation', { name: 'Main navigation' });
    await expect(nav.getByRole('link', { name: 'Entities' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'My account' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Administrators' })).toHaveCount(0);
    await expect(nav.getByRole('link', { name: 'System' })).toHaveCount(0);
    await expect(page.getByRole('main').getByText(state.tenants.a.name).first()).toBeVisible();
    await expect(page.getByText(state.tenants.b.name)).toHaveCount(0);
    expect(await page.content()).not.toContain(state.tenants.b.fqdn);
  });

  // Every tenant screen of the admin SPA, opened for entity B.
  const entityBScreens: { name: string; path: (b: string, transferId: string) => string }[] = [
    { name: 'general', path: (b) => `/tenants/${b}/general` },
    { name: 'branding', path: (b) => `/tenants/${b}/branding` },
    { name: 'network', path: (b) => `/tenants/${b}/network` },
    { name: 'smtp', path: (b) => `/tenants/${b}/smtp` },
    { name: 'templates', path: (b) => `/tenants/${b}/templates` },
    { name: 'template editor', path: (b) => `/tenants/${b}/templates/transfer-notification/en` },
    { name: 'legal', path: (b) => `/tenants/${b}/legal` },
    { name: 'legal editor', path: (b) => `/tenants/${b}/legal/legal-notice/en` },
    { name: 'transfers', path: (b) => `/tenants/${b}/transfers` },
    { name: 'transfer detail', path: (b, t) => `/tenants/${b}/transfers/${t}` },
    { name: 'invitations', path: (b) => `/tenants/${b}/invitations` },
    { name: 'blocklist', path: (b) => `/tenants/${b}/blocklist` },
    { name: 'tokens', path: (b) => `/tenants/${b}/tokens` },
    { name: 'new token', path: (b) => `/tenants/${b}/tokens/new` },
    { name: 'audit', path: (b) => `/tenants/${b}/audit` },
    { name: 'stats', path: (b) => `/tenants/${b}/stats` },
    { name: 'privacy', path: (b) => `/tenants/${b}/privacy` },
  ];

  for (const screen of entityBScreens) {
    test(`entity-B ${screen.name} screen is "Page not found" without entity-B data`, async ({
      page,
      state,
      guards,
    }) => {
      const transferId = await entityBTransferId();
      // A 404 from the server would be acceptable; anything else is a leak (checked below).
      guards.allowHttpError(404, new RegExp(`/api/v1/admin/tenants/${state.tenants.b.id}`));
      const calls = watchEntityBCalls(page);

      await page.goto(`${ORIGINS.admin}/admin${screen.path(state.tenants.b.id, transferId)}`);
      await expect(page.getByRole('heading', { name: 'Page not found', level: 1 })).toBeVisible();
      // The navigation is rendered (signed in), but no tenant sub-navigation for entity B.
      const nav = page.getByRole('navigation', { name: 'Main navigation' });
      await expect(nav.getByRole('link', { name: 'Entities' })).toBeVisible();
      await expect(nav.getByRole('link', { name: 'System' })).toHaveCount(0);
      await expect(page.getByRole('link', { name: 'Back to the administration home' })).toBeVisible();

      const html = await page.content();
      for (const marker of entityBMarkers(transferId)) {
        expect(html, `DOM must not reveal "${marker}"`).not.toContain(marker);
      }
      expect(await page.title()).not.toContain(state.tenants.b.name);
      for (const res of calls) {
        expect(res.status(), `${res.request().method()} ${res.url()}`).toBe(404);
      }
    });
  }

  for (const path of [
    '/admins',
    '/admins/new',
    `/admins/ADMIN_ID`,
    '/system',
    '/system/maintenance',
    '/system/settings',
    '/system/audit',
    '/system/master-key',
    '/tenants/new',
  ]) {
    test(`super-admin area ${path} is "Page not found"`, async ({ page, state }) => {
      const calls: string[] = [];
      page.on('request', (req) => {
        const u = new URL(req.url()).pathname;
        // The maintenance state is read by every admin for the banner (allowed by design).
        if (u === '/api/v1/admin/system/maintenance') return;
        if (u.startsWith('/api/v1/admin/admins') || u.startsWith('/api/v1/admin/system')) calls.push(u);
      });
      await page.goto(`${ORIGINS.admin}/admin${path.replace('ADMIN_ID', state.superAdmin.id)}`);
      await expect(page.getByRole('heading', { name: 'Page not found', level: 1 })).toBeVisible();
      expect(calls, 'the SPA must not call super-admin endpoints').toEqual([]);
      expect(await page.content()).not.toContain(state.superAdmin.email);
    });
  }

  test('an entity-B transfer id under the entity-A path is "Transfer not found"', async ({
    page,
    state,
    guards,
  }) => {
    const transferId = await entityBTransferId();
    const detailUrl = new RegExp(`/api/v1/admin/tenants/${state.tenants.a.id}/transfers/${transferId}$`);
    guards.allowHttpError(404, detailUrl);
    const answer = page.waitForResponse((res) => detailUrl.test(res.url()));
    await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/transfers/${transferId}`);
    expect((await answer).status()).toBe(404);
    await expect(page.getByRole('heading', { name: 'Transfer not found', level: 1 })).toBeVisible();
    const html = await page.content();
    expect(html).not.toContain('entity-b-secret.txt');
    expect(html).not.toContain(state.tenants.b.name);
    await checkA11y(page);
  });
});

test.describe('tenant isolation (delegate session on the admin API)', () => {
  test('every entity-B endpoint answers 404 without data, and nothing changes', async ({ state }) => {
    const transferId = await entityBTransferId();
    const b = state.tenants.b;
    const api = delegateApi();
    const base = `/admin/tenants/${b.id}`;
    const victim = internalEmail('isolation-victim');
    const calls: [string, string, unknown?][] = [
      ['GET', base],
      ['PATCH', base, { defaultLanguage: 'en' }],
      ['GET', `${base}/branding`],
      ['GET', `${base}/branding/logo`],
      ['DELETE', `${base}/branding/logo`],
      ['GET', `${base}/network`],
      ['PUT', `${base}/network`, { internalCidrs: ['10.0.0.0/8'], internalDomains: ['example.com'] }],
      ['GET', `${base}/smtp`],
      ['POST', `${base}/smtp/test`, { to: victim }],
      ['GET', `${base}/smtp/dns-check`],
      ['GET', `${base}/email-templates`],
      ['GET', `${base}/email-templates/transfer-notification/en`],
      [
        'PUT',
        `${base}/email-templates/transfer-notification/en`,
        { subject: 'x', bodyHtml: '<p>x</p>', bodyText: 'x' },
      ],
      [
        'POST',
        `${base}/email-templates/transfer-notification/en/preview`,
        { subject: 'x', bodyHtml: '<p>x</p>', bodyText: 'x' },
      ],
      ['GET', `${base}/legal/legal-notice/en`],
      ['PUT', `${base}/legal/legal-notice/en`, { markdown: 'x' }],
      ['GET', `${base}/transfers`],
      ['GET', `${base}/transfers/${transferId}`],
      ['POST', `${base}/transfers/${transferId}/resend`, {}],
      ['DELETE', `${base}/transfers/${transferId}`],
      ['GET', `${base}/invitations`],
      ['GET', `${base}/blocklist`],
      ['POST', `${base}/blocklist`, { kind: 'email', value: victim }],
      ['GET', `${base}/api-tokens`],
      ['POST', `${base}/api-tokens`, { name: 'isolation', allowedCidrs: ['127.0.0.1/32'] }],
      ['GET', `${base}/audit-events`],
      ['GET', `${base}/stats`],
      ['POST', `${base}/data-subjects/search`, { email: victim }],
      ['POST', `${base}/data-subjects/erase`, { email: victim }],
    ];
    const failures: string[] = [];
    for (const [method, path, body] of calls) {
      const res = await api.call(method, path, body);
      if (res.status !== 404) failures.push(`${method} ${path} -> ${res.status} ${res.text.slice(0, 200)}`);
      for (const marker of [b.name, b.fqdn, b.fromAddress, 'entity-b-secret.txt']) {
        if (res.text.includes(marker)) failures.push(`${method} ${path} body reveals "${marker}"`);
      }
    }
    // Super-admin endpoints: refused (403 or 404), never data.
    for (const path of [
      '/admin/admins',
      `/admin/admins/${state.superAdmin.id}`,
      '/admin/system/stats',
      '/admin/system/settings',
      '/admin/system/audit-events',
      '/admin/system/master-key',
    ]) {
      const res = await api.call('GET', path);
      if (res.status !== 403 && res.status !== 404) failures.push(`GET ${path} -> ${res.status}`);
      if (res.text.includes(state.superAdmin.email) || res.text.includes(b.name))
        failures.push(`GET ${path} body reveals another scope`);
    }
    expect(failures).toEqual([]);

    // Nothing was changed in entity B: the transfer still exists, no blocklist entry or token.
    const sa = superAdminApi();
    const detail = await sa.call('GET', `${base}/transfers/${transferId}`);
    expect(detail.status).toBe(200);
    const blocklist = await sa.ok<unknown>('GET', `${base}/blocklist`);
    expect(JSON.stringify(blocklist)).not.toContain(victim);
    const tokens = await sa.ok<unknown>('GET', `${base}/api-tokens`);
    expect(JSON.stringify(tokens)).not.toMatch(/"name":"isolation"/);
    const network = await sa.ok<{ internalCidrs: string[] }>('GET', `${base}/network`);
    expect(network.internalCidrs).toContain('127.0.0.1/32');
  });
});

test.describe('tenant isolation (public hosts)', () => {
  test('entity-B host never shows entity A, a download link only works on its own host', async ({
    page,
    state,
    guards,
  }) => {
    const { a, b } = state.tenants;
    await page.goto(`${b.origin}/`);
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    for (const path of ['/', '/legal/legal-notice', '/legal/privacy-policy']) {
      await page.goto(`${b.origin}${path}`);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      const html = await page.content();
      expect(html, path).not.toContain(a.name);
      expect(html, path).not.toContain(a.fqdn);
      expect(html, path).not.toContain(a.fromAddress);
    }
    const tenant = await page.evaluate(async () => (await fetch('/api/v1/tenant')).json());
    expect(tenant.name).toBe(b.name);

    // An entity-A download link opened on the entity-B host: not found, nothing of A shown.
    const transfer = await tokenDeposit(
      state.apiTokenA,
      internalEmail('isolation-a-sender'),
      {
        recipients: [internalEmail('isolation-a-recipient')],
        files: [textFile('entity-a-report.txt', 'entity A content')],
      },
      { host: HOSTS.a },
    );
    const path = downloadPath(transfer.downloadUrl!);
    guards.allowHttpError(404, /\/api\/v1\/downloads\//);
    await page.goto(`${b.origin}${path}`);
    await expect(page.getByRole('heading', { name: 'Transfer not found', level: 1 })).toBeVisible();
    expect(await page.content()).not.toContain('entity-a-report.txt');

    await page.goto(`${a.origin}${path}`);
    await expect(page.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(page.getByText('entity-a-report.txt').first()).toBeVisible();
  });
});
