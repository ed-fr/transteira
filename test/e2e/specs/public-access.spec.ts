// Public scenario 5 (CLAUDE.md sections 6.2, 8.1, 15.2, 16.3): who may deposit. An address
// outside the internal domains is refused even from the internal network, an internal address is
// refused from outside the internal ranges, and an address or a domain on the tenant blocklist is
// refused, with the same generic message (the reason is not revealed). Each refusal is written to
// the security log with the real client IP and its reason, as fail2ban and CrowdSec read it.
//
// Blocklist entries are unique to each test (one address, one sub-domain of example.org), never
// the shared example.com domain, and are removed at the end: tests run in parallel.
import crypto from 'node:crypto';
import { externalIp } from '../support/clientip';
import { externalEmail, internalEmail } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { identify, submitEmail } from '../support/publicflow';
import { waitForSecurityEvents } from '../support/securitylog';
import { superAdminApi } from '../support/state';

const NOT_ALLOWED =
  'Deposits are only possible from the internal network with an address of the organisation. ' +
  'To send files from outside, ask an internal user to invite you.';
const DEPOSIT_SESSIONS = /\/api\/v1\/deposit-sessions$/;

interface BlocklistEntry {
  id: string;
}

/** Adds a blocklist entry to tenantId and returns a function removing it. */
async function block(
  tenantId: string,
  kind: 'email' | 'domain',
  value: string,
): Promise<() => Promise<void>> {
  const api = superAdminApi();
  const entry = await api.ok<BlocklistEntry>(
    'POST',
    `/admin/tenants/${tenantId}/blocklist`,
    { kind, value, comment: 'e2e public-access' },
    [201],
  );
  return async () => {
    await api.ok('DELETE', `/admin/tenants/${tenantId}/blocklist/${entry.id}`, undefined, [204]);
  };
}

test.describe('public: access rules and blocklist', () => {
  test('an address outside the internal domains is refused from the internal network', async ({
    page,
    state,
    guards,
    clientIp,
  }) => {
    guards.allowHttpError(403, DEPOSIT_SESSIONS);
    const tenant = state.tenants.a;
    await page.goto(`${tenant.origin}/`);
    await submitEmail(page, externalEmail('outsider'));
    await expect(page.getByRole('alert').filter({ hasText: NOT_ALLOWED })).toBeVisible();
    // Still on the email step: no code was asked for.
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);
    await waitForSecurityEvents({
      ip: clientIp,
      event: 'deposit_refused',
      tenant: tenant.fqdn,
      fields: { reason: 'domain' },
    });
  });

  test('an internal address is refused from outside the internal ranges', async ({
    state,
    guards,
    newContext,
  }) => {
    guards.allowHttpError(403, DEPOSIT_SESSIONS);
    const tenant = state.tenants.a;
    const ip = externalIp();
    const page = await (await newContext({ clientIp: ip })).newPage();
    await page.goto(`${tenant.origin}/`);
    await submitEmail(page, internalEmail('remote'));
    await expect(page.getByRole('alert').filter({ hasText: NOT_ALLOWED })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    await checkA11y(page);
    await waitForSecurityEvents({
      ip,
      event: 'deposit_refused',
      tenant: tenant.fqdn,
      fields: { reason: 'ip' },
    });
  });

  test('a blocklisted internal address is refused with the same message', async ({
    page,
    state,
    guards,
    clientIp,
  }) => {
    guards.allowHttpError(403, DEPOSIT_SESSIONS);
    const tenant = state.tenants.a;
    const blocked = internalEmail('blocked');
    const unblock = await block(tenant.id, 'email', blocked);
    try {
      await page.goto(`${tenant.origin}/`);
      await submitEmail(page, blocked);
      await expect(page.getByRole('alert').filter({ hasText: NOT_ALLOWED })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
      await waitForSecurityEvents({
        ip: clientIp,
        event: 'deposit_refused',
        tenant: tenant.fqdn,
        fields: { reason: 'blocklist' },
      });
    } finally {
      await unblock();
    }
    // Once the entry is removed, the same address may identify again (only the blocklist refused it).
    await identify(page, tenant.origin, blocked);
    await expectCleanStorage(page);
  });

  test('an invitation to a blocklisted domain is refused', async ({ page, state, guards, clientIp }) => {
    guards.allowHttpError(403, /\/api\/v1\/invitations$/);
    const tenant = state.tenants.a;
    const domain = `blk-${crypto.randomBytes(4).toString('hex')}.example.org`;
    const inviter = internalEmail('blk-inviter');
    const unblock = await block(tenant.id, 'domain', domain);
    try {
      await identify(page, tenant.origin, inviter);
      await page.getByRole('link', { name: 'Invite someone to send you files' }).click();
      // A sub-domain of the blocked domain is covered too.
      await page.getByLabel(/^Email address of the person to invite/).fill(`someone@team.${domain}`);
      await page.getByRole('button', { name: 'Send the invitation' }).click();
      // The refusal is generic: it neither reveals that the invited domain is blocklisted nor
      // blames the inviter, and the form stays so that the address can be corrected.
      await expect(
        page.getByText('This invitation cannot be sent. Check the address or contact your administrator.'),
      ).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Invite an external person', level: 1 })).toBeVisible();
      await expect(page.getByText(/not allowed to send invitations/)).toHaveCount(0);
      await checkA11y(page);
      await waitForSecurityEvents({
        ip: clientIp,
        event: 'deposit_refused',
        tenant: tenant.fqdn,
        fields: { reason: 'blocklist' },
      });
    } finally {
      await unblock();
    }
  });
});
