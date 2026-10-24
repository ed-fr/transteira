// Seeding through the admin API, as an operator would: first-run setup with TOTP, two tenants
// (entity-a, entity-b) reachable through Caddy with internal networks, the example.com domain and
// SMTP to Mailpit, a delegated admin of entity A without TOTP, and an API token of entity A.
import crypto from 'node:crypto';
import { AdminApi, request } from './api';
import { HOSTS, INTERNAL_DOMAIN, MAILPIT_SMTP_HOST, MAILPIT_SMTP_PORT, ORIGINS, TENANT_CIDRS } from './env';
import type { E2EState, SeededTenant } from './state';
import { freshTotp } from './totp';

const GiB = 2 ** 30;

/** A random password for a seeded account (only kept in the gitignored state.json). */
function password(label: string): string {
  return `e2e-${label}-${crypto.randomBytes(12).toString('base64url')}`;
}

/** Seeds a blank server and returns the state to save. */
export async function seed(
  port: number,
  setupToken: string,
  clamavAddr: string,
  db: E2EState['db'],
): Promise<E2EState> {
  const api = new AdminApi(port);

  // First-run setup, then TOTP enrollment confirmed: the super admin session becomes full.
  const superPassword = password('super');
  const enrollment = await api.ok<{ secret: string }>(
    'POST',
    '/admin/setup',
    { username: 'superadmin', email: 'it-admin@example.com', password: superPassword, setupToken },
    [201],
  );
  const totpSecret = enrollment.secret;
  await api.ok('POST', '/admin/me/totp/confirm', { code: await freshTotp(totpSecret) });
  const me = await api.ok<{ id: string }>('GET', '/admin/me');

  const tenants: Partial<Record<'a' | 'b', SeededTenant>> = {};
  for (const key of ['a', 'b'] as const) {
    const name = key === 'a' ? 'Entity A' : 'Entity B';
    const fqdn = HOSTS[key];
    const fromAddress = `transfer@entity-${key}.example.com`;
    const t = await api.ok<{ id: string }>(
      'POST',
      '/admin/tenants',
      {
        name,
        fqdn,
        defaultLanguage: 'en',
        storageQuotaBytes: 5 * GiB,
        maxTransferBytes: 2 * GiB,
        maxTransferCeiling: 20 * GiB,
      },
      [201],
    );
    await api.ok('PUT', `/admin/tenants/${t.id}/network`, {
      internalCidrs: TENANT_CIDRS,
      internalDomains: [INTERNAL_DOMAIN],
    });
    await api.ok('PUT', `/admin/tenants/${t.id}/smtp`, {
      host: MAILPIT_SMTP_HOST,
      port: MAILPIT_SMTP_PORT,
      security: 'none',
      fromAddress,
      fromName: `${name} transfers`,
    });
    tenants[key] = { id: t.id, name, fqdn, origin: ORIGINS[key], fromAddress };
  }
  const a = tenants.a!;
  const b = tenants.b!;

  const token = await api.ok<{ token: string }>(
    'POST',
    `/admin/tenants/${a.id}/api-tokens`,
    { name: 'e2e seed token', allowedCidrs: ['127.0.0.1/32', '172.16.0.0/12'] },
    [201],
  );

  // Delegated admin of entity A, activated through its link (the token is in the fragment).
  const created = await api.ok<{ id: string; activationUrl: string }>(
    'POST',
    '/admin/admins',
    {
      username: 'delegate-a',
      email: 'delegate-a@example.com',
      role: 'delegated_admin',
      tenantIds: [a.id],
      requireTotp: false,
    },
    [201],
  );
  const activationToken = new URL(created.activationUrl).hash.slice(1);
  const delegatePassword = password('delegate');
  const activation = await request(port, 'POST', '/api/v1/admin/activation', {
    body: { activationToken, password: delegatePassword },
    headers: { Origin: ORIGINS.admin, 'Sec-Fetch-Site': 'same-origin' },
  });
  if (activation.status < 200 || activation.status >= 300) {
    throw new Error(`activation -> ${activation.status} ${activation.text}`);
  }
  const delegate = new AdminApi(port);
  await delegate.login('delegate-a', delegatePassword);

  return {
    db,
    serverPort: port,
    clamavAddr,
    superAdmin: {
      id: me.id,
      username: 'superadmin',
      email: 'it-admin@example.com',
      password: superPassword,
      totpSecret,
      apiSession: api.session!,
    },
    delegate: {
      id: created.id,
      username: 'delegate-a',
      email: 'delegate-a@example.com',
      password: delegatePassword,
      tenantIds: [a.id],
      apiSession: delegate.session!,
    },
    tenants: { a, b },
    apiTokenA: token.token,
  };
}
