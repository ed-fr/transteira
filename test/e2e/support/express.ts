// Steps of the express secret scenarios (specs/express-secret.spec.ts, CLAUDE.md section 22.2):
// the tenant switch through the admin API, the /x page, the leak checks of the network capture
// (threat T-399) and the mailbox of the delegated admin.
import crypto from 'node:crypto';
import { expect, type Page } from '@playwright/test';
import type { AdminApi } from './api';
import { request } from './api';
import { ORIGINS } from './env';
import { listMails, getMail, type Mail } from './mailpit';
import type { CapturedRequest } from './secret';
import type { E2EState } from './state';

/** Members of SecretSettings that the express scenarios change. */
export interface ExpressSettings {
  expressEnabled: boolean;
  expressPerHourPerIp: number;
  expressPerHourPerToken: number;
  expressMaxPending: number;
}

/** Defaults of the settings, restored after every test. */
export const EXPRESS_DEFAULTS: ExpressSettings = {
  expressEnabled: false,
  expressPerHourPerIp: 10,
  expressPerHourPerToken: 100,
  expressMaxPending: 1000,
};

/** Changes the express members of the secret settings of a tenant (the others are kept). */
export async function setExpress(
  api: AdminApi,
  tenantId: string,
  patch: Partial<ExpressSettings>,
): Promise<void> {
  const path = `/admin/tenants/${tenantId}/secret-settings`;
  const current = await api.ok<Record<string, unknown>>('GET', path);
  await api.ok('PUT', path, { ...current, ...patch });
}

/** Deletes every live anonymous express secret of a tenant; returns how many. */
export async function purgeExpress(api: AdminApi, tenantId: string): Promise<number> {
  const res = await api.ok<{ deleted: number }>('POST', `/admin/tenants/${tenantId}/express-secrets/purge`);
  return res.deleted;
}

/** Opens /x and expects the creation form. */
export async function openExpress(page: Page, origin: string): Promise<void> {
  await page.goto(`${origin}/x`);
  await expect(page.getByRole('heading', { name: 'Express secret', level: 1 })).toBeVisible();
  await expect(page.locator('#tt-express-text')).toBeVisible();
}

/** Fills the form of /x; the duration is a label such as "1 hour", "1 day" or "7 days". */
export async function fillExpress(page: Page, text: string, duration?: string): Promise<void> {
  await page.locator('#tt-express-text').fill(text);
  if (duration !== undefined) await page.getByRole('radio', { name: duration }).check();
}

/** Sends the form of /x and waits for the done screen; returns the full link shown. */
export async function submitExpress(page: Page): Promise<string> {
  await page.locator('#tt-express-submit').click();
  await expect(page.getByRole('heading', { name: 'Secret created', level: 1 })).toBeVisible({
    timeout: 30_000,
  });
  const link = (await page.getByTestId('express-done-link').textContent()) ?? '';
  expect(link).toMatch(/\/s\/tts_[A-Za-z0-9]{43}#k=[A-Za-z0-9_-]{43}$/);
  return link;
}

/** Opens /x, creates an express secret and returns its link. */
export async function createExpress(
  page: Page,
  origin: string,
  text: string,
  duration?: string,
): Promise<string> {
  await openExpress(page, origin);
  await fillExpress(page, text, duration);
  return submitExpress(page);
}

/** A text with a distinctive random marker, a URL, HTML and Markdown (rendered as plain text). */
export function expressText(): { text: string; marker: string } {
  const marker = `xs-${crypto.randomBytes(8).toString('hex')}`;
  return {
    text: `${marker} see https://evil.example/login <b>bold</b> [click](https://evil.example/) é中`,
    marker,
  };
}

/** The token (tts_...) of a secret link. */
export function tokenOf(link: string): string {
  const m = /\/s\/(tts_[A-Za-z0-9]{43})/.exec(link);
  if (!m) throw new Error(`no secret token in ${link}`);
  return m[1]!;
}

/**
 * Checks that a marker of the plaintext, and the full link with its key, appear in no URL, header
 * or body of the captured requests (T-399), and that no Referer carries a fragment.
 */
export function expectTextAndLinkNowhere(
  requests: readonly CapturedRequest[],
  marker: string,
  link: string,
): void {
  for (const r of requests) {
    const where = `${r.method} ${r.url}`;
    const parts = [r.url, decodeURIComponent(r.url), ...Object.values(r.headers)];
    if (r.body !== null) parts.push(r.body.toString('utf8'), r.body.toString('latin1'));
    for (const part of parts) {
      expect(part.includes(marker), `plaintext in ${where}`).toBe(false);
      expect(part.includes(link), `full link in ${where}`).toBe(false);
    }
    const referer = r.headers.referer;
    if (referer !== undefined) expect(referer, `fragment in the Referer of ${where}`).not.toContain('#');
  }
}

/** Waits for a mail to `to` whose text contains `needle` (the mailbox is shared by many tests). */
export async function waitForMailContaining(to: string, needle: string, timeoutMs = 30_000): Promise<Mail> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    for (const summary of await listMails(to)) {
      const mail = await getMail(summary.ID);
      if (mail.Text.includes(needle) || mail.HTML.includes(needle)) return mail;
    }
    if (Date.now() > deadline) throw new Error(`no mail to ${to} containing ${needle}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

/** Creates an auditor of a tenant (no second factor) and returns its credentials. */
export async function createAuditor(
  api: AdminApi,
  state: E2EState,
  tenantId: string,
): Promise<{ username: string; password: string }> {
  const username = `xs-auditor-${crypto.randomBytes(4).toString('hex')}`;
  const password = `e2e-auditor-${crypto.randomBytes(12).toString('base64url')}`;
  const created = await api.ok<{ activationUrl: string }>(
    'POST',
    '/admin/admins',
    {
      username,
      email: `${username}@example.com`,
      role: 'auditor',
      tenantIds: [tenantId],
      requireTotp: false,
    },
    [201],
  );
  const activated = await request(state.serverPort, 'POST', '/api/v1/admin/activation', {
    body: { activationToken: new URL(created.activationUrl).hash.slice(1), password },
    headers: { Origin: ORIGINS.admin, 'Sec-Fetch-Site': 'same-origin' },
  });
  expect(activated.status).toBeLessThan(300);
  return { username, password };
}
