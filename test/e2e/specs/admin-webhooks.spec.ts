// Webhooks (CLAUDE.md section 12.4, V1.1 step 3): tenant webhooks as the delegated admin of
// entity A (creation of a generic webhook with its secret shown once, test delivery checked by a
// local receiver with the HMAC signature, edition, secret rotation, address refused by the
// network guard, deletion, failed test), instance webhooks as the super admin (system events
// only, rate limit of the test button) and the "include addresses" switch of the General screen.
//
// Receivers: each test starts its own HTTP server on 127.0.0.1 (free port). The server under
// test must allow that range for webhooks: TT_WEBHOOK_ALLOW_NETWORKS and
// TT_WEBHOOK_ALLOW_HTTP_NETWORKS include 127.0.0.0/8 in support/server.ts. Every other private
// or reserved range keeps its default refusal (169.254.169.254 is refused below).
import type { Page } from '@playwright/test';
import crypto from 'node:crypto';
import http from 'node:http';
import type net from 'node:net';
import { ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { re } from '../support/regexp';
import { freePort } from '../support/server';
import { delegateApi } from '../support/state';

/** One request received by a test receiver. */
interface Received {
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** A local webhook receiver answering 200 to every POST. */
interface Receiver {
  /** Base URL (http://127.0.0.1:<port>). */
  readonly url: string;
  readonly received: Received[];
  close(): Promise<void>;
}

async function startReceiver(): Promise<Receiver> {
  const received: Received[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      received.push({
        path: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as net.AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    received,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/**
 * Checks the X-TransTeira-Signature header of a delivery ("t=<unix>,v1=<hex HMAC-SHA256 of
 * "<t>.<body>">") with the secret shown once, in constant time.
 */
function signatureValid(delivery: Received, secret: string): boolean {
  const header = String(delivery.headers['x-transteira-signature'] ?? '');
  const parts = Object.fromEntries(header.split(',').map((p) => p.split('=', 2) as [string, string]));
  const t = parts['t'];
  const v1 = parts['v1'];
  if (!t || !v1 || !/^[0-9a-f]{64}$/.test(v1)) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${t}.${delivery.body}`).digest();
  return crypto.timingSafeEqual(expected, Buffer.from(v1, 'hex'));
}

/** The row of a table that contains `text`. */
function rowWith(page: Page, text: string | RegExp) {
  return page.getByRole('row').filter({ hasText: text });
}

/** Unique name of a webhook of this run. */
function uniqueName(prefix: string): string {
  return `${prefix} ${crypto.randomBytes(4).toString('hex')}`;
}

/** Reads the secret of the SecretOnceModal, acknowledges it and closes the dialog. */
async function takeSecret(page: Page, title: string): Promise<string> {
  const modal = page.getByRole('dialog', { name: title });
  await expect(modal).toBeVisible();
  const secret = (await modal.locator('code').innerText()).trim();
  expect(secret.length).toBeGreaterThanOrEqual(32);
  await checkA11y(page);
  const close = modal.getByRole('button', { name: 'Close' });
  await expect(close).toBeDisabled();
  await modal.getByRole('checkbox', { name: /I have stored this secret/ }).check();
  await close.click();
  await expect(modal).toBeHidden();
  return secret;
}

test.describe('tenant webhooks', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('a generic webhook is created, tested with a valid signature, edited, re-keyed and deleted', async ({
    page,
    state,
  }) => {
    const receiver = await startReceiver();
    try {
      const name = uniqueName('e2e SIEM');
      const hookPath = `/hook-${crypto.randomBytes(4).toString('hex')}`;
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/webhooks`);
      await expect(page.getByRole('heading', { name: 'Webhooks', level: 1 })).toBeVisible();
      await expect(
        page.getByRole('navigation').getByRole('link', { name: 'Webhooks', exact: true }),
      ).toHaveAttribute('aria-current', 'page');
      await checkA11y(page);

      // Creation: client-side checks first.
      await page.getByRole('button', { name: 'Add a webhook' }).click();
      const create = page.getByRole('dialog', { name: 'New webhook' });
      await expect(create).toBeVisible();
      await create.getByRole('button', { name: 'Create the webhook' }).click();
      await expect(create.getByText('Select at least one event.').first()).toBeVisible();
      await create.getByLabel(/^Name/).fill(name);
      await create.getByRole('radio', { name: 'Generic JSON' }).check();
      await create.getByLabel(/^Address \(URL\)/).fill(`${receiver.url}${hookPath}`);
      // Tenant events only.
      await expect(create.getByRole('checkbox', { name: 'Disk space alert' })).toHaveCount(0);
      await create.getByRole('checkbox', { name: 'Virus detected' }).check();
      await create.getByRole('checkbox', { name: 'Quota reached' }).check();
      await checkA11y(page);
      await create.getByRole('button', { name: 'Create the webhook' }).click();
      await expect(create).toBeHidden();
      const secret = await takeSecret(page, `Webhook ${name} created`);
      await expectCleanStorage(page);

      const row = rowWith(page, name);
      await expect(row).toHaveCount(1);
      await expect(row.getByText('Generic JSON')).toBeVisible();
      await expect(row.getByText(receiver.url)).toBeVisible();
      await expect(row.getByText(hookPath)).toHaveCount(0);
      await expect(row.getByText('Enabled', { exact: true })).toBeVisible();
      await expect(row.getByText('None yet')).toBeVisible();

      // Test: delivered to the receiver, signed with the secret shown once.
      await row.getByRole('button', { name: `Test ${name}` }).click();
      await expect(page.getByText(re(`Test of ${name} delivered: HTTP 200`))).toBeVisible();
      // A test is not a delivery (testTenantWebhook): the last delivery stays empty.
      await expect(row.getByText('None yet')).toBeVisible();
      expect(receiver.received).toHaveLength(1);
      const first = receiver.received[0]!;
      expect(first.path).toBe(hookPath);
      expect(first.headers['x-transteira-event']).toBe('webhook.test');
      expect(signatureValid(first, secret)).toBe(true);
      expect(first.body).not.toContain('@');

      // Edition: rename and drop one event; the URL field left empty keeps the address.
      const renamed = `${name} v2`;
      await row.getByRole('button', { name: `Edit ${name}` }).click();
      const edit = page.getByRole('dialog', { name: `Edit the webhook ${name}` });
      await expect(edit.getByLabel(/^New address \(URL\)/)).toHaveValue('');
      await edit.getByLabel(/^Name/).fill(renamed);
      await edit.getByRole('checkbox', { name: 'Quota reached' }).uncheck();
      await checkA11y(page);
      await edit.getByRole('button', { name: 'Save' }).click();
      await expect(edit).toBeHidden();
      const renamedRow = rowWith(page, renamed);
      await expect(renamedRow).toHaveCount(1);
      await expect(renamedRow.getByText('Quota reached')).toHaveCount(0);
      await expect(renamedRow.getByText('Virus detected')).toBeVisible();

      // Rotation: the new secret signs the next test, the old one no longer does.
      await renamedRow.getByRole('button', { name: `New secret ${renamed}` }).click();
      const rotate = page.getByRole('dialog', { name: `Generate a new secret for ${renamed}?` });
      await rotate.getByRole('button', { name: 'Generate a new secret' }).click();
      const rotated = await takeSecret(page, `New secret of the webhook ${renamed}`);
      expect(rotated).not.toBe(secret);
      await renamedRow.getByRole('button', { name: `Test ${renamed}` }).click();
      await expect(page.getByText(re(`Test of ${renamed} delivered: HTTP 200`))).toBeVisible();
      expect(receiver.received).toHaveLength(2);
      expect(signatureValid(receiver.received[1]!, rotated)).toBe(true);
      expect(signatureValid(receiver.received[1]!, secret)).toBe(false);

      // Deletion.
      await renamedRow.getByRole('button', { name: `Delete ${renamed}` }).click();
      const del = page.getByRole('dialog', { name: `Delete the webhook ${renamed}?` });
      await checkA11y(page);
      await del.getByRole('button', { name: 'Delete the webhook' }).click();
      await expect(del).toBeHidden();
      await expect(rowWith(page, renamed)).toHaveCount(0);
      await expect(page.getByRole('heading', { name: 'Webhooks', level: 1 })).toBeFocused();
    } finally {
      await receiver.close();
    }
  });

  test('an address of a denied network is refused on the URL field', async ({ page, state, guards }) => {
    guards.allowHttpError(400, /\/admin\/tenants\/[^/]+\/webhooks$/);
    await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/webhooks`);
    await page.getByRole('button', { name: 'Add a webhook' }).click();
    const create = page.getByRole('dialog', { name: 'New webhook' });
    await create.getByLabel(/^Name/).fill(uniqueName('e2e metadata'));
    await create.getByRole('radio', { name: 'Microsoft Teams' }).check();
    // Client-side check: user information is refused before sending.
    await create.getByLabel(/^Address \(URL\)/).fill('https://user:pass@hooks.example.com/x');
    await create.getByRole('checkbox', { name: 'Abuse reported' }).check();
    await create.getByRole('button', { name: 'Create the webhook' }).click();
    await expect(
      create.getByText('The address must not contain a user name or a password.').first(),
    ).toBeVisible();
    // Server-side network guard: the cloud metadata address is always refused.
    await create.getByLabel(/^Address \(URL\)/).fill('https://169.254.169.254/latest/meta-data');
    await create.getByRole('button', { name: 'Create the webhook' }).click();
    await expect(create.getByText(/This address is not allowed/).first()).toBeVisible();
    await expect(create.getByLabel(/^Address \(URL\)/)).toHaveAttribute('aria-invalid', 'true');
    await checkA11y(page);
  });

  test('a failed test reports a coarse cause and leaves the last delivery unchanged', async ({
    page,
    state,
  }) => {
    // A closed port on loopback (allowed network): the connection is refused.
    const closed = await freePort('127.0.0.1');
    const name = uniqueName('e2e closed');
    const api = delegateApi();
    const created = await api.ok<{ id: string }>(
      'POST',
      `/admin/tenants/${state.tenants.a.id}/webhooks`,
      { name, kind: 'slack', url: `http://127.0.0.1:${closed}/hook`, events: ['quota.warning'] },
      [201],
    );
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/webhooks`);
      const row = rowWith(page, name);
      await expect(row.getByText('Slack', { exact: true })).toBeVisible();
      // No secret for Slack: no rotation.
      await expect(row.getByRole('button', { name: `New secret ${name}` })).toHaveCount(0);
      await row.getByRole('button', { name: `Test ${name}` }).click();
      await expect(page.getByText(re(`Test of ${name} failed: Connection failed`))).toBeVisible();
      // The outcome is only in the alert: the test is not recorded as a delivery.
      await expect(row.getByText('None yet')).toBeVisible();
      await expect(row.getByText('Failed', { exact: true })).toHaveCount(0);
      await checkA11y(page);
    } finally {
      await api.ok('DELETE', `/admin/tenants/${state.tenants.a.id}/webhooks/${created.id}`, undefined, [204]);
    }
  });

  test('the General screen switches the addresses of the webhook alerts', async ({ page, state }) => {
    const general = `${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/general`;
    await page.goto(general);
    const section = page.getByRole('region', { name: 'Webhooks' });
    const box = section.getByRole('checkbox', { name: 'Include addresses in webhooks' });
    await expect(box).not.toBeChecked();
    await expect(section.getByText(/Addresses are personal data/)).toBeVisible();
    try {
      await box.check();
      await section.getByRole('button', { name: 'Save the webhook setting' }).click();
      await expect(page.getByText('Webhook setting saved.').first()).toBeVisible();
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/webhooks`);
      await expect(
        page.getByText('The alerts of this entity include the addresses concerned.'),
      ).toBeVisible();
      await checkA11y(page);
    } finally {
      await page.goto(general);
      const again = page
        .getByRole('region', { name: 'Webhooks' })
        .getByRole('checkbox', { name: 'Include addresses in webhooks' });
      if (await again.isChecked()) {
        await again.uncheck();
        await page
          .getByRole('region', { name: 'Webhooks' })
          .getByRole('button', { name: 'Save the webhook setting' })
          .click();
        await expect(page.getByText('Webhook setting saved.').first()).toBeVisible();
      }
    }
  });
});

test.describe('instance webhooks', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('the super admin manages the system webhooks; the test button is rate limited', async ({
    page,
    guards,
  }) => {
    guards.allowHttpError(429, /\/admin\/system\/webhooks\/[^/]+\/test$/);
    const receiver = await startReceiver();
    try {
      const name = uniqueName('e2e ops channel');
      await page.goto(`${ORIGINS.admin}/admin/system/webhooks`);
      await expect(page.getByRole('heading', { name: 'Instance webhooks', level: 1 })).toBeVisible();
      await expect(
        page
          .getByRole('navigation', { name: 'System administration' })
          .getByRole('link', { name: 'Webhooks', exact: true }),
      ).toHaveAttribute('aria-current', 'page');

      await page.getByRole('button', { name: 'Add a webhook' }).click();
      const create = page.getByRole('dialog', { name: 'New webhook' });
      await create.getByLabel(/^Name/).fill(name);
      await create.getByRole('radio', { name: 'Slack' }).check();
      await create.getByLabel(/^Address \(URL\)/).fill(`${receiver.url}/slack`);
      // System events only.
      await expect(create.getByRole('checkbox', { name: 'Virus detected' })).toHaveCount(0);
      await create.getByRole('checkbox', { name: 'Disk space alert' }).check();
      await create.getByRole('checkbox', { name: 'Antivirus unavailable' }).check();
      await checkA11y(page);
      await create.getByRole('button', { name: 'Create the webhook' }).click();
      await expect(create).toBeHidden();
      // Slack: no secret to show.
      await expect(page.getByRole('dialog')).toHaveCount(0);
      const row = rowWith(page, name);
      await expect(row.getByText('Disk space alert')).toBeVisible();

      // 10 tests per hour per administrator: the next one is refused with the wait.
      const button = row.getByRole('button', { name: `Test ${name}` });
      let limited = false;
      const outcome = page.getByText(/^Test of .* delivered|^Too many tests/);
      for (let i = 0; i < 11 && !limited; i++) {
        // The previous outcome is dismissed first, so that the one read below is new.
        if ((await outcome.count()) > 0)
          await page.getByRole('button', { name: 'Dismiss this message' }).click();
        await expect(outcome).toHaveCount(0);
        await button.click();
        await expect(outcome).toHaveCount(1);
        limited = /Too many tests/.test(await outcome.innerText());
      }
      expect(limited).toBe(true);
      await expect(page.getByText(/Try again (in \d+ min|later)/)).toBeVisible();
      // A retried test may start with the quota already used: at most 10 deliveries.
      expect(receiver.received.length).toBeLessThanOrEqual(10);
      expect(receiver.received.every((r) => r.headers['x-transteira-signature'] === undefined)).toBe(true);

      await row.getByRole('button', { name: `Delete ${name}` }).click();
      await page
        .getByRole('dialog', { name: `Delete the webhook ${name}?` })
        .getByRole('button', { name: 'Delete the webhook' })
        .click();
      await expect(rowWith(page, name)).toHaveCount(0);
    } finally {
      await receiver.close();
    }
  });
});
