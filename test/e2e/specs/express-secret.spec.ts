// Express secrets (CLAUDE.md section 22.2, threat model 6.65 and checklist 9.3), client side:
//   - public: the service is off by default; once enabled, creation on /x, reading by a third
//     party with the "unverified third party" banner, plain text rendering, the network capture
//     (T-399), the 10 000 code point limit, abuse reports, the closed service, the rate limit and
//     the isolation between entities;
//   - admin: the settings section, the API token opt-in, the lookup by link (T-408), the emergency
//     purge and the read-only auditor.
// Every test works on entity A, whose express switch is shared state: the tests of this file run
// one after the other (default mode of a describe block) and an afterEach restores the defaults and
// purges the secrets they created.
import { HOSTS, ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { AdminApi, request } from '../support/api';
import { externalIp } from '../support/clientip';
import {
  EXPRESS_DEFAULTS,
  createAuditor,
  createExpress,
  expectTextAndLinkNowhere,
  expressText,
  fillExpress,
  openExpress,
  purgeExpress,
  setExpress,
  submitExpress,
  tokenOf,
  waitForMailContaining,
} from '../support/express';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { msg } from '../support/i18n';
import {
  captureRequests,
  expectGone,
  expectKeyNowhere,
  expectReady,
  expectRevealed,
  pressShow,
} from '../support/secret';
import { waitForSecurityEvents } from '../support/securitylog';
import { delegateApi, superAdminApi } from '../support/state';

const SECRET_LINK_API = /\/api\/v1\/secret-links\/[^/]+(\/reveal)?$/;
const EXPRESS_API = /\/api\/v1\/express-secrets$/;
const MAX_CHARS = 10_000;

/** Files an abuse report on an express secret straight on the API (same-origin headers, like the browser). */
async function reportSecretOnApi(serverPort: number, link: string, message: string): Promise<void> {
  const res = await request(serverPort, 'POST', `/api/v1/secret-links/${tokenOf(link)}/abuse-reports`, {
    host: HOSTS.a,
    body: { category: 'phishing', message },
    headers: { Origin: ORIGINS.a, 'Sec-Fetch-Site': 'same-origin' },
    clientIp: externalIp(),
  });
  expect(res.status).toBe(202);
}

// The config runs tests in parallel: this file shares the express switch of entity A.
test.describe.configure({ mode: 'default' });

test.beforeEach(async ({ state }) => {
  await setExpress(superAdminApi(), state.tenants.a.id, EXPRESS_DEFAULTS);
  await purgeExpress(superAdminApi(), state.tenants.a.id);
});

test.afterEach(async ({ state }) => {
  await setExpress(superAdminApi(), state.tenants.a.id, EXPRESS_DEFAULTS);
  await purgeExpress(superAdminApi(), state.tenants.a.id);
});

test.describe('public: express secrets', () => {
  test('off by default: no page, no header link, creation refused without a token', async ({
    page,
    state,
    clientIp,
    guards,
  }) => {
    guards.allowHttpError(403, EXPRESS_API);
    const origin = state.tenants.a.origin;
    await page.goto(`${origin}/`);
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
    await expect(page.locator('#tt-header-express')).toHaveCount(0);

    await page.goto(`${origin}/x`);
    await expect(page.getByRole('heading', { name: 'Express secret', level: 1 })).toBeVisible();
    await expect(page.getByText(`${state.tenants.a.name} does not offer express secrets.`)).toBeVisible();
    await expect(page.locator('#tt-express-text')).toHaveCount(0);
    await checkA11y(page);

    const res = await request<{ code: string }>(state.serverPort, 'POST', '/api/v1/express-secrets', {
      host: HOSTS.a,
      body: {},
      clientIp,
    });
    expect(res.status).toBe(403);
    expect(res.json.code).toBe('express-secrets-disabled');
    const lines = await waitForSecurityEvents({
      ip: clientIp,
      event: 'express_refused',
      fields: { reason: 'disabled' },
    });
    expect(lines).toHaveLength(1);

    // A token without the opt-in is refused too, with its own code.
    const token = await request<{ code: string }>(state.serverPort, 'POST', '/api/v1/express-secrets', {
      host: HOSTS.a,
      body: {},
      headers: { Authorization: `Bearer ${state.apiTokenA}` },
    });
    expect(token.status).toBe(403);
    expect(token.json.code).toBe('express-token-not-allowed');
  });

  test('create, read once by a third party, plain text, second reading refused', async ({
    page,
    context,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(410, SECRET_LINK_API);
    const origin = state.tenants.a.origin;
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true });
    const { text } = expressText();

    // The header link appears on every public page once the service is offered.
    await page.goto(`${origin}/`);
    const nav = page.locator('#tt-header-express');
    await expect(nav).toHaveText('Express secret');
    await nav.click();
    await expect(page).toHaveURL(`${origin}/x`);
    await expect(page.locator('#tt-express-text')).toBeVisible();
    await expect(page.getByRole('radio', { name: '1 day' })).toBeChecked();
    await checkA11y(page);

    // Counter, duration, link shown once, copy.
    await fillExpress(page, text, '7 days');
    await expect(page.locator('#tt-express-text-counter')).toHaveText(
      new RegExp(`^${[...text].length} characters of 10,000$`),
    );
    const link = await submitExpress(page);
    expect(link.startsWith(`${origin}/s/tts_`)).toBe(true);
    await expect(page.getByText('This link is shown only once.')).toBeVisible();
    await expect(page.locator('#tt-express-text')).toHaveCount(0);
    expect(page.url()).toBe(`${origin}/x`);
    await checkA11y(page);
    await page.getByRole('button', { name: 'Copy the link' }).click();
    await expect(page.getByText('Copied to the clipboard')).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link);
    await expectCleanStorage(page);

    // "Create another secret" forgets the link and the text.
    await page.locator('#tt-express-another').click();
    await expect(page.locator('#tt-express-text')).toHaveValue('');
    await expect(page.getByTestId('express-done-link')).toHaveCount(0);

    // The recipient, from another browser and another address.
    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(link);
    await expectReady(reader);
    expect(reader.url()).not.toContain('k=');
    const banner = reader.getByTestId('secret-express-banner');
    await expect(banner).toContainText(
      `Content created by an unverified third party: ${state.tenants.a.name} is not its author.`,
    );
    await checkA11y(reader);
    await pressShow(reader);
    await expectRevealed(reader, text);
    await expect(banner).toBeVisible();

    // Plain text: the URL is not a link, the tag is not markup.
    await expect(reader.locator('main a[href*="evil.example"], a[href*="evil.example"]')).toHaveCount(0);
    await expect(reader.locator('main b')).toHaveCount(0);
    expect(await reader.content()).not.toContain('<b>bold</b>');
    await checkA11y(reader);
    await expectCleanStorage(reader);

    const second = await (await newContext({ clientIp: externalIp() })).newPage();
    await second.goto(link);
    await expectGone(second, 'This secret has already been read.');
  });

  test('the text and the key never leave the browser: creation, reading and report (T-399)', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(410, SECRET_LINK_API);
    const origin = state.tenants.a.origin;
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true });
    const { text, marker } = expressText();
    const created = captureRequests(page.context());
    const link = await createExpress(page, origin, text);

    const context = await newContext({ clientIp: externalIp() });
    const read = captureRequests(context);
    const reader = await context.newPage();
    await reader.goto(link);
    await expectReady(reader);
    await reader.getByRole('button', { name: 'Report an abuse', exact: true }).click();
    const dialog = reader.getByRole('dialog', { name: 'Report an abuse' });
    await dialog.getByRole('radio', { name: /^Phishing/ }).check();
    await dialog.getByLabel(/^Message/).fill('The text asks me to open a fake login page.');
    await dialog.getByRole('button', { name: 'Send the report' }).click();
    await expect(dialog.getByText('Report sent to the administrators')).toBeVisible();
    await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
    await expect(dialog).toBeHidden();
    await pressShow(reader);
    await expectRevealed(reader, text);

    await created.done();
    await read.done();
    const create = created.requests.filter((r) => r.method === 'POST' && EXPRESS_API.test(r.url));
    expect(create).toHaveLength(1);
    const body = JSON.parse(create[0]!.body!.toString('utf8')) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['encryptedText', 'expiresIn', 'keyVerifier', 'verifier']);
    const report = read.requests.filter((r) => r.method === 'POST' && r.url.endsWith('/abuse-reports'));
    expect(report).toHaveLength(1);
    expect(Object.keys(JSON.parse(report[0]!.body!.toString('utf8')) as object).sort()).toEqual([
      'category',
      'message',
    ]);
    expect(read.requests.some((r) => r.url.endsWith('/reveal'))).toBe(true);

    for (const captured of [created.requests, read.requests]) {
      expect(expectKeyNowhere(captured, link)).toBe(0);
      expectTextAndLinkNowhere(captured, marker, link);
    }
  });

  test('10 000 code points are accepted, 10 001 are refused without any request', async ({
    page,
    state,
    newContext,
  }) => {
    const origin = state.tenants.a.origin;
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true });
    const sent: string[] = [];
    page.on('request', (req) => {
      if (EXPRESS_API.test(req.url())) sent.push(req.url());
    });

    await openExpress(page, origin);
    await fillExpress(page, '\u{1F600}'.repeat(MAX_CHARS + 1));
    await page.locator('#tt-express-submit').click();
    await expect(page.getByText('The text is too long: 10,000 characters at most.').first()).toBeVisible();
    await expect(page.locator('#tt-express-text-counter')).toHaveText('10,001 characters of 10,000');
    expect(sent).toEqual([]);
    await checkA11y(page);

    const emoji = '\u{1F600}'.repeat(MAX_CHARS);
    await fillExpress(page, emoji);
    await expect(page.locator('#tt-express-text-counter')).toHaveText('10,000 characters of 10,000');
    const link = await submitExpress(page);
    expect(sent).toHaveLength(1);

    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(link);
    await pressShow(reader);
    await expectRevealed(reader, emoji);
  });

  test('a report names the secret for the admins: screen and mail, never the link', async ({
    page,
    state,
    newContext,
  }) => {
    const origin = state.tenants.a.origin;
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true });
    const { text } = expressText();
    const link = await createExpress(page, origin, text);
    const secretId = (
      await delegateApi().ok<{ id: string }>('POST', `/admin/tenants/${state.tenants.a.id}/secrets/lookup`, {
        link,
      })
    ).id;
    const since = Date.now() - 2000;
    const message = `fake bank page ${secretId}`;

    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(link);
    await expectReady(reader);
    // Before reading, then after: the button stays available.
    await reader.getByRole('button', { name: 'Report an abuse', exact: true }).click();
    const dialog = reader.getByRole('dialog', { name: 'Report an abuse' });
    await dialog.getByRole('radio', { name: /^Spam/ }).check();
    await dialog.getByRole('button', { name: 'Send the report' }).click();
    await expect(dialog.getByText('Report sent to the administrators')).toBeVisible();
    await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
    await pressShow(reader);
    await expectRevealed(reader, text);
    await reader.getByRole('button', { name: 'Report an abuse', exact: true }).click();
    await dialog.getByRole('radio', { name: /^Phishing/ }).check();
    await dialog.getByLabel(/^Message/).fill(message);
    await dialog.getByRole('button', { name: 'Send the report' }).click();
    await expect(dialog.getByText('Report sent to the administrators')).toBeVisible();

    // The alert names the secret by its identifier, without any token or link.
    const mail = await waitForMailContaining(state.delegate.email, secretId);
    expect(Date.parse(mail.Date)).toBeGreaterThanOrEqual(since);
    for (const part of [mail.Text, mail.HTML, mail.Subject]) {
      expect(part).not.toContain(tokenOf(link));
      expect(part).not.toContain('#k=');
      expect(part).not.toContain('/s/tts_');
    }

    // The delegated admin sees the report with the secret identifier.
    const admin = await (await newContext({ storageState: STORAGE_DELEGATE })).newPage();
    await admin.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/abuse-reports?status=open`);
    await expect(admin.getByRole('heading', { name: 'Abuse reports', level: 1 })).toBeVisible();
    const row = admin.getByRole('row').filter({ hasText: `Express secret ${secretId}` });
    await expect(row).toHaveCount(2);
    await row
      .filter({ hasText: 'Phishing' })
      .getByRole('button', { name: /^Details of the/ })
      .click();
    const details = admin.getByRole('dialog', { name: 'Abuse report' });
    await expect(details.getByText(message, { exact: true })).toBeVisible();
    await expect(details.locator('code', { hasText: secretId })).toBeVisible();
    await expect(details.getByText(tokenOf(link))).toHaveCount(0);
    await checkA11y(admin);
  });

  test('closing the service blocks the reading without consuming anything', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(403, SECRET_LINK_API);
    const origin = state.tenants.a.origin;
    const api = superAdminApi();
    await setExpress(api, state.tenants.a.id, { expressEnabled: true });
    const { text } = expressText();
    const link = await createExpress(page, origin, text);

    await setExpress(api, state.tenants.a.id, { expressEnabled: false });
    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(link);
    await expect(
      reader.getByRole('heading', { name: 'Secret temporarily unavailable', level: 1 }),
    ).toBeVisible();
    await expect(reader.getByText('Nothing was consumed')).toBeVisible();
    await expect(reader.getByRole('button', { name: 'Report an abuse', exact: true })).toBeVisible();
    await checkA11y(reader);

    // Reopened: the same link is readable, once.
    await setExpress(api, state.tenants.a.id, { expressEnabled: true });
    await reader.getByRole('button', { name: 'Try again' }).click();
    await expectReady(reader);
    await pressShow(reader);
    await expectRevealed(reader, text);
  });

  test('the creation rate limit shows a message and is written to the security log', async ({
    page,
    state,
    clientIp,
    guards,
  }) => {
    guards.allowHttpError(429, EXPRESS_API);
    const origin = state.tenants.a.origin;
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true, expressPerHourPerIp: 2 });
    await createExpress(page, origin, 'first');
    await createExpress(page, origin, 'second');

    await openExpress(page, origin);
    await fillExpress(page, 'third');
    await page.locator('#tt-express-submit').click();
    await expect(page.getByText(/Too many secrets created from your connection/)).toBeVisible();
    // The text was not sent and is still there.
    await expect(page.locator('#tt-express-text')).toHaveValue('third');
    await checkA11y(page);
    const lines = await waitForSecurityEvents({
      ip: clientIp,
      event: 'rate_limited',
      fields: { scope: 'express_ip' },
    });
    expect(lines.length).toBeGreaterThanOrEqual(1);
  });

  test('the link of an entity is unknown to another entity', async ({ page, state, newContext, guards }) => {
    guards.allowHttpError(404, SECRET_LINK_API);
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true });
    const { text } = expressText();
    const link = await createExpress(page, state.tenants.a.origin, text);

    const foreign = link.replace(state.tenants.a.origin, state.tenants.b.origin);
    expect(foreign).not.toBe(link);
    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(foreign);
    await expect(reader.getByRole('heading', { name: 'Unknown link', level: 1 })).toBeVisible();
    await expect(reader.getByRole('button', { name: 'Show the secret' })).toHaveCount(0);

    const status = await request(state.serverPort, 'GET', `/api/v1/secret-links/${tokenOf(link)}`, {
      host: HOSTS.b,
    });
    expect(status.status).toBe(404);

    // The administration of entity B does not find it either.
    const lookup = await superAdminApi().call('POST', `/admin/tenants/${state.tenants.b.id}/secrets/lookup`, {
      link,
    });
    expect(lookup.status).toBe(404);

    // Still readable on its own entity: nothing was consumed.
    const own = await (await newContext({ clientIp: externalIp() })).newPage();
    await own.goto(link);
    await expectReady(own);
    await pressShow(own);
    await expectRevealed(own, text);
  });

  test('the help of /x opens the express secret section only when the service is offered', async ({
    page,
    state,
  }) => {
    const origin = state.tenants.a.origin;
    const helpLink = page
      .getByRole('contentinfo')
      .getByRole('link', { name: msg('en', 'components.help.label'), exact: true });
    const sectionTitle = page.getByRole('heading', { name: 'Express secret', level: 2, exact: true });

    // Service off: the section is not offered, the topic falls back to the top of its guide.
    await page.goto(`${origin}/help/express-secret`);
    await expect(page.getByRole('heading', { name: 'Sending files', level: 1 })).toBeFocused();
    await expect(sectionTitle).toHaveCount(0);

    // Service on: the footer help link of /x opens the section, focused.
    await setExpress(superAdminApi(), state.tenants.a.id, { expressEnabled: true });
    await openExpress(page, origin);
    await helpLink.click();
    await expect(page).toHaveURL(/\/help\/express-secret$/);
    await expect(sectionTitle).toBeFocused();
    await checkA11y(page);
    await expectCleanStorage(page);
  });
});

test.describe('admin: express secrets', () => {
  test.describe('delegated admin', () => {
    test.use({ storageState: STORAGE_DELEGATE });

    test('the settings section is validated, saved and shown again', async ({ page, state }) => {
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/secret-settings`);
      await expect(page.getByRole('heading', { name: 'Secrets settings', level: 1 })).toBeVisible();
      const section = page.getByRole('group', { name: 'Express secrets (anonymous)' });
      const enabled = section.getByLabel('Allow anonymous express secrets');
      await expect(enabled).not.toBeChecked();
      await expect(page.getByText(/Before opening this service/)).toHaveCount(0);
      await enabled.check();
      await expect(page.getByText(/Before opening this service/)).toBeVisible();
      await expect(
        section.getByRole('link', { name: 'Open the legal texts of this entity' }),
      ).toHaveAttribute('href', `/admin/tenants/${state.tenants.a.id}/legal`);

      const perIp = section.getByLabel(/^Secrets per hour and per client address/);
      const save = page.getByRole('button', { name: 'Save', exact: true });
      for (const bad of ['0', '1001', 'abc']) {
        await perIp.fill(bad);
        await save.click();
        await expect(page.getByText('Enter a whole number from 1 to 10.').first()).toBeVisible();
      }
      await checkA11y(page);

      await perIp.fill('7');
      await section.getByLabel(/^Secrets per hour and per API token/).fill('50');
      await section.getByLabel(/^Express secrets waiting at the same time/).fill('500');
      await save.click();
      await expect(page.getByText('Secrets settings saved.').first()).toBeVisible();

      await page.reload();
      const again = page.getByRole('group', { name: 'Express secrets (anonymous)' });
      await expect(again.getByLabel('Allow anonymous express secrets')).toBeChecked();
      await expect(again.getByLabel(/^Secrets per hour and per client address/)).toHaveValue('7');
      await expect(again.getByLabel(/^Secrets per hour and per API token/)).toHaveValue('50');
      await expect(again.getByLabel(/^Express secrets waiting at the same time/)).toHaveValue('500');
      const saved = await delegateApi().ok<Record<string, unknown>>(
        'GET',
        `/admin/tenants/${state.tenants.a.id}/secret-settings`,
      );
      expect(saved).toMatchObject({
        expressEnabled: true,
        expressPerHourPerIp: 7,
        expressPerHourPerToken: 50,
        expressMaxPending: 500,
      });
    });

    test('a delegated admin cannot raise an express limit above its default; a raised value survives a re-save', async ({
      page,
      state,
      browser,
    }) => {
      const tenantId = state.tenants.a.id;
      const settingsUrl = `${ORIGINS.admin}/admin/tenants/${tenantId}/secret-settings`;
      const limitsOf = () =>
        delegateApi().ok<Record<string, unknown>>('GET', `/admin/tenants/${tenantId}/secret-settings`);

      // Above the default: field error before any request, nothing saved.
      const puts: string[] = [];
      page.on('request', (req) => {
        if (req.method() === 'PUT' && req.url().endsWith('/secret-settings')) puts.push(req.url());
      });
      await page.goto(settingsUrl);
      const section = page.getByRole('group', { name: 'Express secrets (anonymous)' });
      const perIp = section.getByLabel(/^Secrets per hour and per client address/);
      await expect(perIp).toHaveValue('10');
      await expect(section.getByText(/You can lower these three limits/)).toBeVisible();
      await perIp.fill('11');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(
        page.getByText(/Enter at most 10: only a super administrator can raise/).first(),
      ).toBeVisible();
      await expect(perIp).toHaveAttribute('aria-invalid', 'true');
      expect(puts).toEqual([]);
      expect(await limitsOf()).toMatchObject({ expressPerHourPerIp: 10 });
      await checkA11y(page);

      // The server enforces the same rule on its own (403 forbidden, nothing stored).
      const forced = await delegateApi().call('PUT', `/admin/tenants/${tenantId}/secret-settings`, {
        ...(await limitsOf()),
        expressPerHourPerIp: 11,
      });
      expect(forced.status).toBe(403);
      expect(await limitsOf()).toMatchObject({ expressPerHourPerIp: 10 });

      // The super admin raises it; the delegated admin keeps it by re-saving the form.
      await setExpress(superAdminApi(), tenantId, { expressPerHourPerIp: 25 });
      await page.reload();
      const again = page.getByRole('group', { name: 'Express secrets (anonymous)' });
      const raised = again.getByLabel(/^Secrets per hour and per client address/);
      await expect(raised).toHaveValue('25');
      // Another field changes (a form without change saves nothing): the raised value, untouched,
      // is not sent and stays stored.
      await again.getByLabel(/^Express secrets waiting at the same time/).fill('900');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('Secrets settings saved.').first()).toBeVisible();
      expect(await limitsOf()).toMatchObject({ expressPerHourPerIp: 25, expressMaxPending: 900 });

      // Lowering stays allowed.
      await raised.fill('5');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('Secrets settings saved.').first()).toBeVisible();
      expect(await limitsOf()).toMatchObject({ expressPerHourPerIp: 5 });

      // The super admin is not bound by the default.
      const superPage = await (await browser.newContext({ storageState: STORAGE_SUPER })).newPage();
      await superPage.goto(settingsUrl);
      const superIp = superPage
        .getByRole('group', { name: 'Express secrets (anonymous)' })
        .getByLabel(/^Secrets per hour and per client address/);
      await expect(superIp).toHaveValue('5');
      await expect(superPage.getByText(/You can lower these three limits/)).toHaveCount(0);
      await superIp.fill('50');
      await superPage.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(superPage.getByText('Secrets settings saved.').first()).toBeVisible();
      expect(await limitsOf()).toMatchObject({ expressPerHourPerIp: 50 });
      await superPage.context().close();
    });

    test('a stale form never writes back the express settings the super admin changed meanwhile', async ({
      page,
      state,
    }) => {
      const tenantId = state.tenants.a.id;
      const path = `/admin/tenants/${tenantId}/secret-settings`;
      await setExpress(superAdminApi(), tenantId, { expressEnabled: true });
      await page.goto(`${ORIGINS.admin}${path}`);
      const section = page.getByRole('group', { name: 'Express secrets (anonymous)' });
      const enabled = section.getByLabel('Allow anonymous express secrets');
      await expect(enabled).toBeChecked();
      await expect(section.getByLabel(/^Secrets per hour and per client address/)).toHaveValue('10');

      // Meanwhile, the super admin closes the anonymous mode and lowers a limit.
      await setExpress(superAdminApi(), tenantId, { expressEnabled: false, expressPerHourPerIp: 2 });

      // The delegated admin, still on the stale page, changes another express limit only.
      await section.getByLabel(/^Express secrets waiting at the same time/).fill('900');
      const put = page.waitForRequest(
        (req) => req.method() === 'PUT' && req.url().endsWith('/secret-settings'),
      );
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      const body = (await put).postDataJSON() as Record<string, unknown>;
      expect(body).toMatchObject({ expressMaxPending: 900 });
      for (const key of ['expressEnabled', 'expressPerHourPerIp', 'expressPerHourPerToken']) {
        expect(key in body, key).toBe(false);
      }
      await expect(page.getByText('Secrets settings saved.').first()).toBeVisible();
      expect(await delegateApi().ok<Record<string, unknown>>('GET', path)).toMatchObject({
        expressEnabled: false,
        expressPerHourPerIp: 2,
        expressPerHourPerToken: 100,
        expressMaxPending: 900,
      });
      // The screen shows what is stored.
      await expect(enabled).not.toBeChecked();
    });

    test('an abuse report on a secret: its sec_ id is listed, the admin deletes the secret from the report', async ({
      page,
      state,
      newContext,
      guards,
    }) => {
      guards.allowHttpError(410, SECRET_LINK_API);
      const tenantId = state.tenants.a.id;
      await setExpress(superAdminApi(), tenantId, { expressEnabled: true });
      const author = await (await newContext()).newPage();
      const link = await createExpress(author, state.tenants.a.origin, expressText().text);
      const secretId = (
        await delegateApi().ok<{ id: string }>('POST', `/admin/tenants/${tenantId}/secrets/lookup`, { link })
      ).id;
      const message = `deletable secret report ${secretId}`;
      await reportSecretOnApi(state.serverPort, link, message);

      // The list shows the identifier of the row.
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenantId}/secrets`);
      await expect(page.getByRole('heading', { name: 'One-time secrets', level: 1 })).toBeVisible();
      await expect(page.getByRole('row').filter({ hasText: secretId }).first()).toBeVisible();
      await expect(page.locator('code', { hasText: secretId }).first()).toBeVisible();

      // The report: anonymous reader text, then delete with a confirmation.
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenantId}/abuse-reports?status=open`);
      const row = page.getByRole('row').filter({ hasText: `Express secret ${secretId}` });
      await expect(row).toHaveCount(1);
      await expect(row).toContainText('The anonymous reader of the express secret, not verified');
      await row.getByRole('button', { name: /^Details of the/ }).click();
      const details = page.getByRole('dialog', { name: 'Abuse report' });
      await expect(details.getByText(message, { exact: true })).toBeVisible();
      const open = details.getByRole('button', { name: 'Delete this secret' });
      await open.click();
      const confirm = page.getByRole('dialog', { name: 'Delete this express secret?' });
      await expect(confirm).toBeVisible();
      await checkA11y(page);
      // Cancel first: nothing happens and the focus goes back to the button.
      await confirm.getByRole('button', { name: 'Cancel' }).click();
      await expect(confirm).toBeHidden();
      await expect(open).toBeFocused();
      const before = await delegateApi().ok<{ state: string }>(
        'POST',
        `/admin/tenants/${tenantId}/secrets/lookup`,
        { link },
      );
      expect(before.state).toBe('active');

      await open.click();
      const deleted = page.waitForResponse(
        (res) => res.request().method() === 'DELETE' && res.url().endsWith(`/secrets/${secretId}`),
      );
      await confirm.getByRole('button', { name: 'Delete the secret' }).click();
      expect((await deleted).status()).toBe(204);
      await expect(confirm).toBeHidden();
      const result = details.getByText('Secret deleted: its link no longer works.');
      await expect(result).toBeVisible();
      await expect(result).toBeFocused();
      await expect(details.getByRole('button', { name: 'Delete this secret' })).toHaveCount(0);

      const after = await delegateApi().ok<{ state: string }>(
        'POST',
        `/admin/tenants/${tenantId}/secrets/lookup`,
        { link },
      );
      expect(after.state).toBe('deleted');
      const reader = await (await newContext({ clientIp: externalIp() })).newPage();
      await reader.goto(link);
      await expectGone(reader, 'This secret has been deleted by its sender or by an administrator.');
    });

    test('the security log labels a refused express creation', async ({ page, state, clientIp, guards }) => {
      guards.allowHttpError(403, EXPRESS_API);
      const res = await request<{ code: string }>(state.serverPort, 'POST', '/api/v1/express-secrets', {
        host: HOSTS.a,
        body: {},
        clientIp,
      });
      expect(res.status).toBe(403);
      await waitForSecurityEvents({ ip: clientIp, event: 'express_refused', fields: { reason: 'disabled' } });

      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/security-events`);
      await expect(page.getByRole('heading', { name: 'Security log', level: 1 })).toBeVisible();
      await page.getByLabel(/^Event type/).selectOption({ label: 'Express secret refused' });
      await expect(page.getByRole('cell', { name: 'Express secret refused' }).first()).toBeVisible();
      await checkA11y(page);
    });

    test('lookup by pasted link finds the secret, the key never leaves the page, then purge', async ({
      page,
      state,
      newContext,
      guards,
    }) => {
      guards.allowHttpError(404, /\/secrets\/lookup$/);
      guards.allowHttpError(410, SECRET_LINK_API);
      const tenantId = state.tenants.a.id;
      await setExpress(superAdminApi(), tenantId, { expressEnabled: true });
      const author = await (await newContext()).newPage();
      const first = await createExpress(author, state.tenants.a.origin, expressText().text);
      const second = await createExpress(author, state.tenants.a.origin, expressText().text);

      const captured = captureRequests(page.context());
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenantId}/secrets`);
      await expect(page.getByRole('heading', { name: 'One-time secrets', level: 1 })).toBeVisible();
      const input = page.getByLabel(/^Secret link/);
      const find = page.getByRole('button', { name: 'Find the secret' });

      await find.click();
      await expect(page.getByText('Paste a secret link.')).toBeVisible();
      await input.fill('https://example.org/not-a-secret');
      await find.click();
      await expect(page.getByText(/This is not a valid secret link/)).toBeVisible();
      await input.fill(`${state.tenants.a.origin}/s/tts_${'A'.repeat(43)}#k=${'B'.repeat(43)}`);
      await find.click();
      await expect(page.getByText('No secret of this entity matches this link.')).toBeVisible();

      await input.fill(first);
      await find.click();
      const found = page.getByRole('heading', { name: 'Secret found', level: 2 });
      await expect(found).toBeFocused();
      await expect(input).toHaveValue('');
      const card = page.locator('section', { has: found });
      await expect(card).toContainText('Express secret');
      await expect(card).toContainText('Active');
      expect(page.url()).not.toContain('tts_');
      expect(page.url()).not.toContain('k=');
      expect(await page.content()).not.toContain(tokenOf(first));
      await checkA11y(page);

      await captured.done();
      const lookups = captured.requests.filter((r) => r.url.endsWith('/secrets/lookup'));
      expect(lookups.length).toBeGreaterThanOrEqual(2);
      expect(expectKeyNowhere(captured.requests, first)).toBe(0);
      for (const r of captured.requests) {
        if (r.url.endsWith('/secrets/lookup')) continue;
        expect(r.url).not.toContain(tokenOf(first));
      }

      // The list marks anonymous express secrets.
      await page.reload();
      await expect(page.getByText('Anonymous (express secret)').first()).toBeVisible();

      // Emergency purge from the settings screen.
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenantId}/secret-settings`);
      await page.getByRole('button', { name: 'Delete all live anonymous express secrets' }).click();
      const dialog = page.getByRole('dialog', { name: 'Delete all live anonymous express secrets?' });
      await checkA11y(page);
      await dialog.getByRole('button', { name: 'Delete them all' }).click();
      await expect(page.getByText('2 anonymous express secrets deleted.').first()).toBeVisible();
      await expect(dialog).toBeHidden();

      for (const link of [first, second]) {
        const reader = await (await newContext({ clientIp: externalIp() })).newPage();
        await reader.goto(link);
        await expectGone(reader, 'This secret has been deleted by its sender or by an administrator.');
      }
      const after = await delegateApi().ok<{ state: string }>(
        'POST',
        `/admin/tenants/${tenantId}/secrets/lookup`,
        {
          link: first,
        },
      );
      expect(after.state).toBe('deleted');
    });
  });

  test.describe('super admin', () => {
    test.use({ storageState: STORAGE_SUPER });

    test('the system status box of the home shows the express secrets row', async ({ page }) => {
      await page.goto(`${ORIGINS.admin}/admin/`);
      await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
      const status = page.locator('dl.tt-home__status');
      const row = status.locator('div', { has: page.getByText('Express secrets', { exact: true }) });
      await expect(row).toHaveCount(1);
      // The e2e server does not set TT_EXPRESS_SECRETS_DISABLED.
      await expect(row.getByText('Set per entity')).toBeVisible();
      await expect(row.getByText('Closed for the instance')).toHaveCount(0);
      await checkA11y(page);
    });

    test('the token opt-in is created, listed and honoured by the API', async ({ page, state }) => {
      const name = `e2e express token ${Math.random().toString(16).slice(2, 10)}`;
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/tokens/new`);
      await expect(page.getByRole('heading', { name: 'New API token', level: 1 })).toBeVisible();
      await page.getByLabel(/^Name/).fill(name);
      await page.getByLabel(/^Allowed IP ranges/).fill('127.0.0.1/32');
      const optIn = page.getByLabel('Allowed to create express secrets');
      await expect(optIn).not.toBeChecked();
      await optIn.check();
      await checkA11y(page);
      await page.getByRole('button', { name: 'Create the token' }).click();
      const modal = page.getByRole('dialog', { name: `Token ${name} created` });
      const secret = (await modal.locator('code').innerText()).trim();
      await modal.getByRole('checkbox', { name: /I have stored this secret/ }).check();
      await modal.getByRole('button', { name: 'Close' }).click();
      await expect(modal).toBeHidden();

      const row = page.getByRole('row').filter({ hasText: name });
      await expect(row).toHaveCount(1);
      await expect(row.getByText('Allowed', { exact: true })).toBeVisible();

      // The switch of the entity is off: the opt-in token passes the switches (400 on an empty
      // body), the seeded token without opt-in does not.
      const url = '/api/v1/express-secrets';
      const allowed = await request<{ code: string }>(state.serverPort, 'POST', url, {
        host: HOSTS.a,
        body: {},
        headers: { Authorization: `Bearer ${secret}` },
      });
      expect(allowed.status).toBe(400);
      expect(allowed.json.code).toBe('validation-failed');
      const refused = await request<{ code: string }>(state.serverPort, 'POST', url, {
        host: HOSTS.a,
        body: {},
        headers: { Authorization: `Bearer ${state.apiTokenA}` },
      });
      expect(refused.status).toBe(403);
      expect(refused.json.code).toBe('express-token-not-allowed');

      // Revoke it: the opt-in dies with the token.
      await row.getByRole('button', { name: `Revoke ${name}` }).click();
      const revoke = page.getByRole('dialog', { name: `Revoke the token ${name}?` });
      await revoke.getByLabel(/^Text to type to confirm/).fill(name);
      await revoke.getByRole('button', { name: 'Revoke the token' }).click();
      await expect(revoke).toBeHidden();
      await expect(row.getByText('Revoked')).toBeVisible();
    });
  });

  test('an auditor can look a secret up but cannot purge nor change the settings', async ({
    page,
    state,
    newContext,
  }) => {
    const tenantId = state.tenants.a.id;
    await setExpress(superAdminApi(), tenantId, { expressEnabled: true });
    const author = await (await newContext()).newPage();
    const link = await createExpress(author, state.tenants.a.origin, expressText().text);
    const { username, password } = await createAuditor(superAdminApi(), state, tenantId);

    await page.goto(`${ORIGINS.admin}/admin/login`);
    await page.getByLabel(/^Username/).fill(username);
    await page.getByLabel(/^Password/).fill(password);
    await page.getByRole('button', { name: msg('en', 'adminAuth.login.submit'), exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();

    await page.goto(`${ORIGINS.admin}/admin/tenants/${tenantId}/secrets`);
    await page.getByLabel(/^Secret link/).fill(link);
    await page.getByRole('button', { name: 'Find the secret' }).click();
    const found = page.getByRole('heading', { name: 'Secret found', level: 2 });
    await expect(found).toBeVisible();
    const card = page.locator('section', { has: found });
    await expect(card.getByRole('button', { name: /^Delete/ })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Secrets settings' })).toHaveCount(0);
    await checkA11y(page);

    // The report detail never offers the deletion of a secret to the auditor.
    await page.goto(`${ORIGINS.admin}/admin/tenants/${tenantId}/abuse-reports?status=open`);
    await page.waitForLoadState('networkidle');
    await expect(page.getByRole('button', { name: 'Delete this secret' })).toHaveCount(0);

    // The API refuses the write operations to the auditor.
    const api = new AdminApi(state.serverPort);
    await api.login(username, password);
    const lookup = await api.call('POST', `/admin/tenants/${tenantId}/secrets/lookup`, { link });
    expect(lookup.status).toBe(200);
    const purge = await api.call('POST', `/admin/tenants/${tenantId}/express-secrets/purge`);
    expect(purge.status).toBe(403);
    const settings = await api.call('GET', `/admin/tenants/${tenantId}/secret-settings`);
    expect(settings.status).toBe(403);

    // Nothing was consumed nor purged.
    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(link);
    await expectReady(reader);
  });
});
