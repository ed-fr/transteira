// One-time secrets, public side (CLAUDE.md section 22.1): creation from the "Share a secret" tab
// of the deposit form, reveal on /s/<token>#k=<key> (the key never reaches the server and is
// removed from the address bar), passphrase, attached file, delivery by e-mail with read
// receipt, link-following bots that consume nothing, invited externals, "My secrets".
import crypto from 'node:crypto';
import { externalIp } from '../support/clientip';
import { externalEmail, internalEmail, makeFile } from '../support/data';
import { createInvitation, openDepositSession } from '../support/deposit';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { enterCode, identify, mailLink } from '../support/publicflow';
import {
  captureRequests,
  createSecret,
  expectGone,
  expectKeyNowhere,
  expectReady,
  expectRevealed,
  fillSecret,
  openSecretTab,
  pressShow,
  submitSecret,
} from '../support/secret';

const REVEAL_API = /\/api\/v1\/secret-links\/[^/]+(\/reveal)?$/;

function secretText(): string {
  return `s3cret-${crypto.randomBytes(6).toString('hex')} é中`;
}

test.describe('public: one-time secrets', () => {
  test('link delivery: create, reveal once, second reveal is refused', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(410, REVEAL_API);
    const origin = state.tenants.a.origin;
    const text = secretText();
    await identify(page, origin, internalEmail('sec-link'));

    // The tabs: files by default, then the secret form.
    await expect(page.getByRole('tab', { name: 'Send files' })).toHaveAttribute('aria-selected', 'true');
    await openSecretTab(page);
    await expect(page.getByRole('tab', { name: 'Share a secret' })).toHaveAttribute('aria-selected', 'true');
    await checkA11y(page);
    await fillSecret(page, { text });
    await submitSecret(page);
    const link = (await page.getByTestId('secret-done-link').textContent())!;
    expect(link).toContain(`${origin}/s/tts_`);
    expect(new URL(link).hash).toMatch(/^#k=/);
    await expect(page.getByText('This link is shown only once.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy the link' })).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page, { allowSession: ['tt.upload'] });

    // A fresh browser (no session) reveals it: the key leaves the address bar.
    const reader = await (await newContext()).newPage();
    await reader.goto(link);
    await expectReady(reader);
    expect(reader.url()).not.toContain('#k=');
    expect(reader.url()).not.toContain('k=');
    await checkA11y(reader);
    await pressShow(reader);
    await expectRevealed(reader, text);
    await expect(reader.getByText('has been destroyed on the server')).toBeVisible();
    await checkA11y(reader);
    await expectCleanStorage(reader);

    // The second reveal, from another browser with the full link, is refused.
    const second = await (await newContext()).newPage();
    await second.goto(link);
    await expectGone(second, 'This secret has already been read.');
    await checkA11y(second);
  });

  test('a link without its key shows the incomplete link page and consumes nothing', async ({
    page,
    state,
    newContext,
  }) => {
    const origin = state.tenants.a.origin;
    const text = secretText();
    await identify(page, origin, internalEmail('sec-nokey'));
    const link = (await createSecret(page, { text }))!;

    const reader = await (await newContext()).newPage();
    await reader.goto(link.split('#')[0]!);
    await expect(reader.getByRole('heading', { name: 'Incomplete link', level: 1 })).toBeVisible();
    await checkA11y(reader);

    // The keyless visit consumed nothing: the whole link still works (fresh page: a navigation
    // that only changes the fragment would not reload the screen).
    const again = await (await newContext()).newPage();
    await again.goto(link);
    await expectReady(again);
    await pressShow(again);
    await expectRevealed(again, text);
  });

  test('wrong passphrase shows the attempts left, the right one reveals', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(403, REVEAL_API);
    const origin = state.tenants.a.origin;
    const text = secretText();
    const passphrase = `pass-${crypto.randomBytes(4).toString('hex')}`;
    await identify(page, origin, internalEmail('sec-pass'));
    const link = (await createSecret(page, { text, passphrase }))!;

    const reader = await (await newContext()).newPage();
    await reader.goto(link);
    await expectReady(reader);
    await expect(reader.getByLabel(/^Passphrase/)).toBeVisible();
    await checkA11y(reader);

    await pressShow(reader, 'not-the-passphrase');
    await expect(reader.getByText(/Wrong passphrase\. .*attempt/)).toBeVisible();
    await expect(reader.getByRole('button', { name: 'Show the secret' })).toBeVisible();
    await checkA11y(reader);

    // Empty passphrase is refused locally, nothing consumed.
    await reader.getByRole('button', { name: 'Show the secret' }).click();
    await expect(reader.getByText('Enter the passphrase.')).toBeVisible();

    await pressShow(reader, passphrase);
    await expectRevealed(reader, text);
  });

  test('attached file: reveal, download, SHA-256 equals the original', async ({
    page,
    state,
    newContext,
  }) => {
    const origin = state.tenants.a.origin;
    const file = makeFile('secret-key.bin', 48 * 1024);
    await identify(page, origin, internalEmail('sec-file'));
    await openSecretTab(page);
    await fillSecret(page, { text: 'see the attached file', file });
    await checkA11y(page);
    await submitSecret(page);
    await expect(page.getByText('it has not been scanned by the antivirus')).toBeVisible();
    const link = (await page.getByTestId('secret-done-link').textContent())!;

    const reader = await (await newContext()).newPage();
    await reader.goto(link);
    await expectReady(reader);
    await expect(reader.getByText(/Attached file/).first()).toBeVisible();
    await pressShow(reader);
    await expectRevealed(reader, 'see the attached file');
    const info = reader.getByRole('region', { name: 'Attached file' });
    await expect(info.getByText(file.name)).toBeVisible();
    await expect(info.getByText(file.sha256)).toBeVisible();
    await checkA11y(reader);

    const [dl] = await Promise.all([
      reader.waitForEvent('download'),
      reader.getByRole('button', { name: 'Download the file' }).click(),
    ]);
    expect(dl.suggestedFilename()).toBe(file.name);
    expect(await dl.failure()).toBeNull();
    const { readFileSync } = await import('node:fs');
    const data = readFileSync(await dl.path());
    expect(crypto.createHash('sha256').update(data).digest('hex')).toBe(file.sha256);
    await expect(reader.getByText(/has been downloaded and checked/)).toBeVisible();
  });

  test('e-mail delivery: the mail carries a working link, the read receipt reaches the creator', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(410, REVEAL_API);
    const origin = state.tenants.a.origin;
    const creator = internalEmail('sec-mail');
    const recipient = externalEmail('sec-mail-to');
    const text = secretText();
    await identify(page, origin, creator);
    const since = Date.now() - 2000;
    await openSecretTab(page);
    await fillSecret(page, { text, recipient, readReceipt: true });
    await expect(page.getByText(/The email contains the full link/)).toBeVisible();
    await checkA11y(page);
    await submitSecret(page);
    await expect(page.getByText(`The link has been sent by email to ${recipient}.`)).toBeVisible();
    await expect(page.getByTestId('secret-done-link')).toHaveCount(0);
    await checkA11y(page);

    const mail = await waitForMail(recipient, { subject: /secret was shared/, after: since });
    expect(mail.Text).toContain(creator);
    expect(mail.Text).not.toContain(text);
    const link = mailLink(mail, '/s/', origin);
    expect(new URL(link).hash).toMatch(/^#k=/);

    const reader = await (await newContext({ clientIp: externalIp() })).newPage();
    await reader.goto(link);
    await expectReady(reader);
    await pressShow(reader);
    await expectRevealed(reader, text);

    const receipt = await waitForMail(creator, { subject: /Your secret was read/, after: since });
    expect(receipt.Text).not.toContain(text);
    expect(receipt.Text).toContain(recipient);

    const again = await (await newContext()).newPage();
    await again.goto(link);
    await expectGone(again, 'This secret has already been read.');
  });

  test('bots: plain GET requests of the page and of the status do not consume the secret', async ({
    page,
    state,
    newContext,
    request,
  }) => {
    const origin = state.tenants.a.origin;
    const text = secretText();
    await identify(page, origin, internalEmail('sec-bot'));
    const link = (await createSecret(page, { text }))!;
    const url = new URL(link);
    const token = url.pathname.split('/').pop()!;

    const html = await request.get(`${origin}/s/${token}`, { ignoreHTTPSErrors: true });
    expect(html.status()).toBe(200);
    expect(await html.text()).not.toContain(text);
    for (let i = 0; i < 2; i++) {
      const status = await request.get(`${origin}/api/v1/secret-links/${token}`, { ignoreHTTPSErrors: true });
      expect(status.status()).toBe(200);
      const body = await status.text();
      expect(body).not.toContain(text);
      expect(body).not.toContain('sealed');
    }

    const reader = await (await newContext()).newPage();
    await reader.goto(link);
    await expectReady(reader);
    await pressShow(reader);
    await expectRevealed(reader, text);
  });

  test('keyboard: arrows, Home and End move between the tabs', async ({ page, state }) => {
    await identify(page, state.tenants.a.origin, internalEmail('sec-keys'));
    const files = page.getByRole('tab', { name: 'Send files' });
    const secret = page.getByRole('tab', { name: 'Share a secret' });
    await files.focus();
    await page.keyboard.press('ArrowRight');
    await expect(secret).toBeFocused();
    await expect(secret).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'Share a secret', level: 1 })).toBeVisible();
    await page.keyboard.press('ArrowLeft');
    await expect(files).toBeFocused();
    await expect(files).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
    await page.keyboard.press('End');
    await expect(secret).toBeFocused();
    await page.keyboard.press('Home');
    await expect(files).toBeFocused();
    await checkA11y(page);
  });

  test('an invited external can only send the secret by e-mail to the inviter', async ({
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    const inviter = internalEmail('sec-inviter');
    const guest = externalEmail('sec-guest', 'example.net');
    const text = secretText();
    const session = await openDepositSession(inviter);
    await createInvitation(session, guest);
    const invitation = await waitForMail(guest, { subject: /invites you to send files/ });
    const link = mailLink(invitation, '/i/', tenant.origin);

    const gpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await gpage.goto(link);
    const after = Date.now() - 2000;
    await gpage.getByRole('button', { name: 'Continue' }).click();
    await enterCode(gpage, guest, after);
    await expect(gpage.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();

    await openSecretTab(gpage);
    await expect(
      gpage.getByText(`The link will be sent by email to ${inviter}, who invited you.`),
    ).toBeVisible();
    await expect(gpage.getByLabel('I copy the link myself')).toHaveCount(0);
    await expect(gpage.getByLabel(/^Recipient's email address/)).toHaveCount(0);
    await checkA11y(gpage);
    const sentAfter = Date.now() - 2000;
    await fillSecret(gpage, { text });
    await submitSecret(gpage);
    await expect(gpage.getByText(`The link has been sent by email to ${inviter}.`)).toBeVisible();

    const mail = await waitForMail(inviter, { subject: /secret was shared/, after: sentAfter });
    expect(mail.Text).toContain(guest);
    const reader = await (await newContext()).newPage();
    await reader.goto(mailLink(mail, '/s/', tenant.origin));
    await pressShow(reader);
    await expectRevealed(reader, text);
  });

  test('My secrets: the secret is listed without content and can be deleted before it is read', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(410, REVEAL_API);
    const origin = state.tenants.a.origin;
    const sender = internalEmail('sec-mine');
    const text = secretText();
    await identify(page, origin, sender);
    const link = (await createSecret(page, { text }))!;

    const mine = await (await newContext()).newPage();
    await mine.goto(`${origin}/me`);
    const since = Date.now() - 2000;
    await mine.getByLabel(/^Your email address/).fill(sender);
    await mine.getByRole('button', { name: 'Send me a link' }).click();
    const mail = await waitForMail(sender, { subject: /My transfers link/, after: since });
    await mine.goto(mailLink(mail, '/me', origin));

    await expect(mine.getByRole('heading', { name: 'My secrets', level: 2 })).toBeVisible();
    const table = mine.getByRole('table', { name: 'One-time secrets' });
    await expect(table).toBeVisible();
    await expect(table.getByRole('row').nth(1)).toContainText('Link to hand over');
    await expect(mine.getByText(text)).toHaveCount(0);
    await checkA11y(mine);

    await table
      .getByRole('button', { name: /^Delete.*the secret created on/ })
      .first()
      .click();
    const dialog = mine.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await checkA11y(mine);
    await dialog.getByRole('button', { name: 'Delete permanently' }).click();
    await expect(dialog).toBeHidden();
    await expect(mine.getByText('Secret deleted.').first()).toBeAttached();
    await expect(table.getByRole('button', { name: /^Delete.*the secret created on/ })).toHaveCount(0);
    // The focus moves to the heading of the section once the dialog is closed.
    await expect(mine.getByRole('heading', { name: 'My secrets', level: 2 })).toBeFocused();

    const reader = await (await newContext()).newPage();
    await reader.goto(link);
    await expectGone(reader, 'This secret has been deleted by its sender or by an administrator.');
  });

  // T-344: every request of the creator and of the reader is captured; the key of the link (text
  // or raw bytes) is in no URL, header or body, except the fragmentKey of the e-mail send.
  for (const scenario of [
    { name: 'link delivery with a file', email: false, withFile: true },
    { name: 'e-mail delivery', email: true, withFile: false },
    { name: 'e-mail delivery with a file', email: true, withFile: true },
  ]) {
    test(`the key of the link never leaves the browser: ${scenario.name}`, async ({
      page,
      state,
      newContext,
    }) => {
      const origin = state.tenants.a.origin;
      const creator = internalEmail('sec-net');
      const recipient = externalEmail('sec-net-to');
      const text = secretText();
      const file = scenario.withFile ? makeFile('net-key.bin', 16 * 1024) : undefined;
      const created = captureRequests(page.context());
      await identify(page, origin, creator);
      const since = Date.now() - 2000;
      const shown = await createSecret(page, {
        text,
        ...(file === undefined ? {} : { file }),
        ...(scenario.email ? { recipient, passphrase: 'correct horse battery staple' } : {}),
      });
      let link: string;
      if (scenario.email) {
        expect(shown).toBeUndefined();
        const mail = await waitForMail(recipient, { subject: /secret was shared/, after: since });
        link = mailLink(mail, '/s/', origin);
      } else {
        link = shown!;
      }

      const context = await newContext({ clientIp: externalIp() });
      const read = captureRequests(context);
      const reader = await context.newPage();
      await reader.goto(link);
      await expectReady(reader);
      await pressShow(reader, scenario.email ? 'correct horse battery staple' : undefined);
      await expectRevealed(reader, text);
      if (file !== undefined) {
        const [dl] = await Promise.all([
          reader.waitForEvent('download'),
          reader.getByRole('button', { name: 'Download the file' }).click(),
        ]);
        expect(await dl.failure()).toBeNull();
        await expect(reader.getByText(/has been downloaded and checked/)).toBeVisible();
      }

      await created.done();
      await read.done();
      // The capture saw the API calls of both sides.
      expect(created.requests.some((r) => r.method === 'POST' && r.url.endsWith('/api/v1/secrets'))).toBe(
        true,
      );
      expect(read.requests.some((r) => r.url.endsWith('/reveal'))).toBe(true);
      expect(expectKeyNowhere(created.requests, link)).toBe(scenario.email ? 1 : 0);
      expect(expectKeyNowhere(read.requests, link)).toBe(0);
    });
  }
});
