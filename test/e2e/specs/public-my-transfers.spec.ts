// "My transfers" of V1.1 step 7 (CLAUDE.md section 8.7): a sender without an account asks for an
// access link by mail, opens it (the token travels in the URL fragment, removed at once), sees
// their transfers in progress, extends one and deletes another. The link works once: reusing it
// gets "expired or already used". An unknown address gets the same neutral confirmation and no
// mail.
import { externalEmail, internalEmail, makeFile } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { listMails, waitForMail } from '../support/mailpit';
import { fillTransfer, identify, mailLink, sendTransfer } from '../support/publicflow';

const NEUTRAL =
  'If this address has already been verified on this service, you will receive a link valid for 15 minutes.';

test.describe('public: my transfers', () => {
  test('request a link, list, extend, delete, reuse of the link', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(410, /\/me\/sessions$/);
    const origin = state.tenants.a.origin;
    const sender = internalEmail('mt-sender');
    // The helpers draw a new address on every call: each one is drawn once.
    const keepTo = externalEmail('mt-keep');
    const dropTo = externalEmail('mt-drop');
    const keep = makeFile('keep-me.bin', 4 * 1024);
    const drop = makeFile('drop-me.bin', 4 * 1024);

    // Two transfers of the same sender (the first identification verifies the address).
    await identify(page, origin, sender);
    await fillTransfer(page, { recipients: [keepTo], files: [keep] });
    await sendTransfer(page);
    await page.goto(origin);
    await fillTransfer(page, { recipients: [dropTo], files: [drop] });
    await sendTransfer(page);

    // Link request from a fresh browser.
    const mine = await (await newContext()).newPage();
    await mine.goto(`${origin}/me`);
    await expect(mine.getByRole('heading', { name: 'My transfers', level: 1 })).toBeVisible();
    await checkA11y(mine);
    const after = Date.now();
    await mine.getByLabel(/^Your email address/).fill(sender);
    await mine.getByRole('button', { name: 'Send me a link' }).click();
    await expect(mine.getByText(NEUTRAL)).toBeVisible();
    await checkA11y(mine);

    const mail = await waitForMail(sender, { after });
    const link = mailLink(mail, '/me', origin);
    expect(new URL(link).hash).toMatch(/^#mta_/);

    // The link opens the list; the token is gone from the address bar.
    await mine.goto(link);
    await expect(mine.getByRole('table', { name: 'Transfers in progress' })).toBeVisible();
    expect(mine.url()).not.toContain('mta_');
    await expect(mine.getByRole('rowheader', { name: keepTo })).toBeVisible();
    await expect(mine.getByRole('rowheader', { name: dropTo })).toBeVisible();
    await checkA11y(mine);

    // Detail and extension.
    await mine.getByRole('button', { name: /^Details.*mt-keep/ }).click();
    await expect(mine.getByText(keep.name)).toBeVisible();
    await expect(mine.getByText(keep.sha256)).toBeVisible();
    await checkA11y(mine);
    await mine.getByLabel('30 days').check();
    await mine.getByRole('button', { name: 'Extend', exact: true }).click();
    await expect(mine.getByText(/The transfer is now available until/)).toBeVisible();
    await mine.getByRole('button', { name: 'Back to my transfers' }).click();

    // Deletion with confirmation.
    await mine.getByRole('button', { name: /^Details.*mt-drop/ }).click();
    await mine.getByRole('button', { name: 'Delete this transfer' }).click();
    const dialog = mine.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Delete permanently' }).click();
    await expect(mine.getByRole('table', { name: 'Transfers in progress' })).toBeVisible();
    await expect(mine.getByRole('rowheader', { name: dropTo })).toHaveCount(0);
    await expect(mine.getByRole('rowheader', { name: keepTo })).toBeVisible();

    // A link opened while a session is active asks before replacing it (login CSRF): staying
    // keeps the session, switching opens the link.
    const requestLink = async (): Promise<string> => {
      const requester = await (await newContext()).newPage();
      await requester.goto(`${origin}/me`);
      const since = Date.now();
      await requester.getByLabel(/^Your email address/).fill(sender);
      await requester.getByRole('button', { name: 'Send me a link' }).click();
      await expect(requester.getByText(NEUTRAL)).toBeVisible();
      return mailLink(await waitForMail(sender, { after: since }), '/me', origin);
    };
    const switchHeading = mine.getByRole('heading', { name: 'Open this link?', level: 1 });
    await mine.goto(await requestLink());
    await expect(switchHeading).toBeVisible();
    await expect(mine.getByText(/^You are signed in as .+\. Open the link and switch\?$/)).toBeVisible();
    expect(mine.url()).not.toContain('mta_');
    await checkA11y(mine);
    await mine.getByRole('button', { name: /^Stay signed in as / }).click();
    await expect(mine.getByRole('table', { name: 'Transfers in progress' })).toBeVisible();
    await mine.goto(await requestLink());
    await expect(switchHeading).toBeVisible();
    await mine.getByRole('button', { name: 'Open the link and switch' }).click();
    await expect(mine.getByRole('table', { name: 'Transfers in progress' })).toBeVisible();
    await expect(mine.getByRole('rowheader', { name: keepTo })).toBeVisible();

    // Reload keeps the session (cookie); signing out brings the form back.
    await mine.reload();
    await expect(mine.getByRole('table', { name: 'Transfers in progress' })).toBeVisible();
    await expectCleanStorage(mine);
    await mine.getByRole('button', { name: 'Sign out' }).click();
    await expect(mine.getByLabel(/^Your email address/)).toBeVisible();

    // The link is single use.
    const other = await (await newContext()).newPage();
    await other.goto(link);
    await expect(
      other.getByText('This link has expired or has already been used. Request a new one.'),
    ).toBeVisible();
    await expect(other.getByLabel(/^Your email address/)).toBeVisible();
    expect(other.url()).not.toContain('mta_');
  });

  test('an unknown address gets the same confirmation and no mail', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/me`);
    const unknown = internalEmail('mt-unknown');
    await page.getByLabel(/^Your email address/).fill(unknown);
    await page.getByRole('button', { name: 'Send me a link' }).click();
    await expect(page.getByText(NEUTRAL)).toBeVisible();
    expect(await listMails(unknown)).toHaveLength(0);
  });
});
