// Redesign of the public pages (CLAUDE.md section 13.2): header controls, recipient chips,
// segmented controls, switches, the security disclosure, the volume gauge, the download page
// (pills, file rows, copy of the fingerprint), reflow at 390 px and the 44 px click targets.
// Every state is also checked by axe in both themes (checkA11y runs the two themes).
import type { Page } from '@playwright/test';
import { createInvitation, openDepositSession, recipientPath, tokenDeposit } from '../support/deposit';
import { externalEmail, internalEmail, makeFile, textFile, type GeneratedFile } from '../support/data';
import { HOSTS } from '../support/env';
import { EXPRESS_DEFAULTS, openExpress, setExpress } from '../support/express';
import { checkA11y, checkTargetSize, expect, test } from '../support/fixtures';
import { msg } from '../support/i18n';
import { waitForMail } from '../support/mailpit';
import {
  addRecipients,
  fileItem,
  identify,
  mailLink,
  openSecurity,
  sendTransfer,
  setOption,
} from '../support/publicflow';
import { superAdminApi } from '../support/state';

const MOBILE = { width: 390, height: 844 };

/** True when the page has no horizontal scroll at its current width. */
async function expectNoHorizontalScroll(page: Page, width: number): Promise<void> {
  const scroll = await page.evaluate(() => document.scrollingElement?.scrollWidth ?? 0);
  expect(scroll, 'document.scrollingElement.scrollWidth').toBeLessThanOrEqual(width);
}

const recipientsField = (page: Page) => page.getByRole('textbox', { name: /^Recipients/ });
const chips = (page: Page) => page.getByRole('list', { name: 'Recipients added' }).getByRole('listitem');

/** Creates a transfer by API (entity A) and returns the recipient's download path. */
async function downloadPathOf(token: string, label: string, files: GeneratedFile[]): Promise<string> {
  const recipient = internalEmail(`${label}-recipient`);
  const transfer = await tokenDeposit(
    token,
    internalEmail(`${label}-sender`),
    { recipients: [recipient], files, message: 'Here is the file.' },
    { host: HOSTS.a },
  );
  return recipientPath(transfer, recipient);
}

test.describe('public header', () => {
  test('quick links, language, theme and help sit in the header; help also in the footer', async ({
    page,
    state,
  }) => {
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    const banner = page.getByRole('banner');
    const nav = banner.getByRole('navigation', { name: 'Quick links' });
    await expect(nav.getByRole('link', { name: 'My transfers' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'My transfers' })).not.toHaveAttribute('aria-current', /.+/);
    await expect(banner.getByRole('combobox', { name: 'Language' })).toBeVisible();
    await expect(banner.getByRole('button', { name: 'Dark theme' })).toBeVisible();
    await expect(banner.getByRole('link', { name: 'Help', exact: true })).toBeVisible();
    await expect(
      page.getByRole('contentinfo').getByRole('link', { name: 'Help', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('contentinfo').getByText('Powered by TransTeira')).toBeVisible();
    await checkA11y(page);
    await checkTargetSize(page);
  });

  test('the theme button and the language selector of the header work', async ({ page, state }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto(`${state.tenants.a.origin}/`);
    const banner = page.getByRole('banner');
    const theme = banner.getByRole('button', { name: 'Dark theme' });
    await theme.click();
    await expect(theme).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await checkA11y(page);

    await banner.getByRole('combobox', { name: 'Language' }).selectOption('fr');
    await expect(
      page.getByRole('heading', { name: msg('fr', 'deposit.email.title'), level: 1 }),
    ).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(banner.getByRole('link', { name: msg('fr', 'common.header.myTransfers') })).toBeVisible();
    await checkTargetSize(page);
  });

  test('"My transfers" is the current page on /me; the help link is hidden on /help', async ({
    page,
    state,
  }) => {
    const origin = state.tenants.a.origin;
    await page.goto(`${origin}/me`);
    const banner = page.getByRole('banner');
    await expect(page.getByRole('heading', { name: 'My transfers', level: 1 })).toBeVisible();
    await expect(banner.getByRole('link', { name: 'My transfers' })).toHaveAttribute('aria-current', 'page');
    await checkA11y(page);
    await checkTargetSize(page);

    await page.goto(`${origin}/help`);
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
    await expect(banner.getByRole('link', { name: 'Help', exact: true })).toHaveCount(0);
    await expect(banner.getByRole('combobox', { name: 'Language' })).toBeVisible();
  });

  test.describe('express secret link', () => {
    test.describe.configure({ mode: 'serial' });

    test('the header link of /x is the current page', async ({ page, state }) => {
      // Entity B: the express secret spec works on entity A, whose switch is shared state.
      const tenantId = state.tenants.b.id;
      await setExpress(superAdminApi(), tenantId, { expressEnabled: true });
      try {
        await page.goto(`${state.tenants.b.origin}/`);
        const link = page.getByRole('banner').getByRole('link', { name: 'Express secret' });
        await expect(link).toBeVisible();
        await expect(link).not.toHaveAttribute('aria-current', /.+/);

        await openExpress(page, state.tenants.b.origin);
        await expect(link).toHaveAttribute('aria-current', 'page');
        await expect(
          page.getByRole('banner').getByRole('link', { name: 'My transfers' }),
        ).not.toHaveAttribute('aria-current', /.+/);
        await checkA11y(page);
        await checkTargetSize(page);

        await page.setViewportSize(MOBILE);
        await expectNoHorizontalScroll(page, MOBILE.width);
        await checkTargetSize(page);
        await checkA11y(page);
      } finally {
        await setExpress(superAdminApi(), tenantId, EXPRESS_DEFAULTS);
      }
    });
  });
});

test.describe('deposit form', () => {
  test('the email step and the invitation-free pages respect the 44 px targets', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    await checkTargetSize(page);
    await page.setViewportSize(MOBILE);
    await checkTargetSize(page);
    await expectNoHorizontalScroll(page, MOBILE.width);
  });

  test('recipients become chips: Enter, comma, paste, blur, removal, invalid and duplicate', async ({
    page,
    state,
  }) => {
    await identify(page, state.tenants.a.origin, internalEmail('chips-sender'));
    const field = recipientsField(page);

    await field.fill('first@example.org');
    await field.press('Enter');
    await expect(chips(page)).toHaveCount(1);
    await expect(chips(page).first()).toContainText('first@example.org');
    await expect(field).toHaveValue('');

    // A separator typed after an address commits it; the rest stays a draft.
    await field.fill('second@example.org,');
    await expect(chips(page)).toHaveCount(2);
    await expect(field).toHaveValue('');
    await field.fill('third@example.org; fourth');
    await expect(chips(page)).toHaveCount(3);
    await expect(field).toHaveValue('fourth');
    await field.fill('');

    // A pasted list becomes one chip per address (line breaks and commas both separate).
    await field.evaluate((el) => {
      const data = new DataTransfer();
      data.setData('text/plain', 'pasted-a@example.org\npasted-b@example.org, pasted-c@example.org');
      el.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true }));
    });
    await expect(chips(page)).toHaveCount(6);
    await expect(chips(page).filter({ hasText: 'pasted-c@example.org' })).toHaveCount(1);

    // Leaving the field commits the draft.
    await field.fill('blurred@example.org');
    await page.getByLabel(/^Message/).focus();
    await expect(chips(page)).toHaveCount(7);
    await expect(field).toHaveValue('');

    // A duplicate is ignored and announced in a visible notice.
    await field.fill('first@example.org');
    await field.press('Enter');
    await expect(chips(page)).toHaveCount(7);
    await expect(page.locator('.tt-recipients__notice')).toContainText('first@example.org');

    // An invalid address is kept as a chip marked "not accepted", with its reason in the error.
    await field.fill('not-an-address');
    await field.press('Enter');
    await expect(chips(page)).toHaveCount(8);
    await expect(chips(page).filter({ hasText: 'not-an-address' }).getByText('not accepted')).toBeAttached();
    await expect(field).toHaveAttribute('aria-invalid', 'true');
    await expect(page.locator('[id$="-error"]').filter({ hasText: 'not-an-address' })).toBeVisible();
    await checkA11y(page);
    await checkTargetSize(page);

    // The remove buttons delete a chip; the focus goes back to the field.
    await page.getByRole('button', { name: 'Remove not-an-address' }).click();
    await expect(chips(page)).toHaveCount(7);
    await expect(page.locator('[id$="-error"]').filter({ hasText: 'not-an-address' })).toHaveCount(0);
    await page.getByRole('button', { name: 'Remove blurred@example.org' }).click();
    await expect(chips(page)).toHaveCount(6);
    await expect(chips(page).filter({ hasText: 'blurred@example.org' })).toHaveCount(0);

    // Backspace in the empty field reaches the last chip, which Backspace then removes.
    await field.focus();
    await field.press('Backspace');
    await expect(page.getByRole('button', { name: 'Remove pasted-c@example.org' })).toBeFocused();
    await page.keyboard.press('Backspace');
    await expect(chips(page)).toHaveCount(5);
    await expect(field).toBeFocused();
  });

  test('committing the address left in the field does not move the page under the mouse', async ({
    page,
    state,
  }) => {
    await identify(page, state.tenants.a.origin, internalEmail('shift-sender'));
    const send = page.getByRole('button', { name: /^Send(\s|$)/ });
    await recipientsField(page).fill(internalEmail('shift-recipient'));
    const before = await send.boundingBox();
    // A click on the next control blurs the field first: the draft becomes a chip.
    await page.getByLabel(/^Message/).focus();
    await expect(chips(page)).toHaveCount(1);
    const after = await send.boundingBox();
    expect(after?.y, 'vertical position of the Send button after the draft became a chip').toBe(before?.y);
  });

  test('a real click on Security options right after typing an address works the first time', async ({
    page,
    state,
  }) => {
    await identify(page, state.tenants.a.origin, internalEmail('click-sender'));
    await recipientsField(page).fill(internalEmail('click-recipient'));
    const toggle = page.getByRole('button', { name: /^Security options/ });
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await expect(chips(page)).toHaveCount(1);
  });

  test('the submit commits the address left in the field', async ({ page, state }) => {
    const recipient = internalEmail('draft-recipient');
    await identify(page, state.tenants.a.origin, internalEmail('draft-sender'));
    await recipientsField(page).fill(recipient);
    await expect(chips(page)).toHaveCount(0);
    const file = makeFile('draft.bin', 2048);
    await page
      .getByLabel(/^Files to send/)
      .setInputFiles({ name: file.name, mimeType: file.mimeType, buffer: file.buffer });
    // A synthetic click: no blur happens before it, so the submit itself must commit the draft.
    await page.getByRole('button', { name: /^Send(\s|$)/ }).dispatchEvent('click');
    await expect(page.getByRole('heading', { name: 'Transfer sent', level: 1 })).toBeVisible({
      timeout: 30_000,
    });
    await waitForMail(recipient, { subject: /sent you files via/ });
  });

  test('the duration and the level are segmented controls driven by the arrow keys', async ({
    page,
    state,
  }) => {
    await identify(page, state.tenants.a.origin, internalEmail('segment-sender'));
    const expiry = page.getByRole('group', { name: /^Available for/ });
    await expect(expiry.getByRole('radio')).toHaveCount(3);
    const seven = page.getByRole('radio', { name: '7 days' });
    await expect(seven).toBeChecked();
    await seven.focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.getByRole('radio', { name: '30 days' })).toBeChecked();
    await page.keyboard.press('ArrowLeft');
    await page.keyboard.press('ArrowLeft');
    await expect(page.getByRole('radio', { name: '1 day', exact: true })).toBeChecked();
    await checkA11y(page);
    await checkTargetSize(page);

    // Level: arrows move the choice and the described option is the selected one only.
    const level = page.getByRole('group', { name: 'Confidentiality level' });
    const internal = level.getByRole('radio', { name: 'Internal' });
    await expect(internal).toBeChecked();
    await internal.focus();
    await page.keyboard.press('ArrowRight');
    const confidential = level.getByRole('radio', { name: 'Confidential' });
    await expect(confidential).toBeChecked();
    const visibleDescriptions = await level.getByRole('radio').evaluateAll((radios) =>
      radios
        .map((r) => (r.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean))
        .flat()
        .filter((id) => {
          const el = document.getElementById(id);
          return el !== null && !el.hidden && el.textContent?.trim();
        }),
    );
    expect(visibleDescriptions.length).toBeLessThanOrEqual(1);
    // The level restricts the durations (1 and 7 days): 30 days can no longer be chosen.
    await expect(page.getByRole('radio', { name: '30 days' })).toHaveCount(0);
    await checkA11y(page);
  });

  test('a switch is toggled with the Space key; the password field follows its switch', async ({
    page,
    state,
  }) => {
    await identify(page, state.tenants.a.origin, internalEmail('switch-sender'));
    await openSecurity(page);
    const toggle = page.getByRole('switch', { name: 'Protect with a password' });
    await expect(toggle).not.toBeChecked();
    await expect(page.locator('#tt-deposit-password')).toHaveCount(0);
    await toggle.focus();
    await page.keyboard.press('Space');
    await expect(toggle).toBeChecked();
    await expect(page.locator('#tt-deposit-password')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Security options/ })).toContainText('1 active');
    await checkA11y(page);
    await checkTargetSize(page);
    await page.keyboard.press('Space');
    await expect(toggle).not.toBeChecked();
    await expect(page.locator('#tt-deposit-password')).toHaveCount(0);

    const limit = page.getByRole('switch', { name: 'Limit the number of downloads' });
    await setOption(page, 'Limit the number of downloads', true);
    await expect(page.locator('#tt-deposit-max-downloads')).toBeVisible();
    await expect(limit).toBeChecked();
  });

  test('the security block opens by itself when a level imposes an option', async ({ page, state }) => {
    await identify(page, state.tenants.a.origin, internalEmail('level-sender'));
    const trigger = page.getByRole('button', { name: /^Security options/ });
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    await page.getByRole('radio', { name: 'Confidential' }).check();
    await expect(trigger).toHaveAttribute('aria-expanded', 'true');
    const password = page.getByRole('switch', { name: 'Protect with a password' });
    await expect(password).toBeChecked();
    await expect(password).toBeDisabled();
    await expect(page.getByText('Required by the chosen confidentiality level.').first()).toBeVisible();
    await expect(
      page.getByRole('switch', { name: 'Recipients must verify their address by code' }),
    ).toBeChecked();
    await expect(trigger).toContainText('active');
    await checkA11y(page);
    await checkTargetSize(page);
  });

  test('the security block opens when the error summary points inside it', async ({ page, state }) => {
    await identify(page, state.tenants.a.origin, internalEmail('summary-sender'));
    await addRecipients(page, [internalEmail('summary-recipient')]);
    const file = makeFile('summary.bin', 1024);
    await page
      .getByLabel(/^Files to send/)
      .setInputFiles({ name: file.name, mimeType: file.mimeType, buffer: file.buffer });
    await setOption(page, 'Protect with a password', true);

    // Close the block with its button, then send with the empty password: the block reopens.
    const trigger = page.getByRole('button', { name: /^Security options/ });
    await trigger.click();
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    await page.getByRole('button', { name: /^Send(\s|$)/ }).click();
    await expect(trigger).toHaveAttribute('aria-expanded', 'true');
    const summaryLink = page.locator('ul.tt-deposit-summary a').first();
    await expect(summaryLink).toBeVisible();
    await expect(page.locator('#tt-deposit-password')).toHaveAttribute('aria-invalid', 'true');
    await checkA11y(page);

    await summaryLink.click();
    await expect(page.locator('#tt-deposit-password')).toBeFocused();
  });

  test('the volume gauge counts the files against the limit', async ({ page, state }) => {
    await identify(page, state.tenants.a.origin, internalEmail('gauge-sender'));
    const first = makeFile('gauge-one.bin', 300 * 1024);
    const second = makeFile('gauge-two.bin', 300 * 1024);
    await page
      .getByLabel(/^Files to send/)
      .setInputFiles([first, second].map((f) => ({ name: f.name, mimeType: f.mimeType, buffer: f.buffer })));
    const meter = page.getByRole('meter', { name: 'Volume of the transfer' });
    await expect(meter).toBeVisible();
    await expect(page.locator('span', { hasText: /^2 files · / })).toBeVisible();
    await expect(page.locator('span', { hasText: /% of the limit$/ })).toBeVisible();
    await expect(meter).toHaveAttribute('aria-valuetext', /\bof\b/);
    await expect(page.getByRole('button', { name: /^Send \d/ })).toBeVisible();
    await page.getByRole('button', { name: 'Remove gauge-two.bin' }).click();
    await expect(page.locator('span', { hasText: /^1 file · / })).toBeVisible();
    await checkA11y(page);
    await checkTargetSize(page);
  });

  test('the form reflows in one column at 390 px', async ({ page, state }) => {
    await identify(page, state.tenants.a.origin, internalEmail('mobile-sender'));
    await page.setViewportSize(MOBILE);
    await recipientsField(page).fill('mobile-a@example.org, mobile-b@example.org, mobile-c@example.org, ');
    const file = makeFile('mobile-with-a-rather-long-file-name-to-wrap.bin', 4096);
    await page
      .getByLabel(/^Files to send/)
      .setInputFiles({ name: file.name, mimeType: file.mimeType, buffer: file.buffer });
    await openSecurity(page);
    await expectNoHorizontalScroll(page, MOBILE.width);
    const panes = await page.locator('.tt-pcard__pane').evaluateAll((els) =>
      els.map((el) => {
        const r = el.getBoundingClientRect();
        return { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width) };
      }),
    );
    expect(panes.length).toBeGreaterThanOrEqual(2);
    for (const pane of panes) expect(pane.x).toBe(panes[0]!.x);
    for (let i = 1; i < panes.length; i++) expect(panes[i]!.y).toBeGreaterThan(panes[i - 1]!.y);
    await checkTargetSize(page);
    await checkA11y(page);
  });

  test('the done step respects the 44 px targets', async ({ page, state }) => {
    const recipient = internalEmail('done-recipient');
    await identify(page, state.tenants.a.origin, internalEmail('done-sender'));
    const file = makeFile('done.bin', 2048);
    await addRecipients(page, [recipient]);
    await page
      .getByLabel(/^Files to send/)
      .setInputFiles({ name: file.name, mimeType: file.mimeType, buffer: file.buffer });
    await checkTargetSize(page);
    await sendTransfer(page);
    await checkTargetSize(page);
    await checkA11y(page);
  });
});

test.describe('download page', () => {
  test('pills, file rows with badges, abbreviated fingerprint and copy', async ({ page, state, context }) => {
    const files = [textFile('minutes.txt', 'meeting minutes\n'), textFile('agenda.txt', 'agenda\n')];
    const path = await downloadPathOf(state.apiTokenA, 'redesign', files);
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: state.tenants.a.origin });
    await page.goto(`${state.tenants.a.origin}${path}`);
    await expect(page.getByRole('heading', { name: '2 files for you', level: 1 })).toBeVisible();

    const pills = page.getByRole('list', { name: 'About this transfer' });
    const time = pills.locator('time[datetime]').first();
    await expect(time).toContainText(/^Expires /);
    const iso = (await time.getAttribute('datetime')) ?? '';
    expect(Number.isNaN(Date.parse(iso)), `datetime ${iso}`).toBe(false);
    await expect(time).toHaveAttribute('title', /.+/);
    await expect(pills.getByText(/in total$/)).toBeVisible();
    await expect(pills.getByText('Confidentiality:')).toBeAttached();

    const list = page.getByRole('list', { name: 'Files of this transfer' });
    await expect(list.getByRole('listitem')).toHaveCount(2);
    for (const f of files) {
      const row = fileItem(page, f.name);
      await expect(row.getByText('Scanned', { exact: true })).toBeVisible();
      await expect(row.getByText(f.sha256)).toBeAttached();
      await expect(row.getByText(`${f.sha256.slice(0, 8)}…${f.sha256.slice(-8)}`)).toBeVisible();
      await expect(row.getByRole('link', { name: `Download ${f.name}` })).toBeVisible();
    }

    // Copy puts the full fingerprint on the clipboard and announces it.
    const first = files[0]!;
    await page.getByRole('button', { name: `Copy the SHA-256 fingerprint of ${first.name}` }).click();
    await expect(page.getByText('Copied to the clipboard')).toBeAttached();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(first.sha256);

    await expect(page.getByRole('link', { name: 'Download all files (ZIP)' })).toBeVisible();
    await checkA11y(page);
    await checkTargetSize(page);
  });

  test('the download page reflows at 390 px', async ({ page, state }) => {
    const path = await downloadPathOf(state.apiTokenA, 'mobile-dl', [
      textFile('a-very-long-file-name-that-has-to-wrap-on-a-phone-screen-without-scrolling.txt', 'one\n'),
      textFile('second.txt', 'two\n'),
    ]);
    await page.setViewportSize(MOBILE);
    await page.goto(`${state.tenants.a.origin}${path}`);
    await expect(page.getByRole('heading', { name: '2 files for you', level: 1 })).toBeVisible();
    await expectNoHorizontalScroll(page, MOBILE.width);
    await checkTargetSize(page);
    await checkA11y(page);
  });
});

test.describe('other public pages', () => {
  test('the invitation landing respects the targets and reflows at 390 px', async ({ page, state }) => {
    const guest = externalEmail('redesign-guest');
    const session = await openDepositSession(internalEmail('redesign-inviter'));
    await createInvitation(session, guest);
    const mail = await waitForMail(guest, { subject: /invites you to send files/ });
    await page.goto(mailLink(mail, '/i/', state.tenants.a.origin));
    await expect(
      page.getByRole('heading', { name: 'You are invited to send files', level: 1 }),
    ).toBeVisible();
    await checkTargetSize(page);
    await checkA11y(page);
    await page.setViewportSize(MOBILE);
    await expectNoHorizontalScroll(page, MOBILE.width);
    await checkTargetSize(page);
  });

  test('/me and its mail-link entry respect the targets and reflow at 390 px', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/me`);
    await expect(page.getByRole('heading', { name: 'My transfers', level: 1 })).toBeVisible();
    await checkTargetSize(page);
    await page.setViewportSize(MOBILE);
    await expectNoHorizontalScroll(page, MOBILE.width);
    await checkTargetSize(page);
  });
});
