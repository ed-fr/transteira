// Operations screens of an entity (plan step 19, scenario 8): transfers (filters in the URL,
// detail, resend, deletion), invitations, blocklist, API tokens (secret shown once, real deposit
// with the token, edit, revoke), audit log, statistics and personal data (GDPR search and
// erasure). The data each test needs is created through the public API (support/deposit.ts)
// with unique addresses, and every assertion is scoped to those addresses: tests run in parallel
// with the rest of the suite.
import type { Page } from '@playwright/test';
import { CLAMAV_MAX_SCAN_BYTES, ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { externalEmail, internalEmail, makeFile, textFile } from '../support/data';
import { createInvitation, openDepositSession, tokenCreateTransfer, tokenDeposit } from '../support/deposit';
import { listMails, waitForMail, waitForMails } from '../support/mailpit';
import { re } from '../support/regexp';
import { delegateApi } from '../support/state';
import crypto from 'node:crypto';

/** Admin URL of an operations screen of a tenant. */
function opsUrl(tenantId: string, screen: string): string {
  return `${ORIGINS.admin}/admin/tenants/${tenantId}/${screen}`;
}

/** Today in the browser's time zone (Europe/Paris, playwright.config.ts), as YYYY-MM-DD. */
function today(): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Paris',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date());
}

/** The row of a table that contains `text`. */
function rowWith(page: Page, text: string | RegExp) {
  return page.getByRole('row').filter({ hasText: text });
}

const NOTIFICATION = /sent you files/;

test.describe('transfers', () => {
  test.describe('delegated admin', () => {
    test.use({ storageState: STORAGE_DELEGATE });

    test('filters live in the URL, the detail renders, the notification is resent to one recipient', async ({
      page,
      state,
    }) => {
      const sender = internalEmail('ops-filter-sender');
      const kept = externalEmail('ops-resend-to');
      const other = externalEmail('ops-resend-not');
      const small = textFile('report.txt', 'quarterly figures\n');
      const large = makeFile('archive.bin', CLAMAV_MAX_SCAN_BYTES + 4096);
      const deposit = await tokenDeposit(state.apiTokenA, sender, {
        recipients: [kept, other],
        files: [small, large],
        message: 'Figures for review',
      });
      expect(deposit.status).toBe('available');
      // The first notification reached both recipients.
      await waitForMail(kept, { subject: NOTIFICATION });
      await waitForMail(other, { subject: NOTIFICATION });

      // Filters: status + the unique sender address; applied filters go to the query string.
      const listUrl = opsUrl(state.tenants.a.id, 'transfers');
      await page.goto(listUrl);
      await expect(page.getByRole('heading', { name: 'Transfers', level: 1 })).toBeVisible();
      const filters = page.getByRole('search', { name: 'Filter the transfers' });
      await filters.getByLabel(/^Status/).selectOption({ label: 'Available' });
      await filters.getByLabel(/^Email address/).fill(sender);
      await filters.getByRole('button', { name: 'Apply' }).click();
      await expect(page).toHaveURL(/[?&]status=available(&|$)/);
      expect(new URL(page.url()).searchParams.get('email')).toBe(sender);
      await expect(filters.getByText('1 transfer shown.')).toBeVisible();
      const row = rowWith(page, sender);
      await expect(row).toHaveCount(1);
      await expect(row.getByText('Available')).toBeVisible();
      await expect(row.getByText('API token')).toBeVisible();
      await checkA11y(page);

      // Detail (regression of step 17: the page used to fail to render).
      await row.getByRole('link', { name: re(`Details of the transfer from ${sender}`) }).click();
      await expect(page).toHaveURL(re(`/transfers/${deposit.id}`));
      await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
      const info = page.getByRole('region', { name: 'Information' });
      await expect(info.getByText(sender)).toBeVisible();
      // The origin (a dd); the token identifier follows under the term "API token".
      await expect(info.locator('dd', { hasText: /^API token$/ })).toBeVisible();
      const recipients = page.getByRole('region', { name: 'Recipients' });
      await expect(recipients.getByText(kept)).toBeVisible();
      await expect(recipients.getByText(other)).toBeVisible();
      const files = page.getByRole('region', { name: 'Files' });
      const smallRow = files.getByRole('row').filter({ hasText: small.name });
      await expect(smallRow.getByText(small.sha256)).toBeVisible();
      await expect(smallRow.getByText('Clean')).toBeVisible();
      await expect(smallRow.getByRole('button', { name: `Copy the SHA-256 of ${small.name}` })).toBeVisible();
      const largeRow = files.getByRole('row').filter({ hasText: large.name });
      await expect(largeRow.getByText(large.sha256)).toBeVisible();
      await expect(largeRow.getByText('Not scanned: too large')).toBeVisible();
      await expect(page.getByText('File contents and download links are never available')).toBeVisible();
      await checkA11y(page);

      // Back restores the filtered list and its form.
      await page.goBack();
      await expect(page).toHaveURL(/[?&]status=available(&|$)/);
      await expect(filters.getByLabel(/^Email address/)).toHaveValue(sender);
      await expect(filters.getByLabel(/^Status/)).toHaveValue('available');
      await expect(rowWith(page, sender)).toHaveCount(1);
      await page.goForward();
      await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();

      // Resend to one recipient only.
      const before = Date.now() - 1000;
      await page.getByRole('button', { name: 'Resend the notification' }).click();
      const dialog = page.getByRole('dialog', { name: 'Resend the notification' });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole('checkbox', { name: kept })).toBeChecked();
      await dialog.getByRole('checkbox', { name: other }).uncheck();
      await checkA11y(page);
      await dialog.getByRole('button', { name: 'Resend', exact: true }).click();
      await expect(dialog).toBeHidden();
      await expect(page.getByText('Notification queued for 1 recipient.').first()).toBeVisible();
      await waitForMail(kept, { subject: NOTIFICATION, after: before });
      // The unticked recipient got nothing more. To check an absence without a fixed wait, a
      // sentinel is awaited first: a second resend to the kept recipient only, queued after the
      // first one. The mails of one tenant are delivered one at a time, in the order they were
      // queued (per-tenant FIFO with one delivery in flight, internal/mail/queue.go), so once
      // the sentinel has arrived, any mail of the first resend to the other recipient would have
      // arrived too.
      await delegateApi().ok(
        'POST',
        `/admin/tenants/${state.tenants.a.id}/transfers/${deposit.id}/resend`,
        { recipients: [kept] },
        [202],
      );
      await expect
        .poll(async () => (await listMails(kept)).filter((m) => NOTIFICATION.test(m.Subject)).length)
        .toBe(3);
      expect((await listMails(other)).filter((m) => NOTIFICATION.test(m.Subject))).toHaveLength(1);
      await expectCleanStorage(page);
    });
  });

  test.describe('super admin', () => {
    test.use({ storageState: STORAGE_SUPER });

    test('deletion with a reason returns to the list and is recorded in the audit log', async ({
      page,
      state,
    }) => {
      const sender = internalEmail('ops-delete-sender');
      const deposit = await tokenDeposit(state.apiTokenA, sender, {
        recipients: [externalEmail('ops-delete-to')],
        files: [textFile('to-delete.txt', 'obsolete\n')],
      });

      await page.goto(opsUrl(state.tenants.a.id, `transfers/${deposit.id}`));
      await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
      await page.getByRole('button', { name: 'Delete the transfer' }).click();
      const dialog = page.getByRole('dialog', { name: 'Delete this transfer?' });
      await dialog.getByLabel(/^Reason/).fill('Sent by mistake');
      await checkA11y(page);
      await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
      await expect(page).toHaveURL(re(`/admin/tenants/${state.tenants.a.id}/transfers`));
      await expect(page.getByRole('heading', { name: 'Transfers', level: 1 })).toBeVisible();

      // Audit log filtered by action and day: the deletion of this transfer is listed.
      await page.goto(opsUrl(state.tenants.a.id, 'audit'));
      await expect(page.getByRole('heading', { name: 'Audit log', level: 1 })).toBeVisible();
      const filters = page.getByRole('search', { name: 'Filter the audit log' });
      await filters.getByLabel(/^Action/).selectOption({ label: 'Transfer deleted' });
      // Computed once: the filter and the URL check must use the same day.
      const day = today();
      await filters.getByLabel(/^From/).fill(day);
      await filters.getByLabel(/^To/).fill(day);
      await filters.getByRole('button', { name: 'Apply' }).click();
      await expect(page).toHaveURL(/[?&]action=transfer\.deleted(&|$)/);
      const params = new URL(page.url()).searchParams;
      expect(params.get('from')).toBe(day);
      expect(params.get('to')).toBe(day);
      const entry = rowWith(page, deposit.id);
      await expect(entry).toHaveCount(1);
      await expect(entry.getByText('Transfer deleted')).toBeVisible();
      await expect(entry.getByText(state.superAdmin.username)).toBeVisible();
      await checkA11y(page);
    });
  });
});

test.describe('invitations', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('an invitation is revoked', async ({ page, state }) => {
    const inviter = internalEmail('ops-inviter');
    const guest = externalEmail('ops-guest');
    const session = await openDepositSession(inviter);
    await createInvitation(session, guest, 'Please send the signed contract.');

    await page.goto(opsUrl(state.tenants.a.id, 'invitations'));
    await expect(page.getByRole('heading', { name: 'Invitations', level: 1 })).toBeVisible();
    const row = rowWith(page, guest);
    await expect(row).toHaveCount(1);
    await expect(row.getByText(inviter)).toBeVisible();
    await expect(row.getByText('Pending')).toBeVisible();
    await checkA11y(page);

    await row.getByRole('button', { name: `Revoke the invitation of ${guest}` }).click();
    const dialog = page.getByRole('dialog', { name: 'Revoke this invitation?' });
    await expect(dialog.getByText(guest)).toBeVisible();
    await dialog.getByRole('button', { name: 'Revoke the invitation' }).click();
    await expect(dialog).toBeHidden();
    await expect(row.getByText('Revoked')).toBeVisible();
    await expect(row.getByRole('button', { name: /Revoke/ })).toHaveCount(0);
  });
});

test.describe('blocklist', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('an entry is added, refused as a duplicate, then removed', async ({ page, state, guards }) => {
    const domain = `blocked-${crypto.randomBytes(4).toString('hex')}.example.net`;
    guards.allowHttpError(409, /\/api\/v1\/admin\/tenants\/[^/]+\/blocklist$/);

    await page.goto(opsUrl(state.tenants.a.id, 'blocklist'));
    await expect(page.getByRole('heading', { name: 'Blocklist', level: 1 })).toBeVisible();
    const form = page.getByRole('form', { name: 'Add an entry' });
    await form.getByLabel(/^Kind/).selectOption({ label: 'Domain' });
    await form.getByLabel(/^Value/).fill(domain);
    await form.getByLabel(/^Comment/).fill('Spam campaign');
    await form.getByRole('button', { name: 'Add' }).click();
    await expect(form.getByText(`${domain} has been added to the blocklist.`)).toBeVisible();
    const row = rowWith(page, domain);
    await expect(row).toHaveCount(1);
    await expect(row.getByText('Spam campaign')).toBeVisible();
    await checkA11y(page);

    // The same value again: 409, shown on the form.
    await form.getByLabel(/^Kind/).selectOption({ label: 'Domain' });
    await form.getByLabel(/^Value/).fill(domain);
    await form.getByRole('button', { name: 'Add' }).click();
    await expect(
      form.getByText('This value is already in the blocklist for this kind.').first(),
    ).toBeVisible();
    await expect(rowWith(page, domain)).toHaveCount(1);
    await checkA11y(page);

    await row.getByRole('button', { name: `Remove ${domain} from the blocklist` }).click();
    const dialog = page.getByRole('dialog', { name: 'Remove this entry?' });
    await dialog.getByRole('button', { name: 'Remove the entry' }).click();
    await expect(dialog).toBeHidden();
    await expect(rowWith(page, domain)).toHaveCount(0);
  });
});

test.describe('API tokens', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('a token is created, shown once, used for a deposit, edited and revoked', async ({
    page,
    context,
    state,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGINS.admin });
    const name = `e2e token ${crypto.randomBytes(4).toString('hex')}`;
    const sender = internalEmail('ops-token-sender');

    await page.goto(opsUrl(state.tenants.a.id, 'tokens/new'));
    await expect(page.getByRole('heading', { name: 'New API token', level: 1 })).toBeVisible();
    await page.getByLabel(/^Name/).fill(name);
    // The deposit below goes straight to the server from loopback (support/deposit.ts).
    await page.getByLabel(/^Allowed IP ranges/).fill('127.0.0.1/32');
    await page.getByLabel(/^Allowed senders/).fill(sender);
    await checkA11y(page);
    await page.getByRole('button', { name: 'Create the token' }).click();

    // The secret is shown once; Close stays disabled until the box is ticked or the copy worked.
    const modal = page.getByRole('dialog', { name: `Token ${name} created` });
    await expect(modal).toBeVisible();
    const secret = (await modal.locator('code').innerText()).trim();
    expect(secret).toMatch(/^tt_/);
    const close = modal.getByRole('button', { name: 'Close' });
    await expect(close).toBeDisabled();
    await checkA11y(page);
    const ack = modal.getByRole('checkbox', { name: /I have stored this secret/ });
    await ack.check();
    await expect(close).toBeEnabled();
    await ack.uncheck();
    await expect(close).toBeDisabled();
    await modal.getByRole('button', { name: 'Copy the secret' }).click();
    await expect(close).toBeEnabled();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret);
    await close.click();
    await expect(modal).toBeHidden();
    await expectCleanStorage(page);

    // A real tus deposit with the new token.
    const deposit = await tokenDeposit(secret, sender, {
      recipients: [externalEmail('ops-token-to')],
      files: [textFile('nightly.csv', 'a,b\n1,2\n')],
    });
    expect(deposit.status).toBe('available');

    // Closing the secret goes back to the list.
    await expect(page.getByRole('heading', { name: 'API tokens', level: 1 })).toBeVisible();
    // Edit the name.
    const renamed = `${name} v2`;
    await rowWith(page, name)
      .getByRole('button', { name: `Edit ${name}` })
      .click();
    const edit = page.getByRole('dialog', { name: `Edit the token ${name}` });
    await edit.getByLabel(/^Name/).fill(renamed);
    await checkA11y(page);
    await edit.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Token updated.').first()).toBeVisible();
    const row = rowWith(page, renamed);
    await expect(row).toHaveCount(1);
    await expect(row.getByText(sender)).toBeVisible();
    await expect(row.getByText('Active')).toBeVisible();

    // Revoke: the confirm button needs the exact name.
    await row.getByRole('button', { name: `Revoke ${renamed}` }).click();
    const revoke = page.getByRole('dialog', { name: `Revoke the token ${renamed}?` });
    const confirm = revoke.getByRole('button', { name: 'Revoke the token' });
    await expect(confirm).toBeDisabled();
    await revoke.getByLabel(/^Text to type to confirm/).fill(name);
    await expect(confirm).toBeDisabled();
    await revoke.getByLabel(/^Text to type to confirm/).fill(renamed);
    await expect(confirm).toBeEnabled();
    await checkA11y(page);
    await confirm.click();
    await expect(revoke).toBeHidden();
    await expect(row.getByText('Revoked')).toBeVisible();

    // The revoked token is refused.
    const refused = await tokenCreateTransfer(secret, sender, {
      recipients: [externalEmail('ops-token-refused')],
      files: [textFile('refused.csv', 'x\n')],
    });
    expect(refused.status).toBe(401);
  });
});

test.describe('statistics', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('periods switch and the data tables can be shown', async ({ page, state }) => {
    await page.goto(opsUrl(state.tenants.a.id, 'stats'));
    await expect(page.getByRole('heading', { name: 'Statistics', level: 1 })).toBeVisible();
    // Default period: 30 days.
    await expect(page.getByRole('radio', { name: 'Last 30 days' })).toBeChecked();
    await expect(page.getByText('Transfers per day').first()).toBeVisible();
    await expect(page.getByRole('meter', { name: 'Storage used (current)' })).toBeVisible();
    await expect(page.getByText('Transfers deposited')).toBeVisible();
    await checkA11y(page);

    // The period goes to the URL.
    await page.getByRole('radio', { name: 'Last 7 days' }).check();
    await expect(page).toHaveURL(/[?&]period=7d(&|$)/);
    await expect(page.getByText('Transfers per day').first()).toBeVisible();

    await page.getByRole('radio', { name: 'Last 12 months' }).check();
    await expect(page).toHaveURL(/[?&]period=12m(&|$)/);
    await expect(page.getByText('Transfers per month').first()).toBeVisible();
    await expect(page.getByText('Volume deposited per month').first()).toBeVisible();

    // Back restores the previous period.
    await page.goBack();
    await expect(page.getByRole('radio', { name: 'Last 7 days' })).toBeChecked();
    await page.goForward();
    await expect(page.getByRole('radio', { name: 'Last 12 months' })).toBeChecked();

    const toggle = page.getByRole('button', { name: 'Show the data table' }).first();
    await toggle.click();
    const hide = page.getByRole('button', { name: 'Hide the data table' });
    await expect(hide).toHaveCount(1);
    await expect(hide).toHaveAttribute('aria-expanded', 'true');
    await expect(page.getByRole('columnheader', { name: 'Month' })).toBeVisible();
    await checkA11y(page);
    await hide.click();
    await expect(page.getByRole('button', { name: 'Hide the data table' })).toHaveCount(0);
    await expect(page.getByRole('columnheader', { name: 'Month' })).toHaveCount(0);
  });
});

test.describe('personal data', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('an address is searched and erased after typing it exactly', async ({ page, state }) => {
    const subject = externalEmail('ops-gdpr');
    await tokenDeposit(state.apiTokenA, internalEmail('ops-gdpr-sender'), {
      recipients: [subject],
      files: [textFile('personal.txt', 'personal data\n')],
    });
    await waitForMails(subject, { subject: NOTIFICATION });

    await page.goto(opsUrl(state.tenants.a.id, 'privacy'));
    await expect(page.getByRole('heading', { name: 'Personal data', level: 1 })).toBeVisible();
    await page.getByLabel(/^Email address/).fill(subject);
    await page.getByRole('button', { name: 'Search' }).click();
    const summary = page.getByRole('region', { name: 'Data found in this entity' });
    await expect(summary).toBeVisible();
    await expect(summary.getByText(subject)).toBeVisible();
    // The address is never put in the page URL.
    expect(page.url()).not.toContain(encodeURIComponent(subject));
    expect(page.url()).not.toContain(subject);
    const received = summary.locator('div').filter({ hasText: /^Transfers received/ });
    await expect(received.getByRole('definition')).toHaveText('1');
    await checkA11y(page);

    await summary.getByRole('button', { name: 'Erase all data' }).click();
    const dialog = page.getByRole('dialog', { name: 'Erase all the data of this address' });
    const confirm = dialog.getByRole('button', { name: 'Erase the data' });
    await expect(confirm).toBeDisabled();
    await dialog.getByLabel(/^Text to type to confirm/).fill(subject.replace('@', '@x'));
    await expect(confirm).toBeDisabled();
    await dialog.getByLabel(/^Text to type to confirm/).fill(subject);
    await expect(confirm).toBeEnabled();
    await checkA11y(page);
    await confirm.click();

    const report = page.getByRole('region', { name: 'Erasure report' });
    await expect(report).toBeVisible();
    await expect(
      report.getByText('The data linked to the address has been erased from this entity.'),
    ).toBeVisible();
    // Its only recipient erased, the transfer is deleted.
    const deleted = report.locator('div').filter({ hasText: /^Transfers deleted/ });
    await expect(deleted.getByRole('definition')).toHaveText('1');
    await checkA11y(page);
    await expectCleanStorage(page);
  });
});
