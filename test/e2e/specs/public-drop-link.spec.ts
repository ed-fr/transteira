// Permanent drop links and link-only transfers (CLAUDE.md sections 8.2 and 22, V2 step 6). An admin
// creates a drop link; a third party opens /drop/<token> from outside, identifies by code and
// deposits files that go to the recipients of the link, who are mailed. An internal sender ticks
// "Link only": nobody is mailed, the link is shown once on the last step and opens the download
// page. The tests share two options of entity A and run one after the other.
import { externalIp } from '../support/clientip';
import { externalEmail, internalEmail, makeFile, sha256 } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { listMails, waitForMail } from '../support/mailpit';
import {
  deposit,
  download,
  enterCode,
  fillTransfer,
  identify,
  mailLink,
  sendTransfer,
  submitEmail,
} from '../support/publicflow';
import { loadState, superAdminApi } from '../support/state';

test.describe.configure({ mode: 'serial' });

/** Allows or forbids the link-only transfers of entity A (super admin setting). */
async function setLinkOnly(tenantId: string, on: boolean): Promise<void> {
  await superAdminApi().ok('PATCH', `/admin/tenants/${tenantId}`, { linkOnlyAllowed: on });
}

test.describe('public: drop link', () => {
  test('a third party deposits through the drop link and the recipients are mailed', async ({
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(404, /\/drop-links\/[^/]+$/);
    const tenant = state.tenants.a;
    const service = internalEmail('drop-service');
    const guest = externalEmail('drop-supplier', 'example.net');
    const file = makeFile('supplier-invoice.bin', 64 * 1024);
    const created = await superAdminApi().ok<{ id: string; token: string }>(
      'POST',
      `/admin/tenants/${tenant.id}/drop-links`,
      { label: 'Supplier invoices', recipients: [service], validityDays: 7 },
    );

    const gpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await gpage.goto(`${tenant.origin}/drop/${created.token}`);
    await expect(gpage.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
    await expect(gpage.getByText('Supplier invoices').first()).toBeVisible();
    // The recipients of the link are never shown.
    await expect(gpage.getByText(service)).toHaveCount(0);
    await checkA11y(gpage);
    await gpage.getByRole('button', { name: 'Continue', exact: true }).click();

    // Identification by code, asked at every use.
    const after = Date.now() - 2000;
    await submitEmail(gpage, guest);
    await enterCode(gpage, guest, after);
    await expect(gpage.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
    await expect(gpage.getByRole('textbox', { name: /^Recipients/ })).toHaveCount(0);
    await checkA11y(gpage);
    await deposit(gpage, { files: [file] });
    await checkA11y(gpage);
    await expectCleanStorage(gpage);

    // The service is notified, with the link and the fingerprint.
    const notification = await waitForMail(service, {
      subject: new RegExp(`^${guest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} sent you files via`),
    });
    expect(notification.Text).toContain(file.sha256);
    const dpage = await (await newContext()).newPage();
    await dpage.goto(mailLink(notification, '/d/', tenant.origin));
    const got = await download(dpage, () =>
      dpage.getByRole('link', { name: `Download ${file.name}` }).click(),
    );
    expect(sha256(got.data)).toBe(file.sha256);

    // A revoked link shows the "not valid" page.
    await superAdminApi().ok(
      'DELETE',
      `/admin/tenants/${tenant.id}/drop-links/${created.id}`,
      undefined,
      [204],
    );
    await gpage.goto(`${tenant.origin}/drop/${created.token}`);
    await expect(gpage.getByRole('heading', { name: 'This drop link is not valid', level: 1 })).toBeVisible();
    await checkA11y(gpage);
  });
});

test.describe('public: link only', () => {
  test.afterAll(async () => {
    await setLinkOnly(loadState().tenants.a.id, false);
  });

  test('the link is shown once, nobody is mailed and the link downloads', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    await setLinkOnly(tenant.id, true);
    const sender = internalEmail('link-only-sender');
    const recipient = externalEmail('link-only-recipient', 'example.net');
    const file = makeFile('link-only.bin', 32 * 1024);

    await identify(page, tenant.origin, sender);
    await fillTransfer(page, { recipients: [recipient], files: [file] });
    await page.getByLabel(/^Link only/).check();
    await checkA11y(page);
    await sendTransfer(page);

    // The link is on the last step, with a copy button.
    await expect(page.getByText('This link is shown only once: copy it now.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy the link' })).toBeVisible();
    const shown = (await page.locator('code.tt-done-link').textContent()) ?? '';
    const link = `${tenant.origin}${new URL(shown.trim()).pathname}`;
    expect(link).toContain('/d/dl_');
    await checkA11y(page);
    await expectCleanStorage(page);

    // The sender is told once the analysis is over, without link; the recipient gets nothing.
    const confirmation = await waitForMail(sender, { subject: /^Your files have been sent via/ });
    expect(confirmation.Text).not.toContain('/d/dl_');
    expect(await listMails(recipient)).toHaveLength(0);

    // The link opens the download page.
    const rpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    const got = await download(rpage, () =>
      rpage.getByRole('link', { name: `Download ${file.name}` }).click(),
    );
    expect(sha256(got.data)).toBe(file.sha256);
  });
});
