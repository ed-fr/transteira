// Reply to a transfer (CLAUDE.md section 10, V1.1 step 9): the recipient of a transfer sent by an
// internal user clicks "Reply" on the download page, proves their address by a code, and sends
// files back to the sender without any invitation. The sender is warned in the notification mail
// and on the download page that the transfer is a reply from outside. With the entity option off,
// the download page offers no reply. The tests share the option of entity A: they run one after
// the other and set it themselves.
import type { Page } from '@playwright/test';
import { externalIp } from '../support/clientip';
import { externalEmail, internalEmail, makeFile, sha256, type GeneratedFile } from '../support/data';
import { eicar } from '../support/eicar';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForCode, waitForMail } from '../support/mailpit';
import { deposit, download, fillTransfer, identify, mailLink, sendTransfer } from '../support/publicflow';
import { loadState, superAdminApi } from '../support/state';

test.describe.configure({ mode: 'serial' });

/** Turns the reply option of entity A on or off through the admin API. */
async function setReplyOption(tenantId: string, on: boolean): Promise<void> {
  await superAdminApi().ok('PATCH', `/admin/tenants/${tenantId}`, { allowTransferReply: on });
}

/** Sends a transfer from an internal sender to an external recipient; returns the recipient link. */
async function sendTo(
  page: Page,
  origin: string,
  sender: string,
  recipient: string,
  file: GeneratedFile,
): Promise<string> {
  await identify(page, origin, sender);
  await deposit(page, { recipients: [recipient], files: [file] });
  const mail = await waitForMail(recipient, { subject: /sent you files via/ });
  return mailLink(mail, '/d/', origin);
}

/** From the download page, starts the reply and confirms the code, up to the reply form. */
async function startReply(page: Page, recipient: string): Promise<void> {
  await page.getByRole('button', { name: 'Reply', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Confirm your address to reply', level: 1 })).toBeVisible();
  await checkA11y(page);
  const after = Date.now();
  await page.getByRole('button', { name: 'Send me a code' }).click();
  await expect(page.getByLabel(/^Verification code/)).toBeVisible();
  const code = await waitForCode(recipient, after);
  await page.getByLabel(/^Verification code/).fill(code);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
}

test.describe('public: reply to a transfer', () => {
  test.afterAll(async () => {
    await setReplyOption(loadState().tenants.a.id, false);
  });

  test('the recipient replies after a code and the sender is warned', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(401, /\/downloads\/[^/]+\/reply$/);
    const tenant = state.tenants.a;
    await setReplyOption(tenant.id, true);
    const sender = internalEmail('reply-sender');
    const recipient = externalEmail('reply-recipient');
    const original = makeFile('original-plan.bin', 8 * 1024);
    const answer = makeFile('signed-plan.bin', 24 * 1024);

    const link = await sendTo(page, tenant.origin, sender, recipient, original);
    await expectCleanStorage(page);

    // The recipient opens their link from outside and sees the reply button.
    const rpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(rpage.getByText(`Send files back to ${sender}.`)).toBeVisible();
    await checkA11y(rpage);
    await startReply(rpage, recipient);

    // The reply form has no recipient field: the files go to the sender.
    await expect(rpage.getByText(`Your reply goes to ${sender}.`)).toBeVisible();
    await expect(rpage.getByRole('textbox', { name: /^Recipients/ })).toHaveCount(0);
    await expect(rpage.getByRole('link', { name: 'Invite someone to send you files' })).toHaveCount(0);
    await checkA11y(rpage);
    await fillTransfer(rpage, { files: [answer] });
    await sendTransfer(rpage);
    await expect(rpage.getByRole('main').getByText(sender, { exact: true })).toBeVisible();
    await checkA11y(rpage);
    await expectCleanStorage(rpage);
    await rpage.getByRole('button', { name: 'Back to the download page' }).click();
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();

    // The sender receives the reply, flagged as coming from outside.
    const notification = await waitForMail(sender, { subject: /sent you files via/ });
    expect(notification.Text).toContain(recipient);
    expect(notification.Text).toContain('This is a reply to the transfer you sent on');
    expect(notification.Text).toContain(answer.sha256);

    // The download page of the reply warns the sender and offers no reply to a reply.
    const spage = await (await newContext()).newPage();
    await spage.goto(mailLink(notification, '/d/', tenant.origin));
    await expect(spage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(spage.getByText(`This transfer is a reply sent from outside ${tenant.name}`)).toBeVisible();
    await expect(spage.getByRole('button', { name: 'Reply', exact: true })).toHaveCount(0);
    await checkA11y(spage);
    const got = await download(spage, () =>
      spage.getByRole('link', { name: `Download ${answer.name}` }).click(),
    );
    expect(sha256(got.data)).toBe(answer.sha256);
  });

  test('an infected file in a reply is deleted and the reply refused', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(401, /\/downloads\/[^/]+\/reply$/);
    const tenant = state.tenants.a;
    await setReplyOption(tenant.id, true);
    const recipient = externalEmail('reply-av-recipient');
    const link = await sendTo(
      page,
      tenant.origin,
      internalEmail('reply-av-sender'),
      recipient,
      makeFile('request.bin', 4 * 1024),
    );
    const buffer = eicar();
    const infected: GeneratedFile = {
      name: 'macro.txt',
      mimeType: 'text/plain',
      buffer,
      sha256: sha256(buffer),
    };

    const rpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await startReply(rpage, recipient);
    await fillTransfer(rpage, { files: [infected] });
    await sendTransfer(rpage, 'refused');
  });

  test('without the entity option the download page offers no reply', async ({ page, state, newContext }) => {
    const tenant = state.tenants.a;
    await setReplyOption(tenant.id, false);
    const link = await sendTo(
      page,
      tenant.origin,
      internalEmail('reply-off-sender'),
      externalEmail('reply-off-recipient'),
      makeFile('no-reply.bin', 4 * 1024),
    );
    const rpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(rpage.getByRole('button', { name: 'Reply', exact: true })).toHaveCount(0);
    await checkA11y(rpage);
  });

  test('the reply screen without a reply session points back to the download page', async ({
    page,
    state,
  }) => {
    const tenant = state.tenants.a;
    await page.goto(`${tenant.origin}/d/dl_unknown/reply`);
    await expect(page.getByRole('heading', { name: 'Reply to a transfer', level: 1 })).toBeVisible();
    await expect(page.getByText(/Your reply session has expired or is no longer valid/)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Back to the download page' })).toBeVisible();
    await checkA11y(page);
  });
});
