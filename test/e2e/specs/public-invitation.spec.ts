// Public scenario 3 (CLAUDE.md section 9): an internal user invites an external address from the
// public invite page; the external person receives the invitation mail, opens the link from
// outside the internal network, identifies by code and deposits. The transfer is addressed to the
// inviter, who receives the notification with the link and the fingerprints.
import { externalIp } from '../support/clientip';
import { externalEmail, internalEmail, makeFile } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { deposit, enterCode, identify, mailLink } from '../support/publicflow';
import { escapeRegExp } from '../support/regexp';

test.describe('public: external invitation', () => {
  test('an invited external person deposits files addressed to the inviter', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    const inviter = internalEmail('inviter');
    const guest = externalEmail('guest', 'example.net');
    const note = 'Please send me the signed documents.';
    const file = makeFile('signed-documents.bin', 96 * 1024);

    // Without a deposit session, the invite page explains how to get one.
    await page.goto(`${tenant.origin}/invite`);
    await expect(page.getByRole('heading', { name: 'Identify yourself first', level: 1 })).toBeVisible();
    await checkA11y(page);

    // The internal user identifies, then follows the invite link of the deposit form.
    await identify(page, tenant.origin, inviter);
    await page.getByRole('link', { name: 'Invite someone to send you files' }).click();
    await expect(page.getByRole('heading', { name: 'Invite an external person', level: 1 })).toBeVisible();
    await expect(page.getByText(`they will be addressed to ${inviter}`)).toBeVisible();
    await checkA11y(page);
    await page.getByLabel(/^Email address of the person to invite/).fill(guest);
    await page.getByLabel(/^Message/).fill(note);
    await page.getByRole('button', { name: 'Send the invitation' }).click();
    await expect(page.getByRole('heading', { name: 'Invitation sent', level: 1 })).toBeVisible();
    await expect(page.getByText(`An invitation was sent to ${guest}.`)).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);

    // The invitation mail names the inviter and carries the link.
    const invitation = await waitForMail(guest, { subject: /invites you to send files/ });
    expect(invitation.Subject).toBe(`${inviter} invites you to send files to ${tenant.name}`);
    expect(invitation.Text).toContain(note);
    const link = mailLink(invitation, '/i/', tenant.origin);

    // The guest opens it from outside the internal network.
    const gpage = await (await newContext({ clientIp: externalIp() })).newPage();
    await gpage.goto(link);
    await expect(
      gpage.getByRole('heading', { name: 'You are invited to send files', level: 1 }),
    ).toBeVisible();
    await expect(gpage.getByText(note)).toBeVisible();
    await expect(gpage.getByRole('definition').filter({ hasText: guest })).toBeVisible();
    await checkA11y(gpage);

    // "Continue" sends the code to the invited address at once.
    const after = Date.now() - 2000;
    await gpage.getByRole('button', { name: 'Continue' }).click();
    await expect(gpage.getByRole('heading', { name: 'Enter the verification code', level: 1 })).toBeVisible();
    await expect(gpage.getByText(`A 6-digit code has been sent to ${guest}.`)).toBeVisible();
    await checkA11y(gpage);
    await enterCode(gpage, guest, after);

    // The external form has no recipient field: the files go to the inviter.
    await expect(gpage.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
    await expect(gpage.getByText(`The files will be sent to ${inviter}, who invited you.`)).toBeVisible();
    await expect(gpage.getByLabel(/^Recipients/)).toHaveCount(0);
    // An external depositor cannot invite anyone.
    await expect(gpage.getByRole('link', { name: 'Invite someone to send you files' })).toHaveCount(0);
    await checkA11y(gpage);
    await deposit(gpage, { files: [file] });
    await expect(gpage.getByRole('main').getByText(inviter, { exact: true })).toBeVisible();
    await checkA11y(gpage);
    await expectCleanStorage(gpage);

    // The inviter is notified of the guest's transfer, with the link and the fingerprint.
    const notification = await waitForMail(inviter, {
      subject: new RegExp(`^${escapeRegExp(guest)} sent you files via`),
    });
    expect(notification.Text).toContain(file.sha256);
    const download = mailLink(notification, '/d/', tenant.origin);
    await page.goto(download);
    await expect(page.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(page.getByText(guest, { exact: true })).toBeVisible();
    await expect(page.getByText(file.sha256)).toBeVisible();
  });
});
