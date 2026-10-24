// Public scenario 1 (CLAUDE.md section 24.2, the complete path): an internal user identifies by
// code, deposits three generated files of known content, the recipient gets the mail with the
// link and the SHA-256 fingerprints, downloads one file and the ZIP archive (both checked against
// the originals), and the sender gets the first download receipt once only.
import { externalEmail, internalEmail, makeFile, sha256, textFile } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { listMails, waitForMail } from '../support/mailpit';
import { deposit, download, identify, mailLink } from '../support/publicflow';
import { escapeRegExp, re } from '../support/regexp';
import { readStoredZip } from '../support/zip';

test.describe('public: deposit then download', () => {
  test('three files deposited, one file and the ZIP downloaded with matching SHA-256', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    const sender = internalEmail('sender');
    const recipient = internalEmail('recipient');
    // Three files of known content: several encryption chunks, a small binary, a text file.
    const files = [
      makeFile('report-2026.bin', 600 * 1024),
      makeFile('photo.raw', 40 * 1024),
      textFile('notes.txt', `Notes for ${recipient}\nline two\n`),
    ];
    const message = 'Here are the files we discussed.\nBest regards';

    // Identification by code, with an accessibility check of each step.
    await identify(page, tenant.origin, sender, async () => checkA11y(page));
    await expect(page.getByText(`Identified as ${sender}`)).toBeVisible();

    await deposit(page, { recipients: [recipient], message, files });
    await checkA11y(page);
    // The recap lists the recipient and every file with its SHA-256 (the link is never shown).
    await expect(page.getByRole('main').getByText(recipient, { exact: true })).toBeVisible();
    const recap = page.getByRole('list', { name: 'Files of the transfer' });
    for (const f of files) {
      await expect(recap.getByText(f.sha256)).toBeVisible();
    }
    await expect(recap.getByText('Antivirus: no threat found')).toHaveCount(files.length);
    await expect(page.getByRole('link', { name: /\/d\// })).toHaveCount(0);
    await expectCleanStorage(page);

    // The recipient's notification: link, every fingerprint, the QR code inline (no remote image).
    const notification = await waitForMail(recipient, {
      subject: new RegExp(`^${escapeRegExp(sender)} sent you files via`),
    });
    expect(notification.Subject).toBe(`${sender} sent you files via ${tenant.name}`);
    for (const f of files) expect(notification.Text).toContain(f.sha256);
    expect(notification.Text).toContain('Here are the files we discussed.');
    expect(notification.Inline.some((part) => part.ContentType.startsWith('image/'))).toBe(true);
    expect(notification.HTML).not.toMatch(/<img[^>]+src="https?:/i);
    const link = mailLink(notification, '/d/', tenant.origin);

    // The sender's confirmation.
    const confirmation = await waitForMail(sender, { subject: /^Your files have been sent via/ });
    expect(confirmation.Text).toContain(recipient);

    // The recipient opens the link in their own browser (another context, another IP).
    const rctx = await newContext();
    const rpage = await rctx.newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(rpage.getByText(sender, { exact: true })).toBeVisible();
    await expect(rpage.getByText('Here are the files we discussed.')).toBeVisible();
    await expect(rpage.getByText('3 files,')).toBeVisible();
    const table = rpage.getByRole('table', { name: 'Files of this transfer' });
    for (const f of files) {
      const row = table.getByRole('row', { name: re(f.name) });
      await expect(row.getByText(f.sha256)).toBeVisible();
    }
    // Every file was analysed: no "not analysed" warning.
    await expect(rpage.getByText(/could not be analysed by the antivirus/)).toHaveCount(0);
    await checkA11y(rpage);

    // One file alone: bytes identical to the original.
    const single = files[0]!;
    const one = await download(rpage, () =>
      rpage.getByRole('link', { name: `Download ${single.name}` }).click(),
    );
    expect(one.name).toBe(single.name);
    expect(one.data.length).toBe(single.buffer.length);
    expect(sha256(one.data)).toBe(single.sha256);

    // The whole transfer as a ZIP (store mode): every entry identical to its original.
    const zip = await download(rpage, () =>
      rpage.getByRole('link', { name: 'Download all files (ZIP)' }).click(),
    );
    expect(zip.name).toMatch(/\.zip$/);
    const entries = readStoredZip(zip.data);
    expect(entries.map((e) => e.name).sort()).toEqual(files.map((f) => f.name).sort());
    for (const f of files) {
      const entry = entries.find((e) => e.name === f.name)!;
      expect(sha256(entry.data), `SHA-256 of ${f.name} in the ZIP`).toBe(f.sha256);
    }

    // The first complete download sends the receipt to the sender.
    const receiptSubject = /^Your transfer has been downloaded via/;
    const receipt = await waitForMail(sender, { subject: receiptSubject });
    for (const f of files) expect(receipt.Text).toContain(f.name);

    // A second complete download sends nothing more. To check an absence without a fixed wait, a
    // later mail of the same tenant (an invitation sent by the sender after the second download)
    // is awaited first: the receipt would have been queued before it, at the end of the archive
    // response, while the invitation is only requested afterwards through several UI steps. This
    // relies on the mail queue delivering the mails of one tenant one at a time, in the order
    // they were queued (per-tenant FIFO with one delivery in flight: internal/mail/queue.go,
    // TenantConcurrency fixed to 1 in internal/app/app.go); if that changed, this check would
    // need another sentinel.
    await download(rpage, () => rpage.getByRole('link', { name: 'Download all files (ZIP)' }).click());
    await expectCleanStorage(rpage);
    await page.getByRole('link', { name: 'Invite someone to send you files' }).click();
    const invited = externalEmail('sentinel');
    await page.getByLabel(/^Email address of the person to invite/).fill(invited);
    await page.getByRole('button', { name: 'Send the invitation' }).click();
    await expect(page.getByRole('heading', { name: 'Invitation sent', level: 1 })).toBeVisible();
    await waitForMail(invited, { subject: /invites you to send files/ });
    const receipts = (await listMails(sender)).filter((m) => receiptSubject.test(m.Subject));
    expect(receipts).toHaveLength(1);
  });
});
