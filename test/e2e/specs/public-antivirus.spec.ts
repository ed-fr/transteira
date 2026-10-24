// Public scenario 4 (CLAUDE.md section 11): antivirus outcomes seen by the sender and the
// recipient. An infected file (the EICAR test signature, generated at runtime) is deleted and the
// sender alerted; a file above the scan limit (CLAMAV_MAX_SCAN_BYTES, 1 MiB in the e2e run) is
// delivered with a "not analysed (too large)" notice on the download page; a transfer whose only
// file is infected is refused.
import { internalEmail, makeFile, sha256, type GeneratedFile } from '../support/data';
import { eicar } from '../support/eicar';
import { CLAMAV_MAX_SCAN_BYTES } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { deposit, identify, mailLink } from '../support/publicflow';

/** A file holding the EICAR signature, never committed (CLAUDE.md test rules). */
function infectedFile(name: string): GeneratedFile {
  const buffer = eicar();
  return { name, mimeType: 'text/plain', buffer, sha256: sha256(buffer) };
}

test.describe('public: antivirus', () => {
  test('infected file deleted and reported, oversized file delivered as not analysed', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    const sender = internalEmail('av-sender');
    const recipient = internalEmail('av-recipient');
    const infected = infectedFile('invoice-scan.txt');
    const clean = makeFile('clean-sheet.bin', 16 * 1024);
    const large = makeFile('large-video.bin', CLAMAV_MAX_SCAN_BYTES + 256 * 1024);

    await identify(page, tenant.origin, sender);
    await deposit(page, { recipients: [recipient], files: [infected, clean, large] });

    // The sender's recap: the threat, the deleted file, the file not analysed.
    const recap = page.getByRole('list', { name: 'Files of the transfer' });
    const item = (name: string) => recap.getByRole('listitem').filter({ hasText: name });
    await expect(item(infected.name)).toContainText('Antivirus: threat detected, file deleted');
    await expect(item(infected.name)).toContainText('Threat detected: Eicar-Test-Signature');
    await expect(item(infected.name)).toContainText('it was deleted and will not be delivered');
    await expect(item(clean.name)).toContainText('Antivirus: no threat found');
    await expect(item(large.name)).toContainText('Antivirus: not analysed (file too large)');
    await expect(item(large.name)).toContainText('the recipients are told so');
    await checkA11y(page);
    await expectCleanStorage(page);

    // The sender is alerted of the deleted file and of the file not analysed.
    const alert = await waitForMail(sender, { subject: /^Infected file deleted from your transfer via/ });
    expect(alert.Text).toContain(infected.name);
    expect(alert.Text).toContain('Eicar-Test-Signature');
    const notScanned = await waitForMail(sender, { subject: /^File not scanned by the antivirus/ });
    expect(notScanned.Text).toContain(large.name);

    // The recipient's mail and page only offer the delivered files.
    const notification = await waitForMail(recipient, { subject: /sent you files via/ });
    expect(notification.Text).not.toContain(infected.name);
    expect(notification.Text).toContain(large.sha256);
    const rpage = await (await newContext()).newPage();
    await rpage.goto(mailLink(notification, '/d/', tenant.origin));
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    const table = rpage.getByRole('table', { name: 'Files of this transfer' });
    await expect(table.getByRole('row')).toHaveCount(3); // header + 2 files
    await expect(table.getByText(infected.name)).toHaveCount(0);
    await expect(rpage.getByText(/Some files could not be analysed by the antivirus/)).toBeVisible();
    await expect(table.getByRole('row', { name: /large-video/ })).toContainText(
      'Not analysed by the antivirus: this file is too large to be analysed.',
    );
    await expect(table.getByRole('row', { name: /clean-sheet/ })).not.toContainText('Not analysed');
    await checkA11y(rpage);
    await expectCleanStorage(rpage);
  });

  test('a transfer whose only file is infected is refused', async ({ page, state }) => {
    const tenant = state.tenants.a;
    const sender = internalEmail('av-only');
    const recipient = internalEmail('av-only-recipient');
    const infected = infectedFile('only-file.txt');

    await identify(page, tenant.origin, sender);
    await deposit(page, { recipients: [recipient], files: [infected] }, 'refused');
    await expect(page.getByRole('alert').filter({ hasText: 'No file could be delivered' })).toBeVisible();
    await expect(
      page
        .getByRole('list', { name: 'Files of the transfer' })
        .getByText('Threat detected: Eicar-Test-Signature'),
    ).toBeVisible();
    await checkA11y(page);
    const alert = await waitForMail(sender, { subject: /^Infected file deleted from your transfer via/ });
    expect(alert.Text).toContain(infected.name);
  });
});
