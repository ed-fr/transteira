// Sealed proofs of deposit and delivery (V2 step 4, CLAUDE.md section 22): a sender downloads the
// proof of deposit from "My transfers", a delegated admin the proofs of deposit and delivery from
// the transfer detail of the entity. The PDF is checked as a download (it starts with %PDF and has
// a size); its signature is verified by the Go integration tests (test/integration/proofs_test.go).
import { ORIGINS, STORAGE_DELEGATE } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { externalEmail, internalEmail, makeFile } from '../support/data';
import { openDepositSession, recipientPath, sessionDeposit, tokenDeposit } from '../support/deposit';
import { waitForMail } from '../support/mailpit';
import { download, mailLink } from '../support/publicflow';

/** A PDF is a file that starts with its header and holds more than a header. */
function expectPdf(file: { name: string; data: Buffer }): void {
  expect(file.name).toMatch(/\.pdf$/);
  expect(file.data.subarray(0, 5).toString('latin1')).toBe('%PDF-');
  expect(file.data.length).toBeGreaterThan(1000);
  // The signed statement and its signature are attached files of the PDF.
  const text = file.data.toString('latin1');
  expect(text).toContain('statement.json');
  expect(text).toContain('statement.sig');
}

test.describe('proofs', () => {
  test('a sender downloads the proof of deposit from "My transfers"', async ({ state, newContext }) => {
    const origin = state.tenants.a.origin;
    const sender = internalEmail('proof-sender');
    const to = externalEmail('proof-to');
    const session = await openDepositSession(sender);
    const sent = await sessionDeposit(session, { recipients: [to], files: [makeFile('plans.bin', 4096)] });
    expect(sent.status).toBe('available');

    const mine = await (await newContext()).newPage();
    await mine.goto(`${origin}/me`);
    const after = Date.now();
    await mine.getByLabel(/^Your email address/).fill(sender);
    await mine.getByRole('button', { name: 'Send me a link' }).click();
    await mine.goto(mailLink(await waitForMail(sender, { after }), '/me', origin));
    await expect(mine.getByRole('table', { name: 'Transfers in progress' })).toBeVisible();
    await mine.getByRole('button', { name: /^Details.*proof-to/ }).click();

    const proofs = mine.getByRole('region', { name: 'Proofs' });
    await expect(proofs).toBeVisible();
    // Nothing was downloaded yet: the proof of delivery waits for the first download.
    await expect(proofs.getByRole('button', { name: 'Download the proof of delivery' })).toBeDisabled();
    await expect(proofs.getByText('Available after the first download.')).toBeVisible();
    await checkA11y(mine);

    const proof = await download(mine, () =>
      proofs.getByRole('button', { name: 'Download the proof of deposit' }).click(),
    );
    expectPdf(proof);
    await expect(mine.getByText('Proof downloaded.').first()).toBeAttached();
  });

  test.describe('delegated admin', () => {
    test.use({ storageState: STORAGE_DELEGATE });

    test('the transfer detail gives the proofs of deposit and, after a download, of delivery', async ({
      page,
      state,
      newContext,
    }) => {
      const sender = internalEmail('proof-admin-sender');
      const to = externalEmail('proof-admin-to');
      const file = makeFile('contract.bin', 4096);
      const deposit = await tokenDeposit(state.apiTokenA, sender, { recipients: [to], files: [file] });
      expect(deposit.status).toBe('available');
      const detail = `${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/transfers/${deposit.id}`;

      await page.goto(detail);
      await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
      const proofs = page.getByRole('region', { name: 'Proofs' });
      await expect(proofs.getByRole('button', { name: 'Download the proof of delivery' })).toBeDisabled();
      const deposited = await download(page, () =>
        proofs.getByRole('button', { name: 'Download the proof of deposit' }).click(),
      );
      expectPdf(deposited);
      await checkA11y(page);

      // The recipient downloads the file through their own link.
      const link = await recipientPath(deposit, to);
      const rpage = await (await newContext()).newPage();
      await rpage.goto(`${state.tenants.a.origin}${link}`);
      await download(rpage, () => rpage.getByRole('link', { name: `Download ${file.name}` }).click());
      await waitForMail(sender, { subject: /^Your transfer has been downloaded via/ });

      // The detail now offers the proofs of delivery, overall and for that recipient.
      await page.reload();
      await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
      const delivered = await download(page, () =>
        proofs.getByRole('button', { name: 'Download the proof of delivery', exact: true }).click(),
      );
      expectPdf(delivered);
      expect(delivered.name).not.toBe(deposited.name);
      const forRecipient = await download(page, () =>
        proofs.getByRole('button', { name: `Download the proof of delivery for ${to}` }).click(),
      );
      expectPdf(forRecipient);
    });
  });
});
