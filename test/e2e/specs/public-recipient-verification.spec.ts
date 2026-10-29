// Recipient verification of V1.1 step 6 (CLAUDE.md section 10): every recipient gets a personal
// link (read in their mail, no API answer carries a link). With the option checked by the sender,
// the download page first asks the recipient to prove their address with a 6-digit code sent by
// mail; a link forwarded to someone else is useless, and two wrong codes invalidate the code.
import type { BrowserContext, Page } from '@playwright/test';
import { externalEmail, internalEmail, makeFile, sha256 } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForCode, waitForMail } from '../support/mailpit';
import { download, identify, mailLink, sendTransfer, fillTransfer } from '../support/publicflow';

const VERIFY_TITLE = 'Confirm your address';

/** Sends a transfer with the verification option; returns the recipient's personal link. */
async function sendVerified(
  page: Page,
  origin: string,
  label: string,
  file: ReturnType<typeof makeFile>,
): Promise<{ recipient: string; link: string }> {
  const recipient = externalEmail(`${label}-recipient`);
  await identify(page, origin, internalEmail(`${label}-sender`));
  await fillTransfer(page, { recipients: [recipient], files: [file] });
  const option = page.getByRole('checkbox', { name: 'Recipients must verify their address by code' });
  await expect(option).not.toBeChecked();
  await option.check();
  await sendTransfer(page);
  const mail = await waitForMail(recipient, { subject: /sent you files via/ });
  return { recipient, link: mailLink(mail, '/d/', origin) };
}

/** Asks for a code on the verification step; returns the code read in Mailpit. */
async function requestCode(page: Page, recipient: string): Promise<string> {
  // The code mail is created after the click: a stricter bound than usual tells it from an earlier one.
  const after = Date.now();
  await page.getByRole('button', { name: /^Send (me )?a (new )?code$/ }).click();
  await expect(page.getByLabel(/^Verification code/)).toBeVisible();
  return waitForCode(recipient, after);
}

async function openLink(newContext: () => Promise<BrowserContext>, link: string): Promise<Page> {
  const page = await (await newContext()).newPage();
  await page.goto(link);
  await expect(page.getByRole('heading', { name: VERIFY_TITLE, level: 1 })).toBeVisible();
  return page;
}

test.describe('recipient verification', () => {
  test('the recipient proves their address by code, then downloads', async ({ page, state, newContext }) => {
    const file = makeFile('verified.bin', 8 * 1024);
    const { recipient, link } = await sendVerified(page, state.tenants.a.origin, 'rv-ok', file);
    await expectCleanStorage(page);

    const rpage = await openLink(newContext, link);
    // Nothing of the transfer is shown before the code, and the address is masked.
    await expect(rpage.getByText(file.name)).toHaveCount(0);
    await expect(rpage.getByText(/Address: .*\*\*\*/)).toBeVisible();
    await expect(rpage.getByText(recipient)).toHaveCount(0);
    await checkA11y(rpage);

    const code = await requestCode(rpage, recipient);
    await checkA11y(rpage);
    await rpage.getByLabel(/^Verification code/).fill(code);
    await rpage.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    const got = await download(rpage, () =>
      rpage.getByRole('link', { name: `Download ${file.name}` }).click(),
    );
    expect(sha256(got.data)).toBe(file.sha256);
    await checkA11y(rpage);
    await expectCleanStorage(rpage);
  });

  test('a forwarded link cannot download without the code', async ({ page, state, newContext, guards }) => {
    guards.allowHttpError(401, /\/files\//);
    guards.allowHttpError(403, /\/files\//);
    guards.allowHttpError(409, /\/files\//);
    const file = makeFile('forwarded.bin', 4 * 1024);
    const { recipient, link } = await sendVerified(page, state.tenants.a.origin, 'rv-fwd', file);

    // The recipient verifies and gets the file URL.
    const rpage = await openLink(newContext, link);
    const code = await requestCode(rpage, recipient);
    await rpage.getByLabel(/^Verification code/).fill(code);
    await rpage.getByRole('button', { name: 'Verify', exact: true }).click();
    const href = await rpage.getByRole('link', { name: `Download ${file.name}` }).getAttribute('href');
    const fileUrl = new URL(href ?? '', rpage.url()).toString();

    // Someone the link was forwarded to: another browser, no cookie, no code.
    const other = await newContext();
    const opage = await other.newPage();
    await opage.goto(link);
    await expect(opage.getByRole('heading', { name: VERIFY_TITLE, level: 1 })).toBeVisible();
    await expect(opage.getByText(file.name)).toHaveCount(0);
    await expect(opage.getByRole('link', { name: `Download ${file.name}` })).toHaveCount(0);
    // The file URL itself is refused without the verification cookie.
    const res = await opage.evaluate(async (url) => {
      const r = await fetch(url);
      return { status: r.status, size: (await r.arrayBuffer()).byteLength };
    }, fileUrl);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(res.size).not.toBe(file.buffer.length);
  });

  test('two wrong codes exhaust the code and a new one must be requested', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    guards.allowHttpError(422, /\/verification\/confirm$/);
    guards.allowHttpError(410, /\/verification\/confirm$/);
    guards.allowHttpError(409, /\/verification\/confirm$/);
    const file = makeFile('wrong.bin', 4 * 1024);
    const { recipient, link } = await sendVerified(page, state.tenants.a.origin, 'rv-wrong', file);

    const rpage = await openLink(newContext, link);
    const code = await requestCode(rpage, recipient);
    const wrong = code === '000000' ? '111111' : '000000';
    const input = rpage.getByLabel(/^Verification code/);

    await input.fill(wrong);
    await rpage.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(rpage.getByText(/The code is not correct\./)).toBeVisible();
    await checkA11y(rpage);

    await input.fill(wrong);
    await rpage.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(rpage.getByText(/too many wrong codes/)).toBeVisible();
    await expect(rpage.getByRole('button', { name: 'Send me a code' })).toBeVisible();

    // The exhausted code is useless even when typed correctly after a new request is made:
    // a fresh code is required, and then works.
    const fresh = await requestCode(rpage, recipient);
    await rpage.getByLabel(/^Verification code/).fill(fresh);
    await rpage.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
  });
});
