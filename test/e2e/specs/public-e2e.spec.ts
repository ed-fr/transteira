// End-to-end encryption in the browser (CLAUDE.md sections 8.2 and 22, V2 step 8, threat model
// T-160 and the key-never-sent checks): the sender encrypts the files, their names and the message
// in the browser, gets a decryption key shown once, and the recipient opens the link with the key
// (fragment "#k=" or typed) and decrypts the files in the browser.
//
// The tests change the end-to-end policy of entity A, a setting shared by every test of the run
// (a "required" policy would refuse the deposits of the other specs): this spec runs in the
// "system-serial" project (playwright.config.ts), one test at a time, after the main project.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { BrowserContext, Page, Request } from '@playwright/test';
import {
  externalEmail,
  internalEmail,
  makeFile,
  sha256,
  textFile,
  type GeneratedFile,
} from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { download, fillTransfer, identify, mailLink } from '../support/publicflow';
import { escapeRegExp, re } from '../support/regexp';
import { loadState, superAdminApi } from '../support/state';
import { readStoredZip } from '../support/zip';

test.describe.configure({ mode: 'serial' });

// Caddy's internal CA is unknown to the browser: ignoreHTTPSErrors does not cover the Service
// Worker script fetch ("An SSL certificate error occurred when fetching the script"), so the
// decrypted downloads would silently use the in-memory fallback. This flag makes the Service
// Worker path (/e2e-sw.js, scope /e2e/) the one under test, as with a trusted certificate.
test.use({ launchOptions: { args: ['--ignore-certificate-errors'] } });

type Policy = 'forbidden' | 'allowed' | 'required';

/** Sets the end-to-end policy of entity A (super admin setting). */
async function setPolicy(tenantId: string, policy: Policy): Promise<void> {
  await superAdminApi().ok('PATCH', `/admin/tenants/${tenantId}`, { e2ePolicy: policy });
}

test.beforeAll(async () => setPolicy(loadState().tenants.a.id, 'allowed'));
test.afterAll(async () => setPolicy(loadState().tenants.a.id, 'forbidden'));

/** Records every request of contexts and fails on any trace of the key (T-160). */
class KeyWatch {
  private keys: string[] = [];
  readonly problems: string[] = [];
  requests = 0;

  setKey(key: string): void {
    const raw = Buffer.from(key, 'base64url');
    this.keys = [key, raw.toString('base64'), raw.toString('base64').replace(/=+$/, ''), raw.toString('hex')];
  }

  /** Called for each request: the key is unknown while the first ones go by, so they are kept small. */
  private pending: { label: string; text: string; body: Buffer | null }[] = [];

  attach(context: BrowserContext): void {
    context.on('request', (req: Request) => {
      this.requests++;
      const body = req.postDataBuffer();
      this.pending.push({
        label: `${req.method()} ${req.url()}`,
        text: `${req.url()}\n${JSON.stringify(req.headers())}`,
        // Ciphertext chunks are kept as is: they are searched in check() once the key is known.
        body,
      });
    });
  }

  check(): void {
    for (const p of this.pending) {
      for (const k of this.keys) {
        if (p.text.includes(k)) this.problems.push(`key in URL or headers of ${p.label}`);
        if (p.body?.includes(k)) this.problems.push(`key in the body of ${p.label}`);
      }
    }
    this.pending = [];
  }
}

/** Temporary directory with a folder tree: project/docs/inner.txt. */
function makeFolder(): { root: string; folder: string; file: GeneratedFile } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'transteira-e2e-'));
  const folder = path.join(root, 'project');
  const inner = textFile('inner.txt', 'inside the folder\n'.repeat(50));
  fs.mkdirSync(path.join(folder, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(folder, 'docs', 'inner.txt'), inner.buffer);
  return { root, folder, file: inner };
}

/** Writes a generated file on disk (a stable modification date, needed by the resume after a reload). */
function writeTemp(dir: string, f: GeneratedFile): string {
  const p = path.join(dir, f.name);
  fs.writeFileSync(p, f.buffer);
  return p;
}

/** The key shown on the last step. */
async function shownKey(page: Page): Promise<string> {
  const key = (await page.getByTestId('deposit-e2e-key').innerText()).trim();
  expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return key;
}

/** Sends the filled form and waits for the last step of an end-to-end encrypted transfer. */
async function sendAndWaitKey(page: Page, timeout = 90_000): Promise<string> {
  await page.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Transfer sent', level: 1 })).toBeVisible({ timeout });
  await expect(page.getByTestId('deposit-e2e-key-section')).toBeVisible();
  return shownKey(page);
}

/** Deposits small end-to-end encrypted files (options on the form before sending) and returns key and link. */
async function smallEncryptedDeposit(
  page: Page,
  tenant: { origin: string },
  recipient: string,
  files: GeneratedFile[],
  opts: { password?: string; message?: string; maxDownloads?: number } = {},
): Promise<{ key: string; mail: Awaited<ReturnType<typeof waitForMail>>; link: string }> {
  const sender = internalEmail('e2e-sender');
  await identify(page, tenant.origin, sender);
  const input = {
    recipients: [recipient],
    files,
    ...(opts.password !== undefined ? { password: opts.password } : {}),
    ...(opts.message !== undefined ? { message: opts.message } : {}),
  };
  await fillTransfer(page, input);
  await page.locator('#tt-deposit-e2e').check();
  if (opts.maxDownloads !== undefined)
    await page.locator('#tt-deposit-max-downloads').fill(String(opts.maxDownloads));
  const key = await sendAndWaitKey(page);
  const mail = await waitForMail(recipient, {
    subject: new RegExp(`^${escapeRegExp(sender)} sent you files via`),
  });
  return { key, mail, link: mailLink(mail, '/d/', tenant.origin) };
}

/** Name of the per-file download button of the decrypted list. */
const fileButton = (page: Page, name: string) => page.getByRole('button', { name: re(`Download ${name}`) });

test.describe('public: end-to-end encryption', () => {
  test('encrypted deposit, mail without key, decrypted download of a file and the ZIP', async ({
    page,
    state,
    newContext,
  }) => {
    test.setTimeout(240_000);
    const tenant = state.tenants.a;
    const sender = internalEmail('e2e-sender');
    const recipient = internalEmail('e2e-recipient');
    const tree = makeFolder();
    // 64 MiB: crosses the 32 MiB tus chunks and many 1 MiB encryption chunks.
    const big = makeFile('big-archive.bin', 64 * 1024 * 1024);
    const message = `Secret agenda ${crypto.randomBytes(6).toString('hex')} for the board`;
    const watch = new KeyWatch();
    watch.attach(page.context());

    await identify(page, tenant.origin, sender);
    await page.locator('input[webkitdirectory]').setInputFiles(tree.folder);
    // A 64 MiB file is passed by path (Playwright refuses buffers above 50 MB).
    await page.getByRole('textbox', { name: /^Recipients/ }).fill(recipient);
    await page.getByLabel(/^Message/).fill(message);
    await page.getByLabel(/^Files to send/).setInputFiles(writeTemp(tree.root, big));
    await expect(page.getByRole('list', { name: 'Selected files' }).getByRole('listitem')).toHaveCount(2);
    const option = page.locator('#tt-deposit-e2e');
    await expect(option).toBeVisible();
    await expect(option).not.toBeChecked();
    await expect(page.getByLabel('Encrypt end to end in my browser')).toBeEnabled();
    await checkA11y(page);
    await option.check();
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    // The browser reads the files once before creating the transfer.
    // The step can be over within milliseconds: only its presence is asserted (the labelled bar is
    // covered by the unit tests of the component).
    await expect(page.getByTestId('deposit-e2e-preparing')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Transfer sent', level: 1 })).toBeVisible({
      timeout: 120_000,
    });
    const key = await shownKey(page);
    watch.setKey(key);
    await expect(page.getByRole('button', { name: 'Copy the key' })).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);

    // The mail holds neither the key nor the message nor the names; it says the key comes apart.
    const notification = await waitForMail(recipient, {
      subject: new RegExp(`^${escapeRegExp(sender)} sent you files via`),
    });
    for (const body of [notification.Text, notification.HTML]) {
      expect(body).not.toContain(key);
      expect(body).not.toContain(message);
      expect(body).not.toContain('big-archive');
      expect(body).not.toContain('inner.txt');
    }
    expect(notification.Text.replace(/\s+/g, ' ')).toMatch(/key is not in this message.*another channel/);
    const link = mailLink(notification, '/d/', tenant.origin);
    expect(link).not.toContain('#k=');

    // The recipient: the link and the key in the fragment, in another browser.
    const rctx = await newContext();
    watch.attach(rctx);
    const rpage = await rctx.newPage();
    await rpage.goto(`${link}#k=${key}`);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(rpage.getByText(message)).toBeVisible();
    // The key is removed from the address bar once read; a reload asks for it again.
    expect(await rpage.evaluate(() => location.hash)).toBe('');
    await expect(
      rpage.getByText(/not analysed|could not be analysed|cannot analyse this file/).first(),
    ).toBeVisible();
    const table = rpage.getByRole('table', { name: 'Files of this transfer' });
    await expect(table.getByRole('row', { name: re('big-archive.bin') })).toBeVisible();
    await expect(table.getByRole('row', { name: re('project/docs/inner.txt') })).toBeVisible();
    await expect(table.getByText(big.sha256)).toBeVisible();
    await checkA11y(rpage);

    const one = await download(rpage, () => fileButton(rpage, 'big-archive.bin').click());
    expect(one.name).toBe('big-archive.bin');
    expect(one.data.length).toBe(big.buffer.length);
    expect(sha256(one.data)).toBe(big.sha256);

    const zip = await download(rpage, () => rpage.locator('#tt-e2e-archive').click());
    expect(zip.name).toMatch(/\.zip$/);
    const entries = readStoredZip(zip.data);
    expect(entries.map((e) => e.name).sort()).toEqual(['big-archive.bin', 'project/docs/inner.txt']);
    expect(sha256(entries.find((e) => e.name === 'big-archive.bin')!.data)).toBe(big.sha256);
    expect(sha256(entries.find((e) => e.name === 'project/docs/inner.txt')!.data)).toBe(tree.file.sha256);
    await expectCleanStorage(rpage);

    // Threat model: the key never travelled in any request of the sender or of the recipient.
    expect(watch.requests).toBeGreaterThan(10);
    watch.check();
    expect(watch.problems).toEqual([]);
    fs.rmSync(tree.root, { recursive: true, force: true });
  });

  test('a link without key asks for it; a wrong key is refused; the full link is accepted', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    const recipient = externalEmail('e2e-key-recipient');
    const file = makeFile('quarterly.bin', 20 * 1024);
    const { key, link } = await smallEncryptedDeposit(page, tenant, recipient, [file], {
      message: 'hidden message',
    });

    const rpage = await (await newContext()).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    const field = rpage.locator('#tt-e2e-key');
    await expect(field).toBeVisible();
    await expect(rpage.getByRole('textbox', { name: /^Decryption key/ })).toBeVisible();
    // Neither the names nor the message are readable without the key.
    await expect(rpage.getByText(file.name)).toHaveCount(0);
    await expect(rpage.getByText('hidden message')).toHaveCount(0);
    await checkA11y(rpage);

    // An empty submit, a malformed key, then a valid key of another transfer.
    await rpage.locator('#tt-e2e-key-submit').click();
    await expect(rpage.getByText('Enter the decryption key.')).toBeVisible();
    await field.fill('not-a-key');
    await rpage.locator('#tt-e2e-key-submit').click();
    await expect(rpage.getByText('This is not a valid key')).toBeVisible();
    await expect(field).toHaveAttribute('aria-invalid', 'true');
    await field.fill(crypto.randomBytes(32).toString('base64url'));
    await rpage.locator('#tt-e2e-key-submit').click();
    await expect(rpage.getByText('This key does not open this transfer')).toBeVisible();
    await expect(rpage.getByRole('table', { name: 'Files of this transfer' })).toHaveCount(0);

    // The complete link, pasted in the field, opens it.
    await field.fill(`${link}#k=${key}`);
    await rpage.locator('#tt-e2e-key-submit').click();
    const row = rpage.getByRole('table', { name: 'Files of this transfer' }).getByRole('row', {
      name: re(file.name),
    });
    await expect(row).toBeVisible();
    await expect(rpage.getByText('hidden message')).toBeVisible();
    const got = await download(rpage, () => fileButton(rpage, file.name).click());
    expect(sha256(got.data)).toBe(file.sha256);
  });

  test('a cut connection resumes; a reload mid-upload resumes with the same key', async ({
    page,
    state,
    newContext,
    guards,
  }) => {
    // The connection resets injected on purpose are logged by the browser.
    guards.allowConsoleErrors(/net::ERR_CONNECTION_RESET/);
    test.setTimeout(240_000);
    const tenant = state.tenants.a;
    const sender = internalEmail('e2e-resume');
    const recipient = externalEmail('e2e-resume-recipient');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'transteira-e2e-resume-'));
    // 40 MiB: two tus chunks, so that an interruption leaves a partial upload.
    const cut = makeFile('cut.bin', 40 * 1024 * 1024);
    const paths = [writeTemp(dir, cut)];
    const isPatch = (r: Request) => r.method() === 'PATCH' && /\/api\/v1\/uploads\//.test(r.url());

    // Part 1: the first PATCH fails with a reset connection, the retry succeeds.
    let aborted = 0;
    await page.route(/\/api\/v1\/uploads\//, async (route) => {
      if (isPatch(route.request()) && aborted === 0) {
        aborted++;
        await route.abort('connectionreset');
      } else await route.continue();
    });
    await identify(page, tenant.origin, sender);
    await page.getByRole('textbox', { name: /^Recipients/ }).fill(recipient);
    await page.getByLabel(/^Files to send/).setInputFiles(paths);
    await page.locator('#tt-deposit-e2e').check();
    const key1 = await sendAndWaitKey(page, 120_000);
    expect(aborted).toBe(1);
    await expectCleanStorage(page);
    const mail1 = await waitForMail(recipient, { subject: /sent you files via/ });
    const r1 = await (await newContext()).newPage();
    await r1.goto(`${mailLink(mail1, '/d/', tenant.origin)}#k=${key1}`);
    const got1 = await download(r1, () => fileButton(r1, cut.name).click());
    expect(sha256(got1.data)).toBe(cut.sha256);
    await page.unroute(/\/api\/v1\/uploads\//);

    // Part 2: the first chunk goes through, the rest is cut, the page is reloaded.
    const recipient2 = externalEmail('e2e-resume-recipient2');
    let patches = 0;
    let blocking = true;
    await page.route(/\/api\/v1\/uploads\//, async (route) => {
      if (!isPatch(route.request())) return route.continue();
      patches++;
      if (patches === 1 || !blocking) return route.continue();
      return route.abort('connectionreset');
    });
    await page.getByRole('button', { name: 'New transfer' }).click();
    await page.getByRole('textbox', { name: /^Recipients/ }).fill(recipient2);
    await page.getByLabel(/^Files to send/).setInputFiles(paths);
    await page.locator('#tt-deposit-e2e').check();
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByText('Connection lost, trying again…')).toBeVisible({ timeout: 90_000 });
    expect(await page.evaluate(() => Object.keys(sessionStorage))).toContain('tt.upload');
    blocking = false;
    await page.reload();
    await expect(
      page.getByRole('heading', { name: 'Resume the interrupted upload', level: 1 }),
    ).toBeVisible();
    await page.getByLabel(/^Select the same files again/).setInputFiles(paths);
    await page.getByRole('button', { name: 'Continue the upload' }).click();
    await expect(page.getByRole('heading', { name: 'Transfer sent', level: 1 })).toBeVisible({
      timeout: 120_000,
    });
    const key2 = await shownKey(page);
    expect(key2).not.toBe(key1);
    await expectCleanStorage(page);

    const mail2 = await waitForMail(recipient2, { subject: /sent you files via/ });
    const r2 = await (await newContext()).newPage();
    await r2.goto(`${mailLink(mail2, '/d/', tenant.origin)}#k=${key2}`);
    const got2 = await download(r2, () => fileButton(r2, cut.name).click());
    expect(sha256(got2.data)).toBe(cut.sha256);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('the policy decides whether the option is offered', async ({ page, state }) => {
    const tenant = state.tenants.a;
    const sender = internalEmail('e2e-policy');
    await identify(page, tenant.origin, sender);
    try {
      // Required: ticked and locked.
      await setPolicy(tenant.id, 'required');
      await page.reload();
      await expect(page.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
      const option = page.locator('#tt-deposit-e2e');
      await expect(option).toBeChecked();
      await expect(option).toBeDisabled();
      await expect(page.getByText(/Required by your organisation/)).toBeVisible();

      // Forbidden: absent.
      await setPolicy(tenant.id, 'forbidden');
      await page.reload();
      await expect(page.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
      await expect(page.locator('#tt-deposit-e2e')).toHaveCount(0);
    } finally {
      await page.waitForLoadState('networkidle');
      await setPolicy(tenant.id, 'allowed');
    }
  });

  test('a password and the key: unlock, then key, then download', async ({ page, state, newContext }) => {
    const tenant = state.tenants.a;
    const recipient = externalEmail('e2e-pw-recipient');
    const file = makeFile('locked-and-sealed.bin', 12 * 1024);
    const password = 'correct horse battery staple';
    const { key, link } = await smallEncryptedDeposit(page, tenant, recipient, [file], { password });

    const rpage = await (await newContext()).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Password required', level: 1 })).toBeVisible();
    await expect(rpage.getByText(/you will also need its decryption key/)).toBeVisible();
    await rpage.getByLabel(/^Password/).fill(password);
    await rpage.getByRole('button', { name: 'Unlock' }).click();
    await expect(rpage.locator('#tt-e2e-key')).toBeVisible();
    await rpage.locator('#tt-e2e-key').fill(key);
    await rpage.locator('#tt-e2e-key-submit').click();
    await expect(
      rpage.getByRole('table', { name: 'Files of this transfer' }).getByRole('row', { name: re(file.name) }),
    ).toBeVisible();
    const got = await download(rpage, () => fileButton(rpage, file.name).click());
    expect(sha256(got.data)).toBe(file.sha256);
  });

  test('with a single download allowed, the whole ZIP of an encrypted transfer downloads', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.a;
    const recipient = externalEmail('e2e-max-recipient');
    const files = [makeFile('first.bin', 30 * 1024), makeFile('second.bin', 5 * 1024)];
    const { key, link } = await smallEncryptedDeposit(page, tenant, recipient, files, { maxDownloads: 1 });

    const rpage = await (await newContext()).newPage();
    await rpage.goto(`${link}#k=${key}`);
    await expect(rpage.locator('#tt-e2e-archive')).toBeVisible();
    const zip = await download(rpage, () => rpage.locator('#tt-e2e-archive').click());
    const entries = readStoredZip(zip.data);
    expect(entries.map((e) => e.name).sort()).toEqual(files.map((f) => f.name).sort());
    for (const f of files) {
      expect(sha256(entries.find((e) => e.name === f.name)!.data)).toBe(f.sha256);
    }
  });
});
