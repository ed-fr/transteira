// Steps of the one-time secrets scenarios (specs/public-secret.spec.ts, specs/admin-secrets.spec.ts):
// the creation tab of the public deposit form and the reveal page of a secret link.
import { expect, type BrowserContext, type Page, type Request } from '@playwright/test';
import type { GeneratedFile } from './data';

/** Values of the creation form of a secret. */
export interface SecretInput {
  text?: string;
  passphrase?: string;
  file?: GeneratedFile;
  /** Delivery by e-mail to recipient; absent: link delivery (or forced e-mail for an invited external). */
  recipient?: string;
  readReceipt?: boolean;
}

/** Opens the "Share a secret" tab of the deposit form (the session must be open). */
export async function openSecretTab(page: Page): Promise<void> {
  await page.getByRole('tab', { name: 'Share a secret' }).click();
  await expect(page.getByRole('heading', { name: 'Share a secret', level: 1 })).toBeVisible();
}

/** Fills the creation form (without sending it); the secret tab must be open. */
export async function fillSecret(page: Page, input: SecretInput): Promise<void> {
  if (input.text !== undefined) await page.locator('#tt-secret-text').fill(input.text);
  if (input.recipient !== undefined) {
    await page.getByLabel('Send the link by email').check();
    await page.getByLabel(/^Recipient's email address/).fill(input.recipient);
  }
  if (input.passphrase !== undefined) await page.locator('#tt-secret-passphrase').fill(input.passphrase);
  if (input.file) {
    const f = input.file;
    await page
      .locator('input[type="file"]#tt-secret-file')
      .setInputFiles({ name: f.name, mimeType: f.mimeType, buffer: f.buffer });
    await expect(page.getByRole('list', { name: 'Attached file' }).getByText(f.name)).toBeVisible();
  }
  if (input.readReceipt) await page.getByLabel(/^Notify me by email when the secret is read/).check();
}

/** Sends the filled form and waits for the "Secret created" screen. */
export async function submitSecret(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Create the secret' }).click();
  await expect(page.getByRole('heading', { name: 'Secret created', level: 1 })).toBeVisible({
    timeout: 30_000,
  });
}

/**
 * Opens the secret tab, fills and sends the form; returns the link shown at the end (link
 * delivery) or undefined (e-mail delivery).
 */
export async function createSecret(page: Page, input: SecretInput): Promise<string | undefined> {
  await openSecretTab(page);
  await fillSecret(page, input);
  await submitSecret(page);
  const link = page.getByTestId('secret-done-link');
  return (await link.count()) === 0 ? undefined : ((await link.textContent()) ?? undefined);
}

/** Presses "Show the secret" on the reveal page, with an optional passphrase. */
export async function pressShow(page: Page, passphrase?: string): Promise<void> {
  if (passphrase !== undefined) await page.locator('#tt-secret-passphrase').fill(passphrase);
  await page.getByRole('button', { name: 'Show the secret' }).click();
}

/** Expects the reveal page to be ready (form shown, nothing consumed). */
export async function expectReady(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Read a secret', level: 1 })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Show the secret' })).toBeVisible();
}

/** Expects the revealed secret to show text. */
export async function expectRevealed(page: Page, text: string): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Your secret', level: 1 })).toBeVisible();
  await expect(page.locator('#tt-secret-text')).toHaveValue(text);
}

/** Expects the "no longer available" page with the given text. */
export async function expectGone(page: Page, text: RegExp | string): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Secret no longer available', level: 1 })).toBeVisible();
  await expect(page.getByText(text)).toBeVisible();
}

/** One request of a browser context, as it left the browser (URL, every header, body). */
export interface CapturedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Buffer | null;
}

/**
 * Records every request of a browser context (its pages and service workers) from now on (T-344).
 * Await done() before reading the list: headers are read asynchronously.
 */
export function captureRequests(context: BrowserContext): {
  requests: CapturedRequest[];
  done: () => Promise<void>;
} {
  const requests: CapturedRequest[] = [];
  const pending: Promise<void>[] = [];
  context.on('request', (req: Request) => {
    pending.push(
      req.allHeaders().then((headers) => {
        requests.push({ method: req.method(), url: req.url(), headers, body: req.postDataBuffer() });
      }),
    );
  });
  return { requests, done: async () => void (await Promise.all(pending)) };
}

/** Path of the e-mail send of a secret, the only request allowed to carry its key. */
const SEND_PATH = /^\/api\/v1\/secrets\/[^/]+\/send$/;

/**
 * Checks that the key K of a secret link (base64url, from "#k=") appears in no URL, header or body
 * of the captured requests, in its text form or as raw bytes, except as the fragmentKey member of
 * POST /api/v1/secrets/{id}/send; returns the number of such sends (T-344, T-363).
 */
export function expectKeyNowhere(requests: readonly CapturedRequest[], link: string): number {
  const encoded = new URL(link).hash.replace(/^#k=/, '');
  expect(encoded).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const raw = Buffer.from(encoded, 'base64url');
  expect(raw).toHaveLength(32);
  const leaks = (text: string) => text.includes(encoded) || text.includes(decodeURIComponent(encoded));
  let sends = 0;
  for (const r of requests) {
    const where = `${r.method} ${r.url}`;
    expect(leaks(r.url), `key in the URL of ${where}`).toBe(false);
    for (const [name, value] of Object.entries(r.headers)) {
      expect(leaks(value), `key in the header ${name} of ${where}`).toBe(false);
    }
    if (r.body === null) continue;
    let body = r.body;
    if (r.method === 'POST' && SEND_PATH.test(new URL(r.url).pathname)) {
      const json = JSON.parse(body.toString('utf8')) as { fragmentKey?: unknown };
      expect(json.fragmentKey, `fragmentKey of ${where}`).toBe(encoded);
      delete json.fragmentKey;
      body = Buffer.from(JSON.stringify(json), 'utf8');
      sends++;
    }
    expect(leaks(body.toString('latin1')), `key in the body of ${where}`).toBe(false);
    expect(body.includes(raw), `raw key bytes in the body of ${where}`).toBe(false);
  }
  return sends;
}
