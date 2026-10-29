// Steps of the public interface shared by the public scenarios (specs/public-*.spec.ts):
// identification by code (read in Mailpit), the deposit form, the download page and mail links.
import { expect, type Download, type Page } from '@playwright/test';
import fs from 'node:fs';
import type { GeneratedFile } from './data';
import { linksOf, waitForCode, type Mail } from './mailpit';

/** Waits for the next code sent to email (after `after`), types it and confirms it. */
export async function enterCode(page: Page, email: string, after: number): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Enter the verification code', level: 1 })).toBeVisible();
  const code = await waitForCode(email, after);
  await page.getByLabel(/^Verification code/).fill(code);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
}

/** Submits the email step with address (the deposit page must show it). */
export async function submitEmail(page: Page, email: string): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
  await page.getByLabel(/^Your email address/).fill(email);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
}

/**
 * Opens the deposit page of origin and identifies email by code, up to the deposit form.
 * onScreen runs on the email and code steps (accessibility checks).
 */
export async function identify(
  page: Page,
  origin: string,
  email: string,
  onScreen?: (step: 'email' | 'code') => Promise<void>,
): Promise<void> {
  await page.goto(`${origin}/`);
  await expect(page.getByRole('heading', { name: 'Send files', level: 1 })).toBeVisible();
  await onScreen?.('email');
  const after = Date.now() - 2000;
  await submitEmail(page, email);
  await expect(page.getByRole('heading', { name: 'Enter the verification code', level: 1 })).toBeVisible();
  await onScreen?.('code');
  await enterCode(page, email, after);
  await expectForm(page);
}

/** Checks that the deposit form is shown. */
export async function expectForm(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: 'New transfer', level: 1 })).toBeVisible();
}

/** Values of the deposit form. */
export interface TransferInput {
  /** Recipients (omitted for an invited external depositor). */
  recipients?: string[];
  message?: string;
  password?: string;
  files: GeneratedFile[];
}

/** Fills the deposit form (without sending it). */
export async function fillTransfer(page: Page, input: TransferInput): Promise<void> {
  if (input.recipients)
    await page.getByRole('textbox', { name: /^Recipients/ }).fill(input.recipients.join('\n'));
  if (input.message !== undefined) await page.getByLabel(/^Message/).fill(input.message);
  if (input.password !== undefined) await page.getByLabel('Password', { exact: true }).fill(input.password);
  await page
    .getByLabel(/^Files to send/)
    .setInputFiles(input.files.map((f) => ({ name: f.name, mimeType: f.mimeType, buffer: f.buffer })));
  for (const f of input.files) {
    await expect(page.getByRole('list', { name: 'Selected files' }).getByText(f.name)).toBeVisible();
  }
}

/** Sends the filled form and waits for the recap ("Transfer sent" or "Transfer refused"). */
export async function sendTransfer(page: Page, outcome: 'sent' | 'refused' = 'sent'): Promise<void> {
  await page.getByRole('button', { name: 'Send', exact: true }).click();
  const title = outcome === 'sent' ? 'Transfer sent' : 'Transfer refused';
  // Upload, then antivirus analysis (fake clamd): a few seconds at most for the small files used.
  await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible({ timeout: 30_000 });
}

/** Fills and sends a transfer, up to the recap. */
export async function deposit(
  page: Page,
  input: TransferInput,
  outcome: 'sent' | 'refused' = 'sent',
): Promise<void> {
  await fillTransfer(page, input);
  await sendTransfer(page, outcome);
}

/** The link of a mail whose path starts with prefix (e.g. "/d/"), rebased on origin. */
export function mailLink(mail: Mail, prefix: string, origin: string): string {
  for (const link of linksOf(mail)) {
    const url = new URL(link);
    if (url.pathname.startsWith(prefix)) return `${origin}${url.pathname}${url.search}${url.hash}`;
  }
  throw new Error(`no ${prefix} link in mail "${mail.Subject}": ${JSON.stringify(linksOf(mail))}`);
}

/** Clicks what starts a download and returns the downloaded bytes with the suggested name. */
export async function download(
  page: Page,
  trigger: () => Promise<void>,
): Promise<{ name: string; data: Buffer; download: Download }> {
  const [dl] = await Promise.all([page.waitForEvent('download'), trigger()]);
  const file = await dl.path();
  const failure = await dl.failure();
  if (failure !== null) throw new Error(`download failed: ${failure}`);
  return { name: dl.suggestedFilename(), data: fs.readFileSync(file), download: dl };
}
