// Steps of the public interface shared by the public scenarios (specs/public-*.spec.ts):
// identification by code (read in Mailpit), the deposit form, the download page and mail links.
import { expect, type Download, type Locator, type Page } from '@playwright/test';
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

/** Opens the "Security options" disclosure of the deposit form (no-op when already open). */
export async function openSecurity(page: Page): Promise<void> {
  const trigger = page.getByRole('button', { name: /^Security options/ });
  if ((await trigger.getAttribute('aria-expanded')) !== 'true') await trigger.click();
  await expect(trigger).toHaveAttribute('aria-expanded', 'true');
}

/**
 * Sets one of the security switches of the deposit form (opens the disclosure first). A switch
 * locked by the level or the organisation must already be in the requested state.
 */
export async function setOption(page: Page, name: string | RegExp, on: boolean): Promise<void> {
  await openSecurity(page);
  const option = page.getByRole('switch', { name });
  if (await option.isDisabled()) {
    if (on) await expect(option).toBeChecked();
    else await expect(option).not.toBeChecked();
    return;
  }
  if (on) await option.check();
  else await option.uncheck();
}

/** The row of a file in the file list of the download page. */
export function fileItem(page: Page, name: string | RegExp): Locator {
  return page
    .getByRole('list', { name: 'Files of this transfer' })
    .getByRole('listitem')
    .filter({ hasText: name });
}

/** Types recipients in the chips field (joined with ", ") and commits the last one with Enter. */
export async function addRecipients(page: Page, recipients: string[]): Promise<void> {
  const field = page.getByRole('textbox', { name: /^Recipients/ });
  await field.fill(recipients.join(', '));
  await field.press('Enter');
  await expect(field).toHaveValue('');
}

/** Fills the deposit form (without sending it). */
export async function fillTransfer(page: Page, input: TransferInput): Promise<void> {
  // The recipients are joined with ", ": the field commits an address at each separator and the
  // last one is committed with Enter. (Left as a draft it would be committed by the blur caused
  // by the next click, which moves the layout under the mouse: see public-redesign.spec.ts.)
  if (input.recipients) await addRecipients(page, input.recipients);
  if (input.message !== undefined) await page.getByLabel(/^Message/).fill(input.message);
  if (input.password !== undefined) {
    await openSecurity(page);
    const toggle = page.getByRole('switch', { name: 'Protect with a password' });
    if (!(await toggle.isDisabled()) && !(await toggle.isChecked())) await toggle.check();
    await page.locator('#tt-deposit-password').fill(input.password);
  }
  await page
    .getByLabel(/^Files to send/)
    .setInputFiles(input.files.map((f) => ({ name: f.name, mimeType: f.mimeType, buffer: f.buffer })));
  for (const f of input.files) {
    await expect(page.getByRole('list', { name: 'Selected files' }).getByText(f.name)).toBeVisible();
  }
}

/** Sends the filled form and waits for the recap ("Transfer sent" or "Transfer refused"). */
export async function sendTransfer(page: Page, outcome: 'sent' | 'refused' = 'sent'): Promise<void> {
  await page.getByRole('button', { name: /^Send(\s|$)/ }).click();
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

/** Checks that the download page of a transfer of count files is shown. */
export async function expectDownloadPage(page: Page, count?: number): Promise<void> {
  const name =
    count === undefined ? /^\d+ files? for you$/ : count === 1 ? '1 file for you' : `${count} files for you`;
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}
