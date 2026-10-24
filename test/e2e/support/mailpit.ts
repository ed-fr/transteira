// Mailpit helpers: every mail sent by the server under test (tenant SMTP and system SMTP) is
// captured by the Mailpit of the test environment. Tests use unique addresses (data.ts), so
// searching by recipient isolates them from each other without clearing the mailbox.
import { MAILPIT_API } from './env';

/** Summary of a message in a Mailpit search. */
export interface MailSummary {
  ID: string;
  Subject: string;
  Created: string;
  To: { Address: string; Name: string }[];
}

/** A full message. */
export interface Mail {
  ID: string;
  Subject: string;
  Date: string;
  From: { Address: string; Name: string };
  To: { Address: string; Name: string }[];
  Text: string;
  HTML: string;
  Attachments: { FileName: string; ContentType: string; PartID: string }[];
  Inline: { FileName: string; ContentType: string; ContentID: string; PartID: string }[];
}

/** Options of waitForMail. */
export interface WaitMailOptions {
  /** Only messages whose subject matches. */
  subject?: RegExp;
  /** Only messages received at or after this instant (ms since the epoch). */
  after?: number;
  /** Number of matching messages to wait for (default 1); the newest `count` are returned. */
  count?: number;
  timeoutMs?: number;
}

const api = (p: string) => `${MAILPIT_API}/api/v1${p}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Mailpit ${url} -> ${res.status}`);
  return (await res.json()) as T;
}

/** Messages addressed to `to` (newest first). */
export async function listMails(to: string): Promise<MailSummary[]> {
  const q = encodeURIComponent(`to:"${to}"`);
  const res = await getJson<{ messages: MailSummary[] | null }>(api(`/search?query=${q}&limit=200`));
  return res.messages ?? [];
}

/** Reads one message. */
export function getMail(id: string): Promise<Mail> {
  return getJson<Mail>(api(`/message/${id}`));
}

/** Waits for mail(s) to `to` and returns the newest matching ones (newest first). */
export async function waitForMails(to: string, opts: WaitMailOptions = {}): Promise<Mail[]> {
  const deadline = Date.now() + (opts.timeoutMs ?? 30_000);
  const count = opts.count ?? 1;
  for (;;) {
    const matching = (await listMails(to)).filter(
      (m) =>
        (opts.after === undefined || Date.parse(m.Created) >= opts.after) &&
        (opts.subject === undefined || opts.subject.test(m.Subject)),
    );
    if (matching.length >= count) return Promise.all(matching.slice(0, count).map((m) => getMail(m.ID)));
    if (Date.now() > deadline) {
      const seen = (await listMails(to)).map((m) => m.Subject);
      throw new Error(`no mail to ${to} matching ${opts.subject ?? '*'} (seen: ${JSON.stringify(seen)})`);
    }
    await sleep(250);
  }
}

/** Waits for one mail to `to` and returns it. */
export async function waitForMail(to: string, opts: Omit<WaitMailOptions, 'count'> = {}): Promise<Mail> {
  const [mail] = await waitForMails(to, { ...opts, count: 1 });
  return mail!;
}

/** The 6-digit code of a verification mail. */
export function codeOf(mail: Mail): string {
  const m = /\b(\d{6})\b/.exec(mail.Text);
  if (!m) throw new Error(`no 6-digit code in mail "${mail.Subject}"`);
  return m[1]!;
}

/** Waits for the next verification code sent to `to` and returns it. */
export async function waitForCode(to: string, after?: number): Promise<string> {
  return codeOf(await waitForMail(to, { after, subject: /code/i }));
}

/** Every https:// link of the text part (in order, duplicates removed). */
export function linksOf(mail: Mail): string[] {
  const found = mail.Text.match(/https:\/\/[^\s<>"')\]]+/g) ?? [];
  return [...new Set(found)];
}

/** Deletes every message addressed to `to` (cleanup of a test's mailbox). */
export async function deleteMailsTo(to: string): Promise<void> {
  const q = encodeURIComponent(`to:"${to}"`);
  const res = await fetch(api(`/search?query=${q}`), { method: 'DELETE' });
  if (!res.ok) throw new Error(`Mailpit delete for ${to} -> ${res.status}`);
}
