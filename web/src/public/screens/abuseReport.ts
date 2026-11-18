// Logic of the "Report an abuse" dialog of the download page (CLAUDE.md section 10, version 1.1)
// and, since 2.3, of the read page of an express secret (section 22.2, reportSecretAbuse), kept
// out of the component so that it is unit tested in Node: categories, request body, request and
// classification of the API errors. A report never carries the key nor the text of a secret: only
// the token of its link (in the path), the category and the reporter's message (threat model
// T-399, T-407).
import { ApiProblem, type ApiClient } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import type { Translate } from '../../shared/i18n/messages';

/** What is reported: a transfer (download link) or, since 2.3, an express secret (secret link). */
export type ReportTarget = 'transfer' | 'secret';

/** Category of an abuse report. */
export type AbuseCategory = components['schemas']['AbuseReportCategory'];

/** Categories offered, in display order. */
export const ABUSE_CATEGORIES: readonly AbuseCategory[] = [
  'malware',
  'phishing',
  'illegal_content',
  'spam',
  'unknown_sender',
  'other',
];

/** Maximum length of the message, in characters (AbuseReportCreate). */
export const ABUSE_MESSAGE_MAX = 1000;

/** Radio options of the categories, labelled in the active language. */
export function categoryOptions(t: Translate): { value: AbuseCategory; label: string }[] {
  return ABUSE_CATEGORIES.map((value) => ({ value, label: t(`abuse.category.${value}`) }));
}

/** Length of the message in code points, as counted by the API. */
export function messageLength(message: string): number {
  return [...message].length;
}

/** Reports whether the message is within the limit. */
export function messageFits(message: string): boolean {
  return messageLength(message.trim()) <= ABUSE_MESSAGE_MAX;
}

/** Body of the POST: the category and the trimmed message when there is one. */
export function reportBody(
  category: AbuseCategory,
  message: string,
): components['schemas']['AbuseReportCreate'] {
  const trimmed = message.trim();
  return trimmed === '' ? { category } : { category, message: trimmed };
}

/** Sends the report of the transfer or express secret whose link token is token. */
export async function sendAbuseReport(
  api: Pick<ApiClient, 'post'>,
  target: ReportTarget,
  token: string,
  body: components['schemas']['AbuseReportCreate'],
): Promise<void> {
  if (target === 'secret') {
    await api.post('/secret-links/{secretToken}/abuse-reports', { path: { secretToken: token }, body });
  } else {
    await api.post('/downloads/{linkToken}/abuse-reports', { path: { linkToken: token }, body });
  }
}

/** Message key of the introduction of the dialog. */
export function reportIntroKey(target: ReportTarget): string {
  return target === 'secret' ? 'secret.reveal.report.intro' : 'download.report.intro';
}

/** Outcome of a failed report. */
export type ReportFailure =
  | { kind: 'rate-limited' }
  | { kind: 'not-found' }
  | { kind: 'gone' }
  | { kind: 'invalid' }
  | { kind: 'error' };

/** Classifies the error of a report: 429, 404, 410, 400, anything else. */
export function reportFailure(err: unknown): ReportFailure {
  if (err instanceof ApiProblem) {
    switch (err.status) {
      case 429:
        return { kind: 'rate-limited' };
      case 404:
        return { kind: 'not-found' };
      case 410:
        return { kind: 'gone' };
      case 400:
        return { kind: 'invalid' };
    }
  }
  return { kind: 'error' };
}

/**
 * Message key of a failure: download.report.errors.*, except the end of an express secret
 * (secret.reveal.report.gone).
 */
export function reportFailureKey(failure: ReportFailure, target: ReportTarget = 'transfer'): string {
  if (target === 'secret' && failure.kind === 'gone') {
    return 'secret.reveal.report.gone';
  }
  return `download.report.errors.${failure.kind === 'not-found' ? 'notFound' : failure.kind === 'rate-limited' ? 'rateLimited' : failure.kind}`;
}
