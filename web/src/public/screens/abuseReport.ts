// Logic of the "Report an abuse" dialog of the download page (CLAUDE.md section 10, version 1.1),
// kept out of the component so that it is unit tested in Node: categories, request body and
// classification of the API errors.
import { ApiProblem } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import type { Translate } from '../../shared/i18n/messages';

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

/** Message key (download.report.errors.*) of a failure. */
export function reportFailureKey(failure: ReportFailure): string {
  return `download.report.errors.${failure.kind === 'not-found' ? 'notFound' : failure.kind === 'rate-limited' ? 'rateLimited' : failure.kind}`;
}
