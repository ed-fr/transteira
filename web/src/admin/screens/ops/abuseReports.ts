// Logic of the abuse reports screen of a tenant (CLAUDE.md section 10, version 1.1), kept out of
// the component so that it is unit tested in Node: category and status labels (the enums are
// extensible: an unknown value is shown as is), who reported, the pseudonym of an erased address,
// the body of the close / reopen request and the list update after it.
import type { components } from '../../../shared/api/schema';
import type { Translate } from '../../../shared/i18n/messages';
import type { StatusVariant } from '../../components/fields';
import type { SelectOption } from '../../components/select';
import { ABUSE_REPORT_STATUSES, type AbuseReportStatus } from './filters';
import { removeItem, replaceItem, type PagedList } from './paging';

/** An abuse report as listed by listAbuseReports. */
export type AbuseReport = components['schemas']['AbuseReport'];
/** Category of an abuse report. */
export type AbuseReportCategory = components['schemas']['AbuseReportCategory'];

/** Maximum length of the note of a closed report (AbuseReportUpdate). */
export const NOTE_MAX_LENGTH = 1000;

/** Categories offered by the download page, in display order. */
export const ABUSE_CATEGORIES: readonly AbuseReportCategory[] = [
  'malware',
  'phishing',
  'illegal_content',
  'spam',
  'unknown_sender',
  'other',
];

/** Label of a category; a category unknown to this version is shown as is. */
export function categoryLabel(category: string, t: Translate): string {
  return (ABUSE_CATEGORIES as readonly string[]).includes(category)
    ? t(`abuse.category.${category}`)
    : category;
}

/** Badge of a report status. */
export function reportStatusView(status: string, t: Translate): { variant: StatusVariant; label: string } {
  if (status === 'open') {
    return { variant: 'warning', label: t('opsAbuse.status.open') };
  }
  if (status === 'closed') {
    return { variant: 'ok', label: t('opsAbuse.status.closed') };
  }
  return { variant: 'info', label: status };
}

/** Pseudonym that replaces an address erased under the GDPR ("erased-<16 hex>"). */
export const ERASED_ADDRESS = /^erased-[0-9a-f]{16}$/;

/** Reports whether an address is the pseudonym of an erased one. */
export function isErasedAddress(address: string): boolean {
  return ERASED_ADDRESS.test(address);
}

/** Text of an address column: the address, or "Erased address" for a pseudonym. */
export function addressText(address: string, t: Translate): string {
  return isErasedAddress(address) ? t('opsAbuse.erasedAddress') : address;
}

/**
 * Who reported: the verified address; else the number of the recipient link used (unverified);
 * else the shared link of a transfer created before 1.1.
 */
export function reporterText(report: AbuseReport, t: Translate): string {
  if (report.reporterVerified && report.reportedBy !== undefined && report.reportedBy !== null) {
    return t('opsAbuse.reporter.verified', { email: addressText(report.reportedBy, t) });
  }
  if (report.recipientIndex !== undefined && report.recipientIndex !== null) {
    return t('opsAbuse.reporter.recipientLink', { n: report.recipientIndex });
  }
  return t('opsAbuse.reporter.sharedLink');
}

/** Options of the status filter: all, then each status. */
export function statusFilterOptions(t: Translate): SelectOption[] {
  return [
    { value: '', label: t('opsAbuse.filters.allStatuses') },
    ...ABUSE_REPORT_STATUSES.map((s) => ({ value: s, label: t(`opsAbuse.status.${s}`) })),
  ];
}

/** Body of the PATCH: closing carries the trimmed note when there is one; reopening never. */
export function updateBody(
  status: AbuseReportStatus,
  note: string,
): components['schemas']['AbuseReportUpdate'] {
  const trimmed = note.trim();
  return status === 'closed' && trimmed !== '' ? { status, note: trimmed } : { status };
}

/** Reports whether the note is too long for the API (counted in code points). */
export function noteTooLong(note: string): boolean {
  return [...note.trim()].length > NOTE_MAX_LENGTH;
}

/** List after an update: the row is replaced, or leaves the list when the filter excludes it. */
export function afterUpdate(
  state: PagedList<AbuseReport>,
  report: AbuseReport,
  status: AbuseReportStatus | undefined,
): PagedList<AbuseReport> {
  return status !== undefined && report.status !== status
    ? removeItem(state, report.id)
    : replaceItem(state, report);
}

/** Result text of the filter bar: number of reports loaded, "or more" when a page remains. */
export function loadedText(count: number, hasMore: boolean, t: Translate): string {
  return t(hasMore ? 'opsAbuse.loadedMore' : 'opsAbuse.loaded', { count });
}
