// Logic of the transfer screens of a tenant (TransferList, TransferDetail), kept out of the
// components so that it is unit tested in Node: validation of the filter form, badges and labels
// of the extensible enums (status, origin, antivirus result; an unknown value shows its raw text
// with a neutral badge), row summaries, the resend body and the mapping of the API errors of the
// resend and delete actions.
//
// The API never returns the download link of a transfer nor the content of its files: these
// screens show metadata only.
import type { components } from '../../../shared/api/schema';
import type { ErrorView } from '../../../shared/api/problem';
import type { StatusVariant } from '../../components/fields';
import type { SelectOption } from '../../components/select';
import { tenantPath } from '../../shell';
import { filterErrors, filterIssueMessage, formatWait, type Translate } from './common';
import {
  AUDIT_FILTERS,
  TRANSFER_FILTERS,
  TRANSFER_STATUSES,
  formToFilters,
  instantToDay,
  pathWithFilters,
  validateFilters,
  type FilterForm,
} from './filters';

/** A transfer of the list (AdminTransfer). */
export type TransferSummary = components['schemas']['AdminTransfer'];
/** A transfer with its files (AdminTransferDetail). */
export type TransferDetail = components['schemas']['AdminTransferDetail'];
/** One file of a transfer. */
export type TransferFile = TransferDetail['files'][number];
/** Body of a resend request. */
export type ResendBody = components['schemas']['ResendRequest'];
/** Body of a deletion (optional reason). */
export type DeleteBody = components['schemas']['AdminReason'];

export type { Translate };
export { instantToDay };

/** Maximum length of the deletion reason (AdminReason.reason). */
export const REASON_MAX_LENGTH = 500;

/** Number of recipients shown in a list row before "+N". */
export const RECIPIENTS_SHOWN = 2;

// ---- Filters ---------------------------------------------------------------------------------

/** Form of the transfer filters (every field, "" when not set). */
export type TransferFilterForm = Required<FilterForm<typeof TRANSFER_FILTERS>>;
/** Field of the transfer filter form. */
export type TransferFilterField = keyof typeof TRANSFER_FILTERS & string;

/** Outcome of the validation of the filter form. */
export type FilterSubmit =
  | { ok: true; path: string }
  | { ok: false; errors: Partial<Record<TransferFilterField, string>>; first: TransferFilterField };

/**
 * Validates the filter form: the path to navigate to (the list path with the filter query), or
 * a message per invalid field and the first invalid field (to focus).
 */
export function submitFilters(listPath: string, form: TransferFilterForm, t: Translate): FilterSubmit {
  const failed = filterErrors(
    validateFilters(TRANSFER_FILTERS, form),
    (issue) => filterIssueMessage(issue.code, t),
    (issue) => issue.field,
  );
  if (failed !== undefined) {
    return { ok: false, ...failed };
  }
  return {
    ok: true,
    path: pathWithFilters(listPath, TRANSFER_FILTERS, formToFilters(TRANSFER_FILTERS, form) ?? {}),
  };
}

/** Options of the status filter: "any status" first, then every status. */
export function statusOptions(t: Translate): SelectOption[] {
  return [
    { value: '', label: t('opsTransfers.list.statusAny') },
    ...TRANSFER_STATUSES.map((s) => ({ value: s, label: statusView(s, t).label })),
  ];
}

/** Text under the filters: number of transfers shown, and whether more can be loaded. */
export function resultText(count: number, hasMore: boolean, t: Translate): string {
  return hasMore ? t('opsTransfers.list.loadedMore', { count }) : t('opsTransfers.list.loaded', { count });
}

// ---- Labels and badges -----------------------------------------------------------------------

/** Badge of a status: variant and visible label. */
export interface BadgeView {
  variant: StatusVariant;
  label: string;
}

const STATUS_VARIANTS: Readonly<Record<string, StatusVariant>> = {
  uploading: 'info',
  scanning: 'info',
  available: 'ok',
  rejected: 'error',
  expired: 'warning',
  deleted: 'info',
};

const SCAN_VARIANTS: Readonly<Record<string, StatusVariant>> = {
  pending: 'info',
  scanning: 'info',
  clean: 'ok',
  infected: 'error',
  not_scanned_too_large: 'warning',
  not_scanned_encrypted: 'warning',
  not_scanned_disabled: 'warning',
  scan_error: 'error',
};

const ORIGINS: readonly string[] = ['internal', 'external', 'api', 'internal_remote', 'reply'];

/** Badge of a transfer status; an unknown status shows its raw value with a neutral badge. */
export function statusView(status: string, t: Translate): BadgeView {
  return Object.hasOwn(STATUS_VARIANTS, status)
    ? { variant: STATUS_VARIANTS[status] as StatusVariant, label: t(`opsTransfers.status.${status}`) }
    : { variant: 'info', label: status };
}

/** Badge of an antivirus result; an unknown result shows its raw value with a neutral badge. */
export function scanView(scanStatus: string, t: Translate): BadgeView {
  return Object.hasOwn(SCAN_VARIANTS, scanStatus)
    ? { variant: SCAN_VARIANTS[scanStatus] as StatusVariant, label: t(`opsTransfers.scan.${scanStatus}`) }
    : { variant: 'info', label: scanStatus };
}

/** Label of an origin; an unknown origin shows its raw value. */
export function originLabel(origin: string, t: Translate): string {
  return ORIGINS.includes(origin) ? t(`opsTransfers.origin.${origin}`) : origin;
}

/** Recipients of a list row: the first ones, and the number of the others. */
export interface RecipientsSummary {
  shown: string[];
  more: number;
  /** "a@example.com, b@example.com +3". */
  text: string;
}

/** Summary of the recipients of a list row (the first RECIPIENTS_SHOWN, then "+N"). */
export function recipientsSummary(
  recipients: readonly string[],
  t: Translate,
  max: number = RECIPIENTS_SHOWN,
): RecipientsSummary {
  const shown = recipients.slice(0, Math.max(0, max));
  const more = recipients.length - shown.length;
  const head = shown.join(', ');
  const text = more > 0 ? t('opsTransfers.list.moreRecipients', { list: head, count: more }) : head;
  return { shown, more, text };
}

/** "3 files, 12 GiB". */
export function filesText(
  count: number,
  bytes: number,
  t: Translate,
  formatBytes: (n: number) => string,
): string {
  return t('opsTransfers.list.filesSize', { count, size: formatBytes(bytes) });
}

/** A date, or the fallback text when there is none (no expiry, never downloaded). */
export function dateOr(
  value: string | null | undefined,
  fallback: string,
  formatDate: (d: string) => string,
): string {
  return value === null || value === undefined || value === '' ? fallback : formatDate(value);
}

/** Who or what created the transfer: an invitation or an API token, when known. */
export type CreatedVia = { kind: 'invitation'; id: string } | { kind: 'token'; id: string } | undefined;

/** Invitation or API token through which the transfer was created. */
export function createdVia(transfer: Pick<TransferSummary, 'invitationId' | 'apiTokenId'>): CreatedVia {
  if (transfer.invitationId !== undefined && transfer.invitationId !== '') {
    return { kind: 'invitation', id: transfer.invitationId };
  }
  if (transfer.apiTokenId !== undefined && transfer.apiTokenId !== '') {
    return { kind: 'token', id: transfer.apiTokenId };
  }
  return undefined;
}

/** Sender IP of a transfer, or the "unknown" text (older transfers have none). */
export function senderIpText(ip: string | null | undefined, t: Translate): string {
  return ip === null || ip === undefined || ip === '' ? t('opsTransfers.detail.unknownIp') : ip;
}

// ---- Paths -----------------------------------------------------------------------------------

/** Path of the detail screen of a transfer. */
export function detailPath(tenantId: string, transferId: string): string {
  return `${tenantPath(tenantId, 'transfers')}/${encodeURIComponent(transferId)}`;
}

/**
 * Path of the audit log around a transfer. The audit filters have no "object" filter: the link
 * opens the log from the day the transfer was created (the admin finds the transfer id in the
 * object column).
 */
export function auditPath(tenantId: string, createdAt: string, timeZone?: string): string {
  const from = instantToDay(createdAt, timeZone);
  return pathWithFilters(tenantPath(tenantId, 'audit'), AUDIT_FILTERS, from === undefined ? {} : { from });
}

// ---- Actions ---------------------------------------------------------------------------------

/** The notification can be resent (available transfers only). */
export function canResend(status: string): boolean {
  return status === 'available';
}

/** The transfer can be deleted (not ended yet). */
export function canDelete(status: string): boolean {
  return status !== 'expired' && status !== 'deleted';
}

/**
 * Body of a resend: undefined (all recipients) when every recipient is selected, else the
 * selected recipients in their original order. Undefined as well when none is selected (check
 * with hasSelection first).
 */
export function resendBody(
  recipients: readonly string[],
  selected: Readonly<Record<string, boolean>>,
): ResendBody | undefined {
  const chosen = recipients.filter((r) => selected[r] === true);
  if (chosen.length === 0 || chosen.length === recipients.length) {
    return undefined;
  }
  return { recipients: chosen };
}

/** Number of selected recipients. */
export function selectedCount(
  recipients: readonly string[],
  selected: Readonly<Record<string, boolean>>,
): number {
  return recipients.filter((r) => selected[r] === true).length;
}

/** Selection with every recipient checked. */
export function selectAll(recipients: readonly string[]): Record<string, boolean> {
  return Object.fromEntries(recipients.map((r) => [r, true]));
}

/** Display of a failed resend. */
export interface ResendFailure {
  kind: 'not-recipient' | 'not-available' | 'rate-limited' | 'mail-unavailable' | 'other';
  /** Message (for rate-limited, without the remaining wait: see rateLimitedText). */
  message: string;
  /** Seconds before a new attempt (rate-limited). */
  retryAfterSeconds?: number;
}

/** Maps a resend error: 400 non-original recipient, 409 not available, 429 rate limit, 503 no SMTP. */
export function resendFailure(view: ErrorView, t: Translate): ResendFailure {
  if (view.status === 400 && view.code === 'validation-failed') {
    return { kind: 'not-recipient', message: t('opsTransfers.resend.errors.notRecipient') };
  }
  if (view.status === 409) {
    return { kind: 'not-available', message: t('opsTransfers.resend.errors.notAvailable') };
  }
  if (view.status === 429) {
    const out: ResendFailure = {
      kind: 'rate-limited',
      message: t('opsTransfers.resend.errors.rateLimitedNoDelay'),
    };
    if (view.retryAfterSeconds !== undefined && view.retryAfterSeconds > 0) {
      out.retryAfterSeconds = view.retryAfterSeconds;
    }
    return out;
  }
  if (view.status === 503 || view.code === 'mail-unavailable') {
    return { kind: 'mail-unavailable', message: t('opsTransfers.resend.errors.mailUnavailable') };
  }
  return { kind: 'other', message: view.message };
}

/** Rate limit message with the remaining wait (0: the wait is over). */
export function rateLimitedText(remaining: number, t: Translate): string {
  return remaining > 0
    ? t('opsTransfers.resend.errors.rateLimited', { wait: formatWait(remaining, t) })
    : t('opsTransfers.resend.errors.rateLimitedOver');
}

/** Body of a deletion: the trimmed reason, or undefined when empty. */
export function deleteBody(reason: string): DeleteBody | undefined {
  const trimmed = reason.trim();
  return trimmed === '' ? undefined : { reason: trimmed };
}

/** Message of a failed deletion: 409 upload in progress (with the delay), 404 gone, 400 reason. */
export function deleteFailure(view: ErrorView, t: Translate): string {
  if (view.status === 409) {
    return view.retryAfterSeconds !== undefined && view.retryAfterSeconds > 0
      ? t('opsTransfers.delete.errors.uploading', { wait: formatWait(view.retryAfterSeconds, t) })
      : t('opsTransfers.delete.errors.uploadingNoDelay');
  }
  if (view.status === 404) {
    return t('opsTransfers.delete.errors.notFound');
  }
  if (view.status === 400) {
    return view.fields['reason']?.message ?? view.message;
  }
  return view.message;
}

/** Download tracking of one recipient (RecipientTracking), since 1.1. */
export type RecipientTracking = components['schemas']['RecipientTracking'];

/** One line of a recipient's downloads: a file name (or the ZIP archive label) with counts and dates. */
export type TrackedDownload = { key: string; label: string; count: number; firstAt: string; lastAt: string };

/**
 * Lines of the downloads of one recipient. A null or missing file id is the ZIP archive; a file id
 * missing from the transfer's files (should not happen) falls back to the id itself.
 */
export function trackedDownloads(
  tracking: RecipientTracking,
  files: readonly { id: string; name: string }[],
  archiveLabel: string,
): TrackedDownload[] {
  const names = new Map(files.map((f) => [f.id, f.name]));
  return tracking.downloads.map((d) => ({
    key: d.fileId ?? '',
    label: d.fileId == null ? archiveLabel : (names.get(d.fileId) ?? d.fileId),
    count: d.count,
    firstAt: d.firstAt,
    lastAt: d.lastAt,
  }));
}
