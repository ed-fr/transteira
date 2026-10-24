// Logic of the data subject rights screen of a tenant (Privacy, CLAUDE.md section 20), kept out
// of the component so that it is unit tested in Node: client check of the address, request body,
// summary and report rows, mapping of the API errors and link to the audit log. The address is
// sent in a POST body only: it never goes into the URL, the browser storage or an announcement
// (T-168).
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import { EMAIL_MAX_LENGTH, isEmail } from '../../../shared/validation/email';
import type { FieldRef, SubmitOutcome, SummaryError } from '../../components/form';
import { tenantPath } from '../../shell';
import { formatWait } from './common';
import type { Translate } from '../../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** Body of a search or erasure request. */
export type DataSubjectRequest = components['schemas']['DataSubjectRequest'];
/** Counts of the data held for an address. */
export type DataSubjectSummary = components['schemas']['DataSubjectSummary'];
/** Counts of what an erasure did. */
export type DataSubjectEraseReport = components['schemas']['DataSubjectEraseReport'];

/** Formats a count in the interface language. */
export type FormatCount = (n: number) => string;

/** Audit action recorded by an erasure (its object is the pseudonym). */
export const ERASED_ACTION = 'data_subject.erased';

/**
 * What an erasure keeps on purpose (docs/operations/admin.md, "What is kept"): translation keys
 * of the list shown in the confirmation dialog.
 */
export const KEPT_KEYS: readonly string[] = [
  'opsPrivacy.erase.kept.blocklist',
  'opsPrivacy.erase.kept.tokenSenders',
  'opsPrivacy.erase.kept.auditIps',
  'opsPrivacy.erase.kept.queuedMails',
  'opsPrivacy.erase.kept.backups',
];

/** What an erasure removes: translation keys of the list shown in the confirmation dialog. */
export const ERASED_KEYS: readonly string[] = [
  'opsPrivacy.erase.erased.verified',
  'opsPrivacy.erase.erased.sent',
  'opsPrivacy.erase.erased.received',
  'opsPrivacy.erase.erased.invitations',
  'opsPrivacy.erase.erased.audit',
];

/** Address as sent to the API: surrounding spaces removed. */
export function normalizeAddress(input: string): string {
  return input.trim();
}

/** Body of a search or erasure request. */
export function requestBody(input: string): DataSubjectRequest {
  return { email: normalizeAddress(input) };
}

/** Client check of the address field: required, at most 254 characters, a bare address. */
export function validateAddress(input: string, ref: FieldRef, t: Translate): SummaryError[] {
  const value = normalizeAddress(input);
  let message: string | undefined;
  if (value === '') {
    message = t('fieldErrors.required');
  } else if (value.length > EMAIL_MAX_LENGTH) {
    message = t('fieldErrors.too-long');
  } else if (!isEmail(value)) {
    message = t('fieldErrors.invalid-email');
  }
  return message === undefined ? [] : [{ id: ref.id, label: ref.label, message }];
}

/** A row of a definition list: what is counted and its value. */
export interface CountRow {
  /** Stable id (key of the list). */
  id: string;
  term: string;
  value: string;
}

/** Reports whether the summary finds any data linked to the address in the tenant. */
export function hasData(summary: DataSubjectSummary): boolean {
  return (
    summary.verifiedAddress ||
    summary.transfersAsSender > 0 ||
    summary.transfersAsRecipient > 0 ||
    summary.invitations > 0 ||
    summary.auditEvents > 0
  );
}

/**
 * Rows of the search summary. The security log count is left out: it is always 0, since that
 * log never records addresses (the screen says so in a note).
 */
export function summaryRows(summary: DataSubjectSummary, t: Translate, format: FormatCount): CountRow[] {
  return [
    {
      id: 'verifiedAddress',
      term: t('opsPrivacy.summary.verifiedAddress'),
      value: summary.verifiedAddress ? t('opsPrivacy.yes') : t('opsPrivacy.no'),
    },
    {
      id: 'transfersAsSender',
      term: t('opsPrivacy.summary.transfersAsSender'),
      value: format(summary.transfersAsSender),
    },
    {
      id: 'transfersAsRecipient',
      term: t('opsPrivacy.summary.transfersAsRecipient'),
      value: format(summary.transfersAsRecipient),
    },
    { id: 'invitations', term: t('opsPrivacy.summary.invitations'), value: format(summary.invitations) },
    { id: 'auditEvents', term: t('opsPrivacy.summary.auditEvents'), value: format(summary.auditEvents) },
  ];
}

/** Rows of the erasure report. */
export function reportRows(report: DataSubjectEraseReport, t: Translate, format: FormatCount): CountRow[] {
  return [
    {
      id: 'verifiedAddressDeleted',
      term: t('opsPrivacy.report.verifiedAddressDeleted'),
      value: report.verifiedAddressDeleted ? t('opsPrivacy.yes') : t('opsPrivacy.no'),
    },
    {
      id: 'transfersDeleted',
      term: t('opsPrivacy.report.transfersDeleted'),
      value: format(report.transfersDeleted),
    },
    {
      id: 'recipientEntriesRemoved',
      term: t('opsPrivacy.report.recipientEntriesRemoved'),
      value: format(report.recipientEntriesRemoved),
    },
    {
      id: 'invitationsDeleted',
      term: t('opsPrivacy.report.invitationsDeleted'),
      value: format(report.invitationsDeleted),
    },
    {
      id: 'logEntriesPseudonymised',
      term: t('opsPrivacy.report.logEntriesPseudonymised'),
      value: format(report.logEntriesPseudonymised),
    },
  ];
}

/**
 * Outcome of a failed search: a validation-failed problem on the email field goes to the field;
 * anything else (404, network...) gives the general message.
 */
export function searchFailure(view: ErrorView, ref: FieldRef, t: Translate): SubmitOutcome {
  if (view.code === 'validation-failed') {
    const field = view.fields['email'];
    if (field !== undefined) {
      const message = field.code === 'invalid-email' ? t('fieldErrors.invalid-email') : field.message;
      return { ok: false, errors: [{ id: ref.id, label: ref.label, message }] };
    }
  }
  return { ok: false, message: view.message };
}

/**
 * Message of a failed erasure, shown in the confirmation dialog:
 * - 409 state-conflict: an upload of the address is in progress; what was erased stays erased,
 *   repeat after the delay (Retry-After) to complete the erasure;
 * - 400 validation-failed on the address: the message of its code;
 * - anything else: the general message.
 */
export function eraseFailure(view: ErrorView, t: Translate): string {
  if (view.status === 409 && view.code === 'state-conflict') {
    const seconds = view.retryAfterSeconds;
    return seconds !== undefined && seconds > 0
      ? t('opsPrivacy.erase.conflict', { wait: formatWait(seconds, t) })
      : t('opsPrivacy.erase.conflictNow');
  }
  if (view.code === 'validation-failed') {
    const field = view.fields['email'];
    if (field !== undefined) {
      return field.code === 'invalid-email' ? t('fieldErrors.invalid-email') : field.message;
    }
  }
  return view.message;
}

/** Text the admin must type to confirm the erasure: the exact address searched. */
export function confirmTextFor(searched: string): string {
  return normalizeAddress(searched);
}

/** Path of the audit log of the tenant filtered on the erasures (the pseudonym is their object). */
export function auditLinkPath(tenantId: string): string {
  return `${tenantPath(tenantId, 'audit')}?action=${encodeURIComponent(ERASED_ACTION)}`;
}
