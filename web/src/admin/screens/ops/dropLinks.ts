// Logic of the drop link screens (since 2.0, CLAUDE.md section 22), kept out of the components so
// that it is unit tested in Node:
// - status of a link (active, disabled, revoked) and the display order;
// - parsing of the recipients (internal addresses, one per line) and of the form;
// - creation body and merge patch (only the changed fields; a null level means the tenant
//   default);
// - mapping of the API errors (validation-failed pointers, drop-link-limit-reached, state-conflict).
// The token and the URL of a link never go through this module: they are shown once by the
// screen that created or rotated the link.
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import { isEmail, EMAIL_MAX_LENGTH } from '../../../shared/validation/email';
import {
  summaryFromFields,
  type FieldRef,
  type SubmitOutcome,
  type SummaryError,
} from '../../components/form';
import type { StatusVariant } from '../../components/fields';
import { joinLines, parseLineList, type LineError, type LineList, type ParseResult } from '../../forms/lines';
import { isEmptyPatch } from '../../forms/patch';
import { codePointLength } from './filters';
import { expiryFromDate, validateExpiry, type ExpiryError } from './tokens';
import type { Msg, Translate } from '../tenants/network';

/** A drop link as listed (never with its token). */
export type DropLink = components['schemas']['DropLink'];
/** A drop link with its token and URL, in the answers of creation and rotation. */
export type DropLinkCreated = components['schemas']['DropLinkCreated'];
/** Body of the creation of a drop link. */
export type DropLinkCreate = components['schemas']['DropLinkCreate'];
/** Merge patch of a drop link. */
export type DropLinkUpdate = components['schemas']['DropLinkUpdate'];

/** Maximum length of a label (DropLinkCreate.label). */
export const DROP_LABEL_MAX = 100;
/** Maximum number of recipients of a link. */
export const MAX_DROP_RECIPIENTS = 20;
/** Validities offered (ExpiryDays). */
export const VALIDITY_CHOICES = [1, 7, 30] as const;

// ---- Status ---------------------------------------------------------------------------------

/** Status of a drop link. */
export type DropLinkStatus = 'active' | 'disabled' | 'expired' | 'revoked';

/** Status of a link at now: revoked first, then expired, then disabled. */
export function dropLinkStatus(
  link: Pick<DropLink, 'enabled' | 'revokedAt' | 'expiresAt'>,
  now: Date = new Date(),
): DropLinkStatus {
  if (link.revokedAt !== undefined && link.revokedAt !== null) {
    return 'revoked';
  }
  if (link.expiresAt !== undefined && link.expiresAt !== null) {
    const expiry = Date.parse(link.expiresAt);
    if (!Number.isNaN(expiry) && expiry <= now.getTime()) {
      return 'expired';
    }
  }
  return link.enabled ? 'active' : 'disabled';
}

/** Badge of a status (the label always says the status, never the colour alone). */
export function dropStatusView(status: DropLinkStatus): { variant: StatusVariant; key: string } {
  switch (status) {
    case 'active':
      return { variant: 'ok', key: 'opsDropLinks.status.active' };
    case 'expired':
      return { variant: 'warning', key: 'opsDropLinks.status.expired' };
    case 'disabled':
      return { variant: 'warning', key: 'opsDropLinks.status.disabled' };
    default:
      return { variant: 'missing', key: 'opsDropLinks.status.revoked' };
  }
}

/** A revoked link can no longer be edited, rotated, enabled or revoked. */
export function isDropLinkManageable(link: Pick<DropLink, 'enabled' | 'revokedAt'>): boolean {
  return link.revokedAt === undefined || link.revokedAt === null;
}

/** Sorts links for display: active, disabled, expired, then revoked; most recent first. */
export function sortDropLinks(links: readonly DropLink[], now: Date = new Date()): DropLink[] {
  const rank: Record<DropLinkStatus, number> = { active: 0, disabled: 1, expired: 2, revoked: 3 };
  return [...links].sort((a, b) => {
    const r = rank[dropLinkStatus(a, now)] - rank[dropLinkStatus(b, now)];
    return r !== 0 ? r : Date.parse(b.createdAt) - Date.parse(a.createdAt);
  });
}

// ---- Recipients -------------------------------------------------------------------------------

/** Reasons for which a recipient line is refused. */
export type RecipientError = 'email' | 'too-long';

/** Parses a recipient: an e-mail address, normalised to lowercase. */
export function parseDropRecipient(input: string): ParseResult<RecipientError> {
  const s = input.trim().toLowerCase();
  if (s.length > EMAIL_MAX_LENGTH) {
    return { ok: false, error: 'too-long' };
  }
  return isEmail(s) ? { ok: true, value: s } : { ok: false, error: 'email' };
}

/** Parses the recipients text area, one address per line. */
export function parseDropRecipients(text: string): LineList<RecipientError> {
  return parseLineList(text, parseDropRecipient, MAX_DROP_RECIPIENTS);
}

/** Message of an invalid recipient line (without the "Line N:" prefix). */
export function recipientLineMessage(error: LineError<RecipientError>): Msg {
  return {
    key: error.error === 'too-long' ? 'opsDropLinks.errors.recipientTooLong' : 'fieldErrors.invalid-email',
  };
}

// ---- Forms --------------------------------------------------------------------------------------

/** Fields of the creation and edition form. */
export interface DropLinkForm {
  label: string;
  recipientText: string;
  validityDays: number;
  /** Key of the level; '' for the tenant default. */
  level: string;
  enabled: boolean;
  /** Optional last day of the link, a date input value ("YYYY-MM-DD"); '' for no end. */
  expiry: string;
  /** Deposits accepted per hour (number input text), all depositors together. */
  maxDepositsPerHour: string;
}

/** Default and bounds of the hourly cap (DropLinkCreate.maxDepositsPerHour). */
export const DEFAULT_DEPOSITS_PER_HOUR = 20;
export const MIN_DEPOSITS_PER_HOUR = 1;
export const MAX_DEPOSITS_PER_HOUR = 1000;

/** Empty creation form: 7 days, tenant default level, enabled, no end, 20 deposits per hour. */
export function emptyDropLinkForm(): DropLinkForm {
  return {
    label: '',
    recipientText: '',
    validityDays: 7,
    level: '',
    enabled: true,
    expiry: '',
    maxDepositsPerHour: String(DEFAULT_DEPOSITS_PER_HOUR),
  };
}

/** Parses the hourly cap: an integer within bounds, undefined otherwise. */
export function parseDepositsPerHour(text: string): number | undefined {
  const s = text.trim();
  if (!/^\d+$/.test(s)) {
    return undefined;
  }
  const n = Number(s);
  return n >= MIN_DEPOSITS_PER_HOUR && n <= MAX_DEPOSITS_PER_HOUR ? n : undefined;
}

/** Local day ("YYYY-MM-DD") of an API instant; '' for none or invalid. */
export function dateInputFrom(instant: string | null | undefined): string {
  if (instant === undefined || instant === null) {
    return '';
  }
  const d = new Date(instant);
  if (Number.isNaN(d.getTime())) {
    return '';
  }
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Reports whether the creation form holds something typed. */
export function dropFormTouched(form: DropLinkForm): boolean {
  return form.label.trim() !== '' || form.recipientText.trim() !== '';
}

/** Edition form of a link. */
export function dropFormFrom(link: DropLink): DropLinkForm {
  return {
    label: link.label,
    recipientText: joinLines(link.recipients),
    validityDays: link.validityDays,
    level: link.confidentialityLevel ?? '',
    enabled: link.enabled,
    expiry: dateInputFrom(link.expiresAt),
    maxDepositsPerHour: String(link.maxDepositsPerHour),
  };
}

/** Body of the creation: the level only when one is chosen. */
export function dropCreateBody(form: DropLinkForm): DropLinkCreate {
  const body: DropLinkCreate = {
    label: form.label.trim(),
    recipients: [...parseDropRecipients(form.recipientText).values],
    validityDays: form.validityDays as DropLinkCreate['validityDays'],
    enabled: form.enabled,
    maxDepositsPerHour: parseDepositsPerHour(form.maxDepositsPerHour) ?? DEFAULT_DEPOSITS_PER_HOUR,
  };
  if (form.level !== '') {
    body.confidentialityLevel = form.level;
  }
  const expiresAt = expiryFromDate(form.expiry);
  if (expiresAt !== undefined) {
    body.expiresAt = expiresAt;
  }
  return body;
}

/**
 * Merge patch of an edited link: only the changed fields. The level is null when the default is
 * chosen again, the only field where the API accepts null.
 */
export function buildDropLinkPatch(link: DropLink, form: DropLinkForm): DropLinkUpdate {
  const patch: DropLinkUpdate = {};
  const label = form.label.trim();
  if (label !== link.label) {
    patch.label = label;
  }
  const recipients = parseDropRecipients(form.recipientText).values;
  if (recipients.join('\n') !== link.recipients.join('\n')) {
    patch.recipients = [...recipients];
  }
  if (form.validityDays !== link.validityDays) {
    patch.validityDays = form.validityDays as DropLinkUpdate['validityDays'];
  }
  const level = form.level === '' ? null : form.level;
  if (level !== (link.confidentialityLevel ?? null)) {
    patch.confidentialityLevel = level;
  }
  if (form.enabled !== link.enabled) {
    patch.enabled = form.enabled;
  }
  // Days are compared, so an untouched expiry (end of day) never produces a patch.
  if (form.expiry.trim() !== dateInputFrom(link.expiresAt)) {
    const expiresAt = expiryFromDate(form.expiry);
    if (expiresAt !== undefined) {
      patch.expiresAt = expiresAt;
    } else if (form.expiry.trim() === '') {
      patch.expiresAt = null;
    }
  }
  const cap = parseDepositsPerHour(form.maxDepositsPerHour);
  if (cap !== undefined && cap !== link.maxDepositsPerHour) {
    patch.maxDepositsPerHour = cap;
  }
  return patch;
}

/** Reports whether an edition changes nothing. */
export function dropPatchEmpty(patch: DropLinkUpdate): boolean {
  return isEmptyPatch(patch);
}

/** The fields of the form, for the error summary (keys are the API field names). */
export interface DropLinkFields {
  label: FieldRef;
  recipients: FieldRef;
  validityDays: FieldRef;
  confidentialityLevel: FieldRef;
  expiresAt: FieldRef;
  maxDepositsPerHour: FieldRef;
}

const EXPIRY_ERROR_KEYS: Record<ExpiryError, string> = {
  invalid: 'opsDropLinks.errors.expiryInvalid',
  past: 'opsDropLinks.errors.expiryPast',
};

/** Client-side validation of the form; now decides whether the expiry is still to come. */
export function validateDropLink(
  form: DropLinkForm,
  fields: DropLinkFields,
  t: Translate,
  now: Date = new Date(),
): SummaryError[] {
  const out: SummaryError[] = [];
  const add = (ref: FieldRef, msg: Msg): void => {
    out.push({ id: ref.id, label: ref.label, message: t(msg.key, msg.params) });
  };
  const label = form.label.trim();
  if (label === '') {
    add(fields.label, { key: 'fieldErrors.required' });
  } else if (codePointLength(label) > DROP_LABEL_MAX) {
    add(fields.label, { key: 'opsDropLinks.errors.labelTooLong', params: { max: DROP_LABEL_MAX } });
  }
  const list = parseDropRecipients(form.recipientText);
  if (list.errors.length > 0) {
    add(fields.recipients, {
      key: 'adminComponents.lineList.invalidLines',
      params: { count: list.errors.length },
    });
  } else if (list.values.length === 0) {
    add(fields.recipients, { key: 'opsDropLinks.errors.recipientsRequired' });
  } else if (list.tooMany) {
    add(fields.recipients, {
      key: 'opsDropLinks.errors.recipientsTooMany',
      params: { max: MAX_DROP_RECIPIENTS },
    });
  }
  const expiry = validateExpiry(form.expiry, now);
  if (expiry !== undefined) {
    add(fields.expiresAt, { key: EXPIRY_ERROR_KEYS[expiry] });
  }
  if (parseDepositsPerHour(form.maxDepositsPerHour) === undefined) {
    add(fields.maxDepositsPerHour, {
      key: 'opsDropLinks.errors.capInvalid',
      params: { min: MIN_DEPOSITS_PER_HOUR, max: MAX_DEPOSITS_PER_HOUR },
    });
  }
  return out;
}

// ---- Errors -------------------------------------------------------------------------------------

/**
 * Outcome of a failed creation or edition: field errors on their fields (with the general message
 * when some cannot be placed), the limit and the state conflict as general messages.
 */
export function dropLinkErrorOutcome(view: ErrorView, fields: DropLinkFields, t: Translate): SubmitOutcome {
  if (view.code === 'drop-link-limit-reached') {
    return { ok: false, message: t('opsDropLinks.errors.limit') };
  }
  if (view.code === 'state-conflict' || view.status === 409) {
    return { ok: false, message: t('opsDropLinks.errors.conflict') };
  }
  if (view.code === 'validation-failed') {
    const { errors, unmatched } = summaryFromFields(
      view.fields,
      fields as unknown as Record<string, FieldRef>,
    );
    if (errors.length > 0 && unmatched.length === 0) {
      return { ok: false, errors };
    }
    return { ok: false, message: view.message, errors };
  }
  return { ok: false, message: view.message };
}

/** Message of a failed action on a listed link (rotation, revocation): a gone link is said so. */
export function dropActionErrorMessage(view: ErrorView, t: Translate): string {
  if (view.status === 404) {
    return t('opsDropLinks.errors.notFound');
  }
  if (view.code === 'state-conflict' || view.status === 409) {
    return t('opsDropLinks.errors.conflict');
  }
  return view.message;
}

// ---- Levels -------------------------------------------------------------------------------------

/** A confidentiality level of the tenant, as managed by its admins. */
export type TenantLevel = components['schemas']['ConfidentialityLevel'];

/** Label of a level in a language (the key when unknown). */
export function levelLabel(levels: readonly TenantLevel[], key: string, lang: string): string {
  const level = levels.find((l) => l.key === key);
  return level?.labels[lang] ?? level?.labels['en'] ?? key;
}

/** Options of the level select: the tenant default first, then the levels of the tenant. */
export function levelOptions(
  levels: readonly TenantLevel[],
  lang: string,
  defaultLabel: string,
): { value: string; label: string }[] {
  return [
    { value: '', label: defaultLabel },
    ...levels.map((l) => ({ value: l.key, label: levelLabel(levels, l.key, lang) })),
  ];
}

/** The link of a creation or rotation answer, without its token and URL (never kept in a list). */
export function withoutSecret(created: DropLinkCreated): DropLink {
  const { token, url, ...link } = created;
  void token;
  void url;
  return link;
}
