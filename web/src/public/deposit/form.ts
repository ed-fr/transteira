// Pure helpers of the deposit form (CLAUDE.md section 8.2): recipient parsing, client-side
// validation mirroring the server rules (api/openapi.yaml TransferCreate, FileDeclaration), and
// the mapping of validation-failed field errors back to the form.
import type { ProblemFieldError } from '../../shared/api/client';
import { normalizeField } from '../../shared/api/problem';
import type { components } from '../../shared/api/schema';
import { EMAIL_MAX_LENGTH, isEmail } from '../../shared/validation/email';

export { EMAIL_MAX_LENGTH, isEmail };

/** Maximum length of the transfer message (TransferCreate.message). */
export const MESSAGE_MAX_LENGTH = 5000;
/** Maximum number of recipients (TransferCreate.recipients). */
export const MAX_RECIPIENTS = 100;
/** Maximum number of files per transfer (TransferCreate.files). */
export const MAX_FILES = 1000;
/** Maximum length of a file name, in characters (FileDeclaration.name). */
export const FILE_NAME_MAX_LENGTH = 255;
/** Maximum length of the transfer password (TransferCreate.password). */
export const PASSWORD_MAX_LENGTH = 1024;

/** Maximum value of the maximum number of downloads (TransferCreate.maxDownloads). */
export const MAX_DOWNLOADS_LIMIT = 1000;

/** A confidentiality level as offered to senders (GET /tenant). */
export type PublicLevel = components['schemas']['PublicConfidentialityLevel'];
/** Rules of a confidentiality level. */
export type LevelRules = components['schemas']['ConfidentialityRules'];

/** A message to display: a translation key with its parameters. */
export interface Message {
  key: string;
  params?: Record<string, string | number>;
}

/**
 * Splits the recipients field into addresses: separated by commas, semicolons or line breaks,
 * trimmed, "Name <address>" reduced to the address, empty entries dropped, duplicates
 * (case-insensitive) removed while keeping the first spelling and the order.
 */
export function parseRecipients(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of text.split(/[,;\r\n]+/)) {
    let address = part.trim();
    const bracket = /<([^<>]*)>/.exec(address);
    if (bracket !== null) {
      address = (bracket[1] ?? '').trim();
    }
    if (address === '') {
      continue;
    }
    const folded = address.toLowerCase();
    if (!seen.has(folded)) {
      seen.add(folded);
      out.push(address);
    }
  }
  return out;
}

// C0 and C1 controls, and the bidirectional formatting characters the server rejects.
const FORBIDDEN_NAME_CHARS = new RegExp(
  '[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]',
);

/** Field error code of a file name, undefined when the name is acceptable. */
export function fileNameError(name: string): string | undefined {
  const length = [...name].length;
  if (length === 0) {
    return 'required';
  }
  if (length > FILE_NAME_MAX_LENGTH) {
    return 'too-long';
  }
  if (FORBIDDEN_NAME_CHARS.test(name)) {
    return 'invalid-file-name';
  }
  return undefined;
}

/** Identity of a selected file, to avoid adding the same file twice. */
export interface FileIdentity {
  name: string;
  size: number;
  lastModified: number;
}

/** Appends files to a selection, skipping those already selected (same name, size and date). */
export function addFiles<F extends FileIdentity>(current: readonly F[], added: readonly F[]): F[] {
  const out = [...current];
  for (const file of added) {
    const duplicate = out.some(
      (f) => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified,
    );
    if (!duplicate) {
      out.push(file);
    }
  }
  return out;
}

/** Values of the deposit form. */
export interface FormValues<F extends { name: string; size: number }> {
  recipientsText: string;
  message: string;
  expiryDays: number | undefined;
  password: string;
  deleteAfterFirstDownload: boolean;
  files: readonly F[];
}

/** Limits that apply to the form (DepositSession.limits). */
export interface FormLimits {
  maxTransferBytes: number;
  expiryDays: readonly number[];
}

/**
 * Field errors of the form, keyed by dotted path: "recipients", "recipients.<n>" (index in the
 * parsed list), "message", "expiryDays", "password", "files", "files.<n>.name".
 */
export type FormErrors = Record<string, Message>;

function fieldError(code: string, params?: Record<string, string | number>): Message {
  return params === undefined ? { key: `fieldErrors.${code}` } : { key: `fieldErrors.${code}`, params };
}

/**
 * Validates the form before submission. needRecipients is false for an invited external
 * depositor (the files go to the inviter).
 */
export function validateForm<F extends { name: string; size: number }>(
  values: FormValues<F>,
  limits: FormLimits,
  needRecipients: boolean,
): FormErrors {
  const errors: FormErrors = {};
  if (needRecipients) {
    const recipients = parseRecipients(values.recipientsText);
    if (recipients.length === 0) {
      errors['recipients'] = fieldError('required');
    } else if (recipients.length > MAX_RECIPIENTS) {
      errors['recipients'] = { key: 'deposit.form.recipients.tooMany', params: { max: MAX_RECIPIENTS } };
    }
    recipients.forEach((address, i) => {
      if (!isEmail(address)) {
        errors[`recipients.${i}`] = fieldError('invalid-email');
      }
    });
  }
  if (values.message.length > MESSAGE_MAX_LENGTH) {
    errors['message'] = fieldError('too-long');
  }
  if (values.expiryDays === undefined || !limits.expiryDays.includes(values.expiryDays)) {
    errors['expiryDays'] = fieldError('required');
  }
  if (values.password.length > PASSWORD_MAX_LENGTH) {
    errors['password'] = fieldError('too-long');
  }
  const total = values.files.reduce((sum, f) => sum + Math.max(0, f.size), 0);
  if (values.files.length === 0) {
    errors['files'] = { key: 'deposit.form.files.none' };
  } else if (values.files.length > MAX_FILES) {
    errors['files'] = { key: 'deposit.form.files.tooMany', params: { max: MAX_FILES } };
  } else if (total > limits.maxTransferBytes) {
    errors['files'] = { key: 'deposit.form.files.tooLarge' };
  }
  values.files.forEach((file, i) => {
    const code = fileNameError(file.name);
    if (code !== undefined) {
      errors[`files.${i}.name`] = fieldError(code);
    }
  });
  return errors;
}

/** Field error codes the bundle translates; others fall back to fieldErrors.invalid. */
export type HasKey = (key: string) => boolean;

/**
 * Maps the field errors of a validation-failed problem to form errors (same keys as
 * validateForm). Unknown fields are kept under their normalised path; the first error of a
 * field wins.
 */
export function mapServerErrors(errors: readonly ProblemFieldError[] | undefined, has: HasKey): FormErrors {
  const out: FormErrors = {};
  for (const error of errors ?? []) {
    const field = normalizeField(error.field);
    if (Object.hasOwn(out, field)) {
      continue;
    }
    const key = `fieldErrors.${error.code}`;
    out[field] = { key: has(key) ? key : 'fieldErrors.invalid' };
  }
  return out;
}

/** One error of a recipient address, for display. */
export interface RecipientIssue {
  address: string;
  message: Message;
}

/** Errors of individual recipients ("recipients.<n>"), with the address they concern. */
export function recipientIssues(errors: FormErrors, recipients: readonly string[]): RecipientIssue[] {
  const out: RecipientIssue[] = [];
  recipients.forEach((address, i) => {
    const message = errors[`recipients.${i}`];
    if (message !== undefined) {
      out.push({ address, message });
    }
  });
  return out;
}

/** Errors of individual file names ("files.<n>.name" or "files.<n>"), by file index. */
export function fileIssues(errors: FormErrors, count: number): Map<number, Message> {
  const out = new Map<number, Message>();
  for (let i = 0; i < count; i++) {
    const message = errors[`files.${i}.name`] ?? errors[`files.${i}`];
    if (message !== undefined) {
      out.set(i, message);
    }
  }
  return out;
}

/** Ordered list of the form fields that have an error, for the error summary. */
export const FIELD_ORDER = [
  'recipients',
  'message',
  'expiryDays',
  'password',
  'maxDownloads',
  'files',
] as const;

/** A form field of the summary. */
export type FormField = (typeof FIELD_ORDER)[number];

/** Field of the form an error key belongs to ("recipients.2" → recipients, "files.0.name" → files). */
export function fieldOf(path: string): FormField | undefined {
  const head = path.split('.')[0] ?? '';
  return (FIELD_ORDER as readonly string[]).includes(head) ? (head as FormField) : undefined;
}

/** Fields having at least one error, in form order. */
export function invalidFields(errors: FormErrors): FormField[] {
  const set = new Set<FormField>();
  for (const path of Object.keys(errors)) {
    const field = fieldOf(path);
    if (field !== undefined) {
      set.add(field);
    }
  }
  return FIELD_ORDER.filter((f) => set.has(f));
}

/** Default expiry: 7 days when offered, else the first value offered. */
export function defaultExpiry(expiryDays: readonly number[]): number | undefined {
  return expiryDays.includes(7) ? 7 : expiryDays[0];
}

// ---- Confidentiality levels and download limit (version 1.1) -----------------------------

/** The level with the given key, undefined when absent. */
export function levelByKey(levels: readonly PublicLevel[], key: string | undefined): PublicLevel | undefined {
  return key === undefined ? undefined : levels.find((l) => l.key === key);
}

/**
 * Levels a sender can actually use: those that do not require the per-recipient verification
 * while it is unavailable (the server refuses such transfers) and that allow at least one of
 * the durations offered by the session. The order is kept.
 */
export function selectableLevels(
  levels: readonly PublicLevel[],
  sessionDays: readonly number[],
  recipientVerification: boolean,
): PublicLevel[] {
  return levels.filter(
    (l) =>
      (recipientVerification || !l.rules.requireRecipientVerification) &&
      effectiveExpiryDays(sessionDays, l.rules).length > 0,
  );
}

/** The level to preselect: the default one, else the first. */
export function defaultLevel(levels: readonly PublicLevel[]): PublicLevel | undefined {
  return levels.find((l) => l.isDefault) ?? levels[0];
}

/** Durations offered by the form: those of the session that the level also allows. */
export function effectiveExpiryDays(sessionDays: readonly number[], rules: LevelRules | undefined): number[] {
  if (rules === undefined) {
    return [...sessionDays];
  }
  return sessionDays.filter((d) => (rules.allowedExpiryDays as readonly number[]).includes(d));
}

/** Largest value accepted for the maximum number of downloads under the rules. */
export function maxDownloadsCap(rules: LevelRules | undefined): number {
  return Math.min(MAX_DOWNLOADS_LIMIT, rules?.maxDownloads ?? MAX_DOWNLOADS_LIMIT);
}

/** Result of reading the "maximum number of downloads" field. */
export type MaxDownloadsParse = { ok: true; value: number | undefined } | { ok: false; code: string };

/** Reads the field: empty means no limit; otherwise an integer between 1 and the cap. */
export function parseMaxDownloads(
  text: string | number | null | undefined,
  cap = MAX_DOWNLOADS_LIMIT,
): MaxDownloadsParse {
  // A number input bound with bind:value yields a number (or null when empty).
  const trimmed = String(text ?? '').trim();
  if (trimmed === '') {
    return { ok: true, value: undefined };
  }
  if (!/^\d+$/.test(trimmed)) {
    return { ok: false, code: 'invalid' };
  }
  const n = Number(trimmed);
  if (n < 1) {
    return { ok: false, code: 'too-small' };
  }
  if (n > cap) {
    return { ok: false, code: cap < MAX_DOWNLOADS_LIMIT ? 'max-exceeded' : 'too-large' };
  }
  return { ok: true, value: n };
}

/** Value of the delete-after-first-download option once the level is applied. */
export function effectiveDeleteAfterFirst(chosen: boolean, rules: LevelRules | undefined): boolean {
  return chosen || rules?.forceDeleteAfterFirstDownload === true;
}

/** Duration to keep when the offered ones change: the current one when still offered. */
export function keepExpiry(current: number | undefined, offered: readonly number[]): number | undefined {
  return current !== undefined && offered.includes(current) ? current : defaultExpiry(offered);
}

/** Maximum number of downloads to keep when the level changes: clamped to the new cap. */
export function keepMaxDownloads(
  text: string | number | null | undefined,
  rules: LevelRules | undefined,
): string {
  const parsed = parseMaxDownloads(text);
  const cap = rules?.maxDownloads;
  if (parsed.ok && parsed.value !== undefined && cap !== null && cap !== undefined && parsed.value > cap) {
    return String(cap);
  }
  return String(text ?? '');
}

/**
 * Errors of the fields tied to the chosen level and to the download limit: password required by
 * the level, maximum number of downloads (only when the option is offered).
 */
export function validatePolicy(
  password: string,
  maxDownloadsText: string,
  rules: LevelRules | undefined,
  maxDownloadsOffered: boolean,
): FormErrors {
  const errors: FormErrors = {};
  if (rules?.requirePassword === true && password === '') {
    errors['password'] = { key: 'deposit.form.password.requiredByLevel' };
  }
  if (maxDownloadsOffered) {
    const parsed = parseMaxDownloads(maxDownloadsText, maxDownloadsCap(rules));
    if (!parsed.ok) {
      errors['maxDownloads'] =
        parsed.code === 'max-exceeded'
          ? { key: 'deposit.form.maxDownloads.exceeded', params: { max: maxDownloadsCap(rules) } }
          : { key: 'deposit.form.maxDownloads.invalid', params: { max: maxDownloadsCap(rules) } };
    }
  }
  return errors;
}

/**
 * Maps the field errors of a 422 confidentiality-rule-violated problem to form errors: a
 * password required, a duration not allowed, a recipient outside the internal domains, a
 * maximum number of downloads above the cap. Unknown fields are kept under their path.
 */
export function mapRuleErrors(errors: readonly ProblemFieldError[] | undefined): FormErrors {
  const out: FormErrors = {};
  for (const error of errors ?? []) {
    const field = normalizeField(error.field);
    if (Object.hasOwn(out, field)) {
      continue;
    }
    const key = `deposit.form.rules.${error.code}`;
    const known = ['required', 'not-allowed', 'internal-only', 'max-exceeded'].includes(error.code);
    out[field] = { key: known ? key : 'fieldErrors.invalid' };
  }
  return out;
}

/** Maps the field errors of a 403 recipient-domain-refused problem ("/recipients/<i>"). */
export function mapRecipientDomainErrors(errors: readonly ProblemFieldError[] | undefined): FormErrors {
  const out: FormErrors = {};
  for (const error of errors ?? []) {
    out[normalizeField(error.field)] = { key: 'deposit.form.recipients.domainRefused' };
  }
  return out;
}
