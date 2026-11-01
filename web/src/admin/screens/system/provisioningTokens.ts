// Logic of the provisioning token screen (super admin; CLAUDE.md section 2, version 1.2), kept
// out of the component so that it is unit tested in Node:
// - parsing of the allowed ranges (the catch-all ranges are refused, as by the API) and of the
//   allowed FQDN suffixes (a leading dot and at least two labels, ".transfer.example.com");
// - the volume committed by a token (maxTenants x maxStorageQuotaBytes), shown before the
//   creation is confirmed;
// - creation body with the TOTP or recovery code re-confirmation (the typed code is passed in
//   and never kept here) and client-side validation;
// - mapping of the API errors (400 field errors, 401 wrong code, 429 rate limit).
// The secret of a new token never goes through this module (threat model T-167).
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import type { FieldRef, SubmitOutcome, SummaryError } from '../../components/form';
import { isCatchAll, parseCidr, type CidrError } from '../../forms/cidr';
import { MAX_TRANSFER_BYTES } from '../../forms/bytes';
import { parseDomain } from '../../forms/domain';
import { parseLineList, type LineList, type ParseResult } from '../../forms/lines';
import { normalizeRecoveryCode, normalizeTotpCode, recoveryCodeError, totpCodeError } from '../../auth/views';
import { cidrLineMessage, type Msg, type Translate } from '../tenants/network';
import { codePointLength } from '../ops/filters';
import {
  expiryFromDate,
  lineOfEntry,
  tokenStatus,
  validateExpiry,
  type ExpiryError,
  type TokenStatus,
} from '../ops/tokens';

export { isManageable, prefixLabel, statusView, tokenStatus, todayInput } from '../ops/tokens';
export type { TokenStatus };

/** A provisioning token as listed (never with its secret). */
export type ProvisioningToken = components['schemas']['ProvisioningToken'];
/** Body of the creation of a provisioning token. */
export type ProvisioningTokenCreate = components['schemas']['ProvisioningTokenCreate'];

/** Maximum length of a token name (ProvisioningTokenCreate.name). */
export const NAME_MAX = 100;
/** Maximum number of allowed ranges of a token. */
export const MAX_CIDRS = 100;
/** Maximum number of allowed FQDN suffixes of a token. */
export const MAX_SUFFIXES = 100;
/** Ceiling of the number of tenants of a token accepted by the form (a typing slip guard). */
export const MAX_TENANTS_INPUT = 100000;

// ---- Ranges and suffixes ---------------------------------------------------------------------

/** Reasons for which a range line is refused. */
export type RangeError = CidrError | 'catch-all';

/** Parses a range of a provisioning token: a CIDR, but never 0.0.0.0/0 or ::/0. */
export function parseRange(input: string): ParseResult<RangeError> {
  const r = parseCidr(input);
  if (r.ok && isCatchAll(r.value)) {
    return { ok: false, error: 'catch-all' };
  }
  return r;
}

/** Parses the ranges text area, one range per line. */
export function parseRangeList(text: string): LineList<RangeError> {
  return parseLineList(text, parseRange, MAX_CIDRS);
}

/** Message of an invalid range line (without the "Line N:" prefix). */
export function rangeLineMessage(error: {
  error: RangeError;
  suggestion?: string;
  line: number;
  raw: string;
}): Msg {
  if (error.error === 'catch-all') {
    return { key: 'sysProvisioning.errors.catchAll' };
  }
  return cidrLineMessage({ ...error, error: error.error });
}

/** Reasons for which a suffix line is refused. */
export type SuffixError = 'dot' | 'invalid';

/**
 * Parses an FQDN suffix: a leading dot followed by a domain of at least two labels
 * (".transfer.example.com", not ".com"), normalised like an FQDN (lowercase, punycode). The
 * server normalises again and also refuses the suffixes covering an admin host.
 */
export function parseSuffix(input: string): ParseResult<SuffixError> {
  const s = input.trim().toLowerCase();
  if (!s.startsWith('.')) {
    return { ok: false, error: 'dot' };
  }
  const d = parseDomain(s.slice(1));
  return d.ok ? { ok: true, value: `.${d.value}` } : { ok: false, error: 'invalid' };
}

/** Parses the suffixes text area, one suffix per line. */
export function parseSuffixList(text: string): LineList<SuffixError> {
  return parseLineList(text, parseSuffix, MAX_SUFFIXES);
}

/** Message of an invalid suffix line (without the "Line N:" prefix). */
export function suffixLineMessage(error: { error: SuffixError }): Msg {
  return {
    key: error.error === 'dot' ? 'sysProvisioning.errors.suffixDot' : 'sysProvisioning.errors.suffixInvalid',
  };
}

// ---- Numbers and committed volume -------------------------------------------------------------

/** Parses the maximum number of tenants: a whole number from 1; null when empty or invalid. */
export function parseMaxTenants(text: string): number | null {
  const s = text.trim();
  if (!/^[0-9]+$/.test(s)) {
    return null;
  }
  const n = Number(s);
  return Number.isSafeInteger(n) && n >= 1 ? n : null;
}

/**
 * Volume committed by a token: the highest number of tenants times the highest quota of each,
 * or null while one of them is not valid, or 'large' when the product is not a safe integer. The super admin sees it before confirming.
 */
export function committedBytes(
  maxTenants: number | null,
  maxStorageQuotaBytes: number | null,
): number | 'large' | null {
  if (maxTenants === null || maxStorageQuotaBytes === null) {
    return null;
  }
  const total = maxTenants * maxStorageQuotaBytes;
  return Number.isSafeInteger(total) ? total : 'large';
}

/** Quota cap of a listed token as text ("5 TiB" through format), the tenant counter as "n / max". */
export function tenantsText(token: Pick<ProvisioningToken, 'tenantsCreated' | 'maxTenants'>): string {
  return `${token.tenantsCreated} / ${token.maxTenants}`;
}

// ---- Status and sorting -------------------------------------------------------------------------

/** Sorts tokens for display: active ones first, then by creation date, most recent first. */
export function sortTokens(tokens: readonly ProvisioningToken[], now: Date): ProvisioningToken[] {
  const rank: Record<TokenStatus, number> = { active: 0, expired: 1, revoked: 2 };
  return [...tokens].sort((a, b) => {
    const r = rank[tokenStatus(a, now)] - rank[tokenStatus(b, now)];
    return r !== 0 ? r : Date.parse(b.createdAt) - Date.parse(a.createdAt);
  });
}

// ---- Form ---------------------------------------------------------------------------------------

/** Which confirmation code is typed. */
export type CodeMode = 'totp' | 'recovery';

/** Fields of the creation form. */
export interface CreateForm {
  name: string;
  cidrText: string;
  suffixText: string;
  /** Typed number of tenants. */
  maxTenants: string;
  maxStorageQuotaBytes: number | null;
  /** Optional cap of the per-transfer limit; null for no cap below 20 GiB. */
  maxTransferBytes: number | null;
  /** Date input value ("YYYY-MM-DD"), empty for no expiry. */
  expiry: string;
  mode: CodeMode;
  /** Typed TOTP or recovery code. */
  code: string;
}

/** Empty creation form. */
export function emptyCreateForm(): CreateForm {
  return {
    name: '',
    cidrText: '',
    suffixText: '',
    maxTenants: '',
    maxStorageQuotaBytes: null,
    maxTransferBytes: null,
    expiry: '',
    mode: 'totp',
    code: '',
  };
}

/** Body of the creation: the normalised lists, the optional fields, and the typed code. */
export function createBody(form: CreateForm): ProvisioningTokenCreate {
  const body: ProvisioningTokenCreate = {
    name: form.name.trim(),
    allowedCidrs: [...parseRangeList(form.cidrText).values],
    allowedFqdnSuffixes: [...parseSuffixList(form.suffixText).values],
    maxStorageQuotaBytes: form.maxStorageQuotaBytes ?? 0,
    maxTenants: parseMaxTenants(form.maxTenants) ?? 0,
  };
  if (form.maxTransferBytes !== null) {
    body.maxTransferBytes = form.maxTransferBytes;
  }
  const expiresAt = expiryFromDate(form.expiry);
  if (expiresAt !== undefined) {
    body.expiresAt = expiresAt;
  }
  if (form.mode === 'totp') {
    body.code = normalizeTotpCode(form.code);
  } else {
    body.recoveryCode = normalizeRecoveryCode(form.code);
  }
  return body;
}

/** The fields of the creation form, for the error summary (keys are the API field names). */
export interface ProvisioningFields {
  name: FieldRef;
  allowedCidrs: FieldRef;
  allowedFqdnSuffixes: FieldRef;
  maxTenants: FieldRef;
  maxStorageQuotaBytes: FieldRef;
  maxTransferBytes: FieldRef;
  expiresAt: FieldRef;
  code: FieldRef;
}

function listError(list: LineList<string>): Msg | undefined {
  if (list.errors.length > 0) {
    return { key: 'adminComponents.lineList.invalidLines', params: { count: list.errors.length } };
  }
  if (list.tooMany) {
    return { key: 'fieldErrors.too-many' };
  }
  if (list.values.length === 0) {
    return { key: 'fieldErrors.required' };
  }
  return undefined;
}

function nameError(name: string): Msg | undefined {
  const n = name.trim();
  if (n === '') {
    return { key: 'fieldErrors.required' };
  }
  return codePointLength(n) > NAME_MAX
    ? { key: 'opsTokens.errors.nameTooLong', params: { max: NAME_MAX } }
    : undefined;
}

function tenantsError(text: string): Msg | undefined {
  if (text.trim() === '') {
    return { key: 'fieldErrors.required' };
  }
  const n = parseMaxTenants(text);
  if (n === null || n > MAX_TENANTS_INPUT) {
    return { key: 'sysProvisioning.errors.maxTenants', params: { max: MAX_TENANTS_INPUT } };
  }
  return undefined;
}

function codeFieldError(form: CreateForm): Msg | undefined {
  const e = form.mode === 'totp' ? totpCodeError(form.code) : recoveryCodeError(form.code);
  return e !== undefined && 'key' in e ? e : undefined;
}

function push(out: SummaryError[], ref: FieldRef, msg: Msg | undefined, t: Translate): void {
  if (msg !== undefined) {
    out.push({ id: ref.id, label: ref.label, message: t(msg.key, msg.params) });
  }
}

const EXPIRY_ERROR_KEYS: Record<ExpiryError, string> = {
  invalid: 'opsTokens.errors.expiryInvalid',
  past: 'opsTokens.errors.expiryPast',
};

/**
 * Client-side validation of the creation form, in the order of the form. The size fields check
 * themselves (ByteSizeField): a null storage quota is reported as required here; a null transfer
 * cap is valid (no cap).
 */
export function validateCreate(
  form: CreateForm,
  fields: ProvisioningFields,
  t: Translate,
  now: Date,
): SummaryError[] {
  const out: SummaryError[] = [];
  push(out, fields.name, nameError(form.name), t);
  push(out, fields.allowedCidrs, listError(parseRangeList(form.cidrText)), t);
  push(out, fields.allowedFqdnSuffixes, listError(parseSuffixList(form.suffixText)), t);
  push(out, fields.maxTenants, tenantsError(form.maxTenants), t);
  push(
    out,
    fields.maxStorageQuotaBytes,
    form.maxStorageQuotaBytes === null ? { key: 'fieldErrors.required' } : undefined,
    t,
  );
  const expiry = validateExpiry(form.expiry, now);
  push(out, fields.expiresAt, expiry === undefined ? undefined : { key: EXPIRY_ERROR_KEYS[expiry] }, t);
  push(out, fields.code, codeFieldError(form), t);
  return out;
}

/** Ceiling of the per-transfer cap field. */
export const TRANSFER_CAP_MAX = MAX_TRANSFER_BYTES;

// ---- Errors -------------------------------------------------------------------------------------

/** The text of the lists as sent, to point an API error at its line. */
export interface SentLists {
  cidrText: string;
  suffixText: string;
}

const FIELD_ORDER = [
  'name',
  'allowedCidrs',
  'allowedFqdnSuffixes',
  'maxTenants',
  'maxStorageQuotaBytes',
  'maxTransferBytes',
  'expiresAt',
  'code',
] as const;

/** Field error of a validation-failed answer, with the line of a list entry when it can be told. */
function fieldErrors(
  view: Pick<ErrorView, 'fields'>,
  fields: ProvisioningFields,
  sent: SentLists,
  t: Translate,
): { errors: SummaryError[]; unmatched: string[] } {
  const byField = new Map<string, string>();
  const unmatched: string[] = [];
  for (const [path, error] of Object.entries(view.fields)) {
    const [name, index] = path.split('.') as [string, string | undefined];
    // recoveryCode is typed in the same field as the TOTP code.
    const key = name === 'recoveryCode' ? 'code' : name;
    if (!Object.hasOwn(fields, key)) {
      unmatched.push(path);
      continue;
    }
    if (byField.has(key)) {
      continue;
    }
    let message = error.message;
    if (
      index !== undefined &&
      /^\d+$/.test(index) &&
      (key === 'allowedCidrs' || key === 'allowedFqdnSuffixes')
    ) {
      const line =
        key === 'allowedCidrs'
          ? lineOfEntry(sent.cidrText, parseRange, Number(index))
          : lineOfEntry(sent.suffixText, parseSuffix, Number(index));
      message =
        line === undefined
          ? t('opsTokens.errors.entry', { position: Number(index) + 1, message })
          : t('adminComponents.lineList.lineError', { line, message });
    }
    byField.set(key, message);
  }
  const errors: SummaryError[] = [];
  for (const key of FIELD_ORDER) {
    const message = byField.get(key);
    if (message !== undefined) {
      const ref = fields[key];
      errors.push({ id: ref.id, label: ref.label, message });
    }
  }
  return { errors, unmatched };
}

/**
 * Outcome of a failed creation: a wrong code (401) on the code field, with the attempts left
 * when the server says; field errors of a 400 on their fields (with a general message when some
 * cannot be placed); otherwise the general message (the rate limit says when to retry).
 */
export function createErrorOutcome(
  view: ErrorView,
  fields: ProvisioningFields,
  sent: SentLists,
  t: Translate,
): SubmitOutcome {
  if (view.code === 'invalid-credentials' || view.status === 401) {
    const base = t('adminAuth.totp.invalid');
    const message =
      view.attemptsRemaining === undefined
        ? base
        : `${base} ${t('adminAuth.totp.attemptsRemaining', { count: view.attemptsRemaining })}`;
    return {
      ok: false,
      errors: [{ id: fields.code.id, label: fields.code.label, message }],
    };
  }
  if (view.code === 'validation-failed') {
    const { errors, unmatched } = fieldErrors(view, fields, sent, t);
    if (errors.length > 0 && unmatched.length === 0) {
      return { ok: false, errors };
    }
    return { ok: false, message: view.message, errors };
  }
  return { ok: false, message: view.message };
}

/** Message of a failed revocation (the dialog stays open and shows it). */
export function revokeErrorMessage(view: ErrorView, t: Translate): string {
  return view.status === 404 ? t('sysProvisioning.errors.notFound') : view.message;
}
