// Logic of the API token screens (CLAUDE.md section 16.4), kept out of the components so that it
// is unit tested in Node:
// - status of a token (active, expired, revoked) at a given instant;
// - parsing of the allowed senders (a full address or a mail domain) and the "any address"
//   shortcut of the allowed ranges;
// - conversion and validation of the optional expiry date;
// - creation body and merge patch (only the changed fields; an empty sender list is sent as []
//   to lift the restriction);
// - mapping of the API errors (field pointers such as /allowedCidrs/3 to the line of the list,
//   409 on a revoked token).
// The secret of a new token never goes through this module (threat model T-167).
import type { components } from '../../../shared/api/schema';
import type { ErrorView } from '../../../shared/api/problem';
import { isEmail, EMAIL_MAX_LENGTH } from '../../../shared/validation/email';
import type { FieldRef, SubmitOutcome, SummaryError } from '../../components/form';
import type { StatusVariant } from '../../components/fields';
import { CATCH_ALL_CIDRS, isCatchAll, parseCidr, type CidrError } from '../../forms/cidr';
import { parseDomain } from '../../forms/domain';
import {
  joinLines,
  parseLineList,
  splitLines,
  type LineError,
  type LineList,
  type ParseResult,
} from '../../forms/lines';
import { buildPatch } from '../../forms/patch';
import { cidrLineMessage, type Msg, type Translate } from '../tenants/network';
import { codePointLength } from './filters';

/** An API token as listed (never with its secret). */
export type ApiToken = components['schemas']['ApiToken'];
/** Body of the creation of a token. */
export type ApiTokenCreate = components['schemas']['ApiTokenCreate'];
/** Merge patch of a token. */
export type ApiTokenUpdate = components['schemas']['ApiTokenUpdate'];

/** Maximum length of a token name (ApiTokenCreate.name). */
export const TOKEN_NAME_MAX = 100;
/** Maximum number of allowed ranges of a token (AllowedCidrs). */
export const MAX_TOKEN_CIDRS = 100;
/** Maximum number of allowed senders of a token (AllowedSenders). */
export const MAX_TOKEN_SENDERS = 100;
/** Maximum length of one allowed sender entry. */
export const SENDER_MAX_LENGTH = EMAIL_MAX_LENGTH;

// ---- Status ---------------------------------------------------------------------------------

/** Status of a token at a given instant. */
export type TokenStatus = 'active' | 'expired' | 'revoked';

/** Status of token at now: revoked first, then expired once its expiry is reached. */
export function tokenStatus(token: Pick<ApiToken, 'expiresAt' | 'revokedAt'>, now: Date): TokenStatus {
  if (token.revokedAt !== undefined && token.revokedAt !== null) {
    return 'revoked';
  }
  if (token.expiresAt !== undefined && token.expiresAt !== null) {
    const expiry = Date.parse(token.expiresAt);
    if (!Number.isNaN(expiry) && expiry <= now.getTime()) {
      return 'expired';
    }
  }
  return 'active';
}

/** Badge of a status (the label always says the status, never the colour alone). */
export function statusView(status: TokenStatus): { variant: StatusVariant; key: string } {
  switch (status) {
    case 'active':
      return { variant: 'ok', key: 'opsTokens.status.active' };
    case 'expired':
      return { variant: 'warning', key: 'opsTokens.status.expired' };
    default:
      return { variant: 'missing', key: 'opsTokens.status.revoked' };
  }
}

/** Reports whether a token can still be edited or revoked from the screen. */
export function isManageable(token: Pick<ApiToken, 'expiresAt' | 'revokedAt'>, now: Date): boolean {
  return tokenStatus(token, now) === 'active';
}

/** Prefix shown in the list ("tt_EXAM…"): the token is never shown again in full. */
export function prefixLabel(prefix: string): string {
  return `${prefix}…`;
}

/** Sorts tokens for display: active ones first, then by creation date, most recent first. */
export function sortTokens(tokens: readonly ApiToken[], now: Date): ApiToken[] {
  const rank: Record<TokenStatus, number> = { active: 0, expired: 1, revoked: 2 };
  return [...tokens].sort((a, b) => {
    const r = rank[tokenStatus(a, now)] - rank[tokenStatus(b, now)];
    return r !== 0 ? r : Date.parse(b.createdAt) - Date.parse(a.createdAt);
  });
}

// ---- Allowed senders --------------------------------------------------------------------------

/** Reasons for which a sender entry is refused. */
export type SenderError = 'email' | 'domain' | 'too-long';

/**
 * Parses an allowed sender: a full address (normalised to lowercase, with the domain checked as
 * a mail domain) or a mail domain (as parseDomain). The server normalises again (punycode) and
 * remains authoritative.
 */
export function parseSender(input: string): ParseResult<SenderError> {
  const s = input.trim();
  if (codePointLength(s) > SENDER_MAX_LENGTH) {
    return { ok: false, error: 'too-long' };
  }
  const at = s.lastIndexOf('@');
  if (at < 0) {
    const d = parseDomain(s);
    if (d.ok) {
      return d;
    }
    return d.suggestion !== undefined
      ? { ok: false, error: 'domain', suggestion: d.suggestion }
      : { ok: false, error: 'domain' };
  }
  const lower = s.toLowerCase();
  const domain = parseDomain(lower.slice(at + 1));
  if (!isEmail(lower) || !domain.ok) {
    return { ok: false, error: 'email' };
  }
  return { ok: true, value: `${lower.slice(0, at)}@${domain.value}` };
}

/** Parses the senders text area, one entry per line. */
export function parseSenderList(text: string): LineList<SenderError> {
  return parseLineList(text, parseSender, MAX_TOKEN_SENDERS);
}

/** Parses the ranges text area of a token, one range per line. */
export function parseTokenCidrList(text: string): LineList<CidrError> {
  return parseLineList(text, parseCidr, MAX_TOKEN_CIDRS);
}

const SENDER_ERROR_KEYS: Record<SenderError, string> = {
  email: 'opsTokens.errors.sender.email',
  domain: 'opsTokens.errors.sender.domain',
  'too-long': 'opsTokens.errors.sender.tooLong',
};

/** Message of an invalid sender line (without the "Line N:" prefix). */
export function senderLineMessage(error: LineError<SenderError>): Msg {
  if (error.error === 'domain' && error.suggestion !== undefined) {
    return { key: 'opsTokens.errors.sender.domainSuggestion', params: { domain: error.suggestion } };
  }
  return { key: SENDER_ERROR_KEYS[error.error] };
}

/** Message of an invalid range line (the messages of the network screen). */
export function tokenCidrLineMessage(error: LineError<CidrError>): Msg {
  return cidrLineMessage(error);
}

// ---- "Any address" ------------------------------------------------------------------------------

/** Reports whether the ranges allow any address of a family (0.0.0.0/0 or ::/0). */
export function hasAnyAddress(cidrs: readonly string[]): boolean {
  return cidrs.some(isCatchAll);
}

/**
 * Reports whether the ranges hold both catch-all ranges (0.0.0.0/0 and ::/0): the "Any address"
 * shortcut has nothing left to add.
 */
export function hasAllAnyAddress(cidrs: readonly string[]): boolean {
  return CATCH_ALL_CIDRS.every((c) => cidrs.includes(c));
}

/**
 * Adds the two catch-all ranges to the ranges text area (shortcut "Any address"), keeping the
 * lines already typed and skipping a catch-all range already present.
 */
export function withAnyAddress(text: string): string {
  const present = new Set(
    splitLines(text)
      .map((l) => parseCidr(l))
      .flatMap((r) => (r.ok ? [r.value] : [])),
  );
  const kept = splitLines(text).filter((l) => l.trim() !== '');
  const added = CATCH_ALL_CIDRS.filter((c) => !present.has(c));
  return joinLines([...kept, ...added]);
}

// ---- Expiry -------------------------------------------------------------------------------------

/** Reasons for which an expiry date is refused. */
export type ExpiryError = 'invalid' | 'past';

const DATE_INPUT = /^(\d{4})-(\d{2})-(\d{2})$/;

/** End of the given day (23:59:59 local time) of a date input value, or undefined when invalid. */
function endOfDay(value: string): Date | undefined {
  const m = DATE_INPUT.exec(value);
  if (m === null) {
    return undefined;
  }
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(y, mo - 1, d, 23, 59, 59, 0);
  if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) {
    return undefined;
  }
  return date;
}

/**
 * Expiry sent to the API for a date input value ("YYYY-MM-DD"): the end of that day in local
 * time, as an ISO date-time; undefined for an empty or invalid value.
 */
export function expiryFromDate(value: string): string | undefined {
  return endOfDay(value.trim())?.toISOString();
}

/** Checks an optional expiry date: empty is fine (no expiry), otherwise a valid future day. */
export function validateExpiry(value: string, now: Date): ExpiryError | undefined {
  const v = value.trim();
  if (v === '') {
    return undefined;
  }
  const date = endOfDay(v);
  if (date === undefined) {
    return 'invalid';
  }
  return date.getTime() <= now.getTime() ? 'past' : undefined;
}

/** Value of the min attribute of the date input: today, local time ("YYYY-MM-DD"). */
export function todayInput(now: Date): string {
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
}

// ---- Forms --------------------------------------------------------------------------------------

/** Fields of the creation form. */
export interface CreateForm {
  name: string;
  cidrText: string;
  senderText: string;
  /** Date input value ("YYYY-MM-DD"), empty for no expiry. */
  expiry: string;
}

/** Fields of the edition form (the expiry cannot be changed). */
export interface EditForm {
  name: string;
  cidrText: string;
  senderText: string;
}

/** Empty creation form. */
export function emptyCreateForm(): CreateForm {
  return { name: '', cidrText: '', senderText: '', expiry: '' };
}

/** Reports whether the creation form holds something typed. */
export function createFormTouched(form: CreateForm): boolean {
  return [form.name, form.cidrText, form.senderText, form.expiry].some((v) => v.trim() !== '');
}

/** Edition form of a token. */
export function editFormFrom(token: ApiToken): EditForm {
  return {
    name: token.name,
    cidrText: joinLines(token.allowedCidrs),
    senderText: joinLines(token.allowedSenders),
  };
}

/** Body of the creation: the normalised lists, and the expiry when one is chosen. */
export function createBody(form: CreateForm): ApiTokenCreate {
  const body: ApiTokenCreate = {
    name: form.name.trim(),
    allowedCidrs: [...parseTokenCidrList(form.cidrText).values],
    allowedSenders: [...parseSenderList(form.senderText).values],
  };
  const expiresAt = expiryFromDate(form.expiry);
  if (expiresAt !== undefined) {
    body.expiresAt = expiresAt;
  }
  return body;
}

/**
 * Merge patch of an edited token: only the fields that changed. An emptied sender list is sent
 * as [] (any internal address again); the ranges are never sent empty (validation refuses it).
 */
export function buildTokenPatch(token: ApiToken, form: EditForm): ApiTokenUpdate {
  const edited = {
    name: form.name.trim(),
    allowedCidrs: [...parseTokenCidrList(form.cidrText).values],
    allowedSenders: [...parseSenderList(form.senderText).values],
  };
  const original = {
    name: token.name,
    allowedCidrs: token.allowedCidrs,
    allowedSenders: token.allowedSenders,
  };
  return buildPatch(original, edited, ['name', 'allowedCidrs', 'allowedSenders']);
}

/** The fields of the token forms, for the error summary (keys are the API field names). */
export interface TokenFields {
  name: FieldRef;
  allowedCidrs: FieldRef;
  allowedSenders: FieldRef;
  expiresAt?: FieldRef;
}

/** Error of one list, or undefined when it can be saved. */
function listError(list: LineList<string>, required: boolean): Msg | undefined {
  if (list.errors.length > 0) {
    return { key: 'adminComponents.lineList.invalidLines', params: { count: list.errors.length } };
  }
  if (list.tooMany) {
    return { key: 'fieldErrors.too-many' };
  }
  if (required && list.values.length === 0) {
    return { key: 'opsTokens.errors.cidrsRequired' };
  }
  return undefined;
}

function nameError(name: string): Msg | undefined {
  const n = name.trim();
  if (n === '') {
    return { key: 'fieldErrors.required' };
  }
  if (codePointLength(n) > TOKEN_NAME_MAX) {
    return { key: 'opsTokens.errors.nameTooLong', params: { max: TOKEN_NAME_MAX } };
  }
  return undefined;
}

function push(out: SummaryError[], ref: FieldRef | undefined, msg: Msg | undefined, t: Translate): void {
  if (ref !== undefined && msg !== undefined) {
    out.push({ id: ref.id, label: ref.label, message: t(msg.key, msg.params) });
  }
}

/** Client-side validation of the edition form. */
export function validateEdit(form: EditForm, fields: TokenFields, t: Translate): SummaryError[] {
  const out: SummaryError[] = [];
  push(out, fields.name, nameError(form.name), t);
  push(out, fields.allowedCidrs, listError(parseTokenCidrList(form.cidrText), true), t);
  push(out, fields.allowedSenders, listError(parseSenderList(form.senderText), false), t);
  return out;
}

const EXPIRY_ERROR_KEYS: Record<ExpiryError, string> = {
  invalid: 'opsTokens.errors.expiryInvalid',
  past: 'opsTokens.errors.expiryPast',
};

/** Client-side validation of the creation form; now decides whether the expiry is in the future. */
export function validateCreate(
  form: CreateForm,
  fields: TokenFields,
  t: Translate,
  now: Date,
): SummaryError[] {
  const out = validateEdit(form, fields, t);
  const expiry = validateExpiry(form.expiry, now);
  push(out, fields.expiresAt, expiry === undefined ? undefined : { key: EXPIRY_ERROR_KEYS[expiry] }, t);
  return out;
}

// ---- Errors -------------------------------------------------------------------------------------

/**
 * Line (from 1) of the text area holding the entry at index of the list sent to the API, which
 * is the list of the valid, deduplicated values in order; undefined when out of range.
 */
export function lineOfEntry<E extends string>(
  text: string,
  parse: (raw: string) => ParseResult<E>,
  index: number,
): number | undefined {
  const seen = new Set<string>();
  const lines = splitLines(text);
  for (let i = 0; i < lines.length; i++) {
    const raw = (lines[i] as string).trim();
    if (raw === '') {
      continue;
    }
    const r = parse(raw);
    if (!r.ok || seen.has(r.value)) {
      continue;
    }
    if (seen.size === index) {
      return i + 1;
    }
    seen.add(r.value);
  }
  return undefined;
}

/** The text of the lists as sent, to point an API error at its line. */
export interface SentLists {
  cidrText: string;
  senderText: string;
}

const LIST_FIELDS = {
  allowedCidrs: { parse: parseCidr, text: (s: SentLists) => s.cidrText },
  allowedSenders: { parse: parseSender, text: (s: SentLists) => s.senderText },
} as const;

/**
 * Error summary of a validation-failed answer: a field pointer names a field ("name"), or one
 * entry of a list ("allowedCidrs.3"), which is then pointed at by its line in the text area.
 * Paths without a field of the form are returned in unmatched, for a general message.
 */
export function tokenFieldErrors(
  view: Pick<ErrorView, 'fields'>,
  fields: TokenFields,
  sent: SentLists,
  t: Translate,
): { errors: SummaryError[]; unmatched: string[] } {
  const byField = new Map<keyof TokenFields, string>();
  const unmatched: string[] = [];
  for (const [path, error] of Object.entries(view.fields)) {
    const [name, index] = path.split('.') as [string, string | undefined];
    const ref = Object.hasOwn(fields, name) ? fields[name as keyof TokenFields] : undefined;
    if (ref === undefined) {
      unmatched.push(path);
      continue;
    }
    if (byField.has(name as keyof TokenFields)) {
      continue;
    }
    let message = error.message;
    const list = Object.hasOwn(LIST_FIELDS, name) ? LIST_FIELDS[name as keyof typeof LIST_FIELDS] : undefined;
    if (list !== undefined && index !== undefined && /^\d+$/.test(index)) {
      const line = lineOfEntry(list.text(sent), list.parse, Number(index));
      message =
        line === undefined
          ? t('opsTokens.errors.entry', { position: Number(index) + 1, message })
          : t('adminComponents.lineList.lineError', { line, message });
    }
    byField.set(name as keyof TokenFields, message);
  }
  const errors: SummaryError[] = [];
  for (const key of ['name', 'allowedCidrs', 'allowedSenders', 'expiresAt'] as const) {
    const ref = fields[key];
    const message = byField.get(key);
    if (ref !== undefined && message !== undefined) {
      errors.push({ id: ref.id, label: ref.label, message });
    }
  }
  return { errors, unmatched };
}

/**
 * Outcome of a failed creation or edition: field errors on their fields (with a general message
 * when some cannot be placed), "token revoked" on a 409, otherwise the general message.
 */
export function tokenErrorOutcome(
  view: ErrorView,
  fields: TokenFields,
  sent: SentLists,
  t: Translate,
): SubmitOutcome {
  if (view.code === 'state-conflict' || view.status === 409) {
    return { ok: false, message: t('opsTokens.errors.revoked') };
  }
  if (view.code === 'validation-failed') {
    const { errors, unmatched } = tokenFieldErrors(view, fields, sent, t);
    if (errors.length > 0 && unmatched.length === 0) {
      return { ok: false, errors };
    }
    return { ok: false, message: view.message, errors };
  }
  return { ok: false, message: view.message };
}

/** Message of a failed revocation (the dialog stays open and shows it). */
export function revokeErrorMessage(view: ErrorView, t: Translate): string {
  if (view.status === 404) {
    return t('opsTokens.errors.notFound');
  }
  return view.message;
}

/** Text of the allowed senders column: the entries, or "internal domains" when empty. */
export function sendersText(token: Pick<ApiToken, 'allowedSenders'>, t: Translate): string {
  return token.allowedSenders.length === 0 ? t('opsTokens.list.anySender') : token.allowedSenders.join(', ');
}
