// Filters of the tenant operation lists (transfers, invitations, blocklist, audit log), reflected
// in the URL query string so that a filtered list can be bookmarked, shared and restored by the
// back button. A filter spec maps each filter field to its kind; the functions below read the
// filters from the URL (dropping anything invalid, never throwing), write them back in a stable
// order, validate the filter form and build the query parameters of the API call.
//
// Date filters come from <input type="date"> (YYYY-MM-DD, a calendar day of the admin) and are
// sent to the API as RFC 3339 instants in UTC: a "start" bound (createdAfter, from) becomes the
// first millisecond of that day, an "end" bound (to, inclusive) its last millisecond
// (23:59:59.999), both in the time zone of the admin (the browser's, or the timeZone option).
import type { components } from '../../../shared/api/schema';
// The same light email check as the deposit form (bare address, at most 254 characters, no
// display name): the server has the final word.
import { EMAIL_MAX_LENGTH, isEmail } from '../../../shared/validation/email';

export { EMAIL_MAX_LENGTH, isEmail };

/** A filter restricted to a closed list of values (an enum of the specification). */
export interface EnumFilter<V extends string = string> {
  kind: 'enum';
  values: readonly V[];
}

/** A filter on an email address (Email: bare address, at most 254 characters). */
export interface EmailFilter {
  kind: 'email';
}

/** A free text filter, trimmed, with a maximum length in characters and an optional pattern. */
export interface TextFilter {
  kind: 'text';
  maxLength: number;
  pattern?: RegExp;
}

/**
 * A calendar day (YYYY-MM-DD) sent as an instant: the start of the day for a "start" bound, the
 * end of the day for an "end" bound (inclusive).
 */
export interface DateFilter {
  kind: 'date';
  bound: 'start' | 'end';
}

/** One filter field. */
export type FilterField = EnumFilter | EmailFilter | TextFilter | DateFilter;

/** A filter spec: filter name (also the URL and API parameter name) to field, in display order. */
export type FilterSpec = Readonly<Record<string, FilterField>>;

/** Value type of a filter field: one of the enum values, else a string. */
export type FilterValue<F> = F extends EnumFilter<infer V> ? V : string;

/** Filters of a spec: every field optional, absent when not set. */
export type Filters<S extends FilterSpec> = { -readonly [K in keyof S]?: FilterValue<S[K]> };

/** Raw values of the filter form (the text of each input; empty means "no filter"). */
export type FilterForm<S extends FilterSpec> = { [K in keyof S]?: string };

/** Code of a filter form error (the fieldErrors key, except "range"). */
export type FilterIssueCode = 'invalid-email' | 'invalid-format' | 'too-long' | 'range';

/** A client-side error of a filter field. */
export interface FilterIssue<S extends FilterSpec = FilterSpec> {
  field: keyof S & string;
  code: FilterIssueCode;
}

/** Default page size of the lists (Limit: 1 to 200). */
export const DEFAULT_LIMIT = 50;
/** Maximum page size accepted by the API. */
export const MAX_LIMIT = 200;
/** Maximum length of the actor filter of the audit log. */
export const ACTOR_MAX_LENGTH = 320;
/** Maximum length of an audit action (AuditAction). */
export const ACTION_MAX_LENGTH = 64;
/** Form of an audit action (AuditAction): "domain.verb". */
export const ACTION_PATTERN = /^[a-z_]+\.[a-z_]+$/;

/** Status of a transfer. */
export type TransferStatus = components['schemas']['TransferStatus'];
/** Status of an invitation. */
export type InvitationStatus = components['schemas']['InvitationStatus'];
/** Kind of a blocklist entry. */
export type BlocklistKind = components['schemas']['BlocklistKind'];

/** Values of TransferStatus. */
export const TRANSFER_STATUSES: readonly TransferStatus[] = [
  'uploading',
  'scanning',
  'available',
  'rejected',
  'expired',
  'deleted',
];
/** Values of InvitationStatus. */
export const INVITATION_STATUSES: readonly InvitationStatus[] = ['pending', 'used', 'expired', 'revoked'];
/** Values of BlocklistKind. */
export const BLOCKLIST_KINDS: readonly BlocklistKind[] = ['email', 'domain', 'sha256'];

/** Filters of listTenantTransfers. */
export const TRANSFER_FILTERS = {
  status: { kind: 'enum', values: TRANSFER_STATUSES } as EnumFilter<TransferStatus>,
  email: { kind: 'email' } as EmailFilter,
  createdAfter: { kind: 'date', bound: 'start' } as DateFilter,
} satisfies FilterSpec;

/** Filters of listTenantInvitations. */
export const INVITATION_FILTERS = {
  status: { kind: 'enum', values: INVITATION_STATUSES } as EnumFilter<InvitationStatus>,
} satisfies FilterSpec;

/** Filters of listBlocklist. */
export const BLOCKLIST_FILTERS = {
  kind: { kind: 'enum', values: BLOCKLIST_KINDS } as EnumFilter<BlocklistKind>,
} satisfies FilterSpec;

/** Filters of listTenantAuditEvents (from and to inclusive). */
export const AUDIT_FILTERS = {
  action: { kind: 'text', maxLength: ACTION_MAX_LENGTH, pattern: ACTION_PATTERN } as TextFilter,
  actor: { kind: 'text', maxLength: ACTOR_MAX_LENGTH } as TextFilter,
  from: { kind: 'date', bound: 'start' } as DateFilter,
  to: { kind: 'date', bound: 'end' } as DateFilter,
} satisfies FilterSpec;

/** Filters of the transfer list. */
export type TransferFilters = Filters<typeof TRANSFER_FILTERS>;
/** Filters of the invitation list. */
export type InvitationFilters = Filters<typeof INVITATION_FILTERS>;
/** Filters of the blocklist. */
export type BlocklistFilters = Filters<typeof BLOCKLIST_FILTERS>;
/** Filters of the audit log. */
export type AuditFilters = Filters<typeof AUDIT_FILTERS>;

// ---- Dates -----------------------------------------------------------------------------------

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** A calendar day. */
interface Day {
  year: number;
  month: number;
  day: number;
}

/** Parses a YYYY-MM-DD calendar day (years 1000 to 9999); undefined when not a real day. */
function parseDay(value: string): Day | undefined {
  const m = DAY.exec(value);
  if (m === null) {
    return undefined;
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (year < 1000) {
    return undefined;
  }
  const check = new Date(0);
  check.setUTCFullYear(year, month - 1, day);
  if (check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) {
    return undefined;
  }
  return { year, month, day };
}

/** Reports whether a value is a real calendar day in the YYYY-MM-DD form. */
export function isDay(value: string): boolean {
  return parseDay(value) !== undefined;
}

/** Numeric date and time parts of an instant in the time zone of format. */
function zoneParts(format: Intl.DateTimeFormat, instant: number): Record<string, number> {
  const parts: Record<string, number> = {};
  for (const part of format.formatToParts(new Date(instant))) {
    if (part.type !== 'literal') {
      parts[part.type] = Number(part.value);
    }
  }
  return parts;
}

/** Offset of a time zone from UTC at an instant, in milliseconds (local wall time minus UTC). */
function zoneOffset(format: Intl.DateTimeFormat, instant: number): number {
  const parts = zoneParts(format, instant);
  const wall = Date.UTC(
    parts['year'] as number,
    (parts['month'] as number) - 1,
    parts['day'] as number,
    (parts['hour'] as number) % 24,
    parts['minute'] as number,
    parts['second'] as number,
  );
  return wall - Math.floor(instant / 1000) * 1000;
}

/** Numeric date and time format in timeZone (undefined: the browser's); undefined when unknown. */
function zoneFormat(timeZone: string | undefined): Intl.DateTimeFormat | undefined {
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
  } catch {
    return undefined;
  }
}

/**
 * Instant (milliseconds since the epoch) of the first millisecond of a day in a time zone: the
 * browser's when timeZone is undefined or unknown. A midnight skipped by a daylight saving change
 * gives the first instant after the gap.
 */
function startOfDay(d: Day, timeZone: string | undefined): number {
  const format = timeZone === undefined ? undefined : zoneFormat(timeZone);
  if (format === undefined) {
    const local = new Date(0);
    local.setFullYear(d.year, d.month - 1, d.day);
    local.setHours(0, 0, 0, 0);
    return local.getTime();
  }
  const utc = new Date(0);
  utc.setUTCFullYear(d.year, d.month - 1, d.day);
  const wall = utc.getTime();
  const offset1 = zoneOffset(format, wall);
  const first = wall - offset1;
  const offset2 = zoneOffset(format, first);
  if (offset2 === offset1) {
    return first;
  }
  const second = wall - offset2;
  // Midnight does not exist that day (daylight saving gap): the later candidate is the first
  // instant after the gap.
  return zoneOffset(format, second) === offset2 ? second : Math.max(first, second);
}

/**
 * Converts a YYYY-MM-DD day to an RFC 3339 instant in UTC: the first millisecond of the day
 * ("start") or its last one ("end", 23:59:59.999), in timeZone (an IANA name, default the
 * browser's time zone). Undefined when the value is not a real day.
 */
export function dayToInstant(value: string, bound: 'start' | 'end', timeZone?: string): string | undefined {
  const d = parseDay(value);
  if (d === undefined) {
    return undefined;
  }
  if (bound === 'start') {
    return new Date(startOfDay(d, timeZone)).toISOString();
  }
  const next = new Date(0);
  next.setUTCFullYear(d.year, d.month - 1, d.day + 1);
  const nextDay: Day = { year: next.getUTCFullYear(), month: next.getUTCMonth() + 1, day: next.getUTCDate() };
  return new Date(startOfDay(nextDay, timeZone) - 1).toISOString();
}

/**
 * Calendar day (YYYY-MM-DD) of an RFC 3339 instant in timeZone (an IANA name; the browser's
 * time zone when undefined or unknown). Undefined when the instant is invalid.
 */
export function instantToDay(instant: string, timeZone?: string): string | undefined {
  const time = new Date(instant).getTime();
  if (Number.isNaN(time)) {
    return undefined;
  }
  const format = zoneFormat(timeZone) ?? (zoneFormat(undefined) as Intl.DateTimeFormat);
  const parts = zoneParts(format, time);
  const pad = (n: number | undefined, width: number): string => String(n ?? 0).padStart(width, '0');
  return `${pad(parts['year'], 4)}-${pad(parts['month'], 2)}-${pad(parts['day'], 2)}`;
}

// ---- Parsing and serialisation ---------------------------------------------------------------

/** Characters of a value (code points), as counted by the maxLength of the specification. */
export function codePointLength(value: string): number {
  return [...value].length;
}

/** Normalised value of a field, or an issue code when the (trimmed, non-empty) value is invalid. */
function check(field: FilterField, raw: string): { value: string } | { code: FilterIssueCode } {
  const value = raw.trim();
  switch (field.kind) {
    case 'enum':
      return field.values.includes(value) ? { value } : { code: 'invalid-format' };
    case 'email':
      return isEmail(value) ? { value } : { code: 'invalid-email' };
    case 'text':
      if (codePointLength(value) > field.maxLength) {
        return { code: 'too-long' };
      }
      return field.pattern === undefined || field.pattern.test(value)
        ? { value }
        : { code: 'invalid-format' };
    case 'date':
      return isDay(value) ? { value } : { code: 'invalid-format' };
  }
}

function keys<S extends FilterSpec>(spec: S): (keyof S & string)[] {
  return Object.keys(spec) as (keyof S & string)[];
}

/**
 * Reads the filters of spec from a URL query string: unknown parameters, empty values and
 * invalid values are dropped (an outdated or edited link shows the unfiltered list instead of
 * an error). A "start" date after an "end" date drops both. Never throws.
 */
export function parseFilters<S extends FilterSpec>(spec: S, query: URLSearchParams | string): Filters<S> {
  const params = typeof query === 'string' ? new URLSearchParams(query) : query;
  const out: Record<string, string> = {};
  for (const name of keys(spec)) {
    const raw = params.get(name);
    if (raw === null || raw.trim() === '') {
      continue;
    }
    const result = check(spec[name] as FilterField, raw);
    if ('value' in result) {
      out[name] = result.value;
    }
  }
  if (rangeIssues(spec, out).length > 0) {
    for (const name of keys(spec)) {
      if ((spec[name] as FilterField).kind === 'date') {
        delete out[name];
      }
    }
  }
  return out as Filters<S>;
}

/**
 * Query string of the filters (without "?"), in the order of the spec, empty values omitted:
 * the same filters always give the same string. Values are written as given (use parseFilters
 * or validateFilters first).
 */
export function filtersToQuery<S extends FilterSpec>(spec: S, filters: Filters<S>): string {
  const params = new URLSearchParams();
  for (const name of keys(spec)) {
    const value = (filters as Record<string, string | undefined>)[name];
    if (value !== undefined && value !== '') {
      params.set(name, value);
    }
  }
  return params.toString();
}

/** Application path with the query string of the filters ("/tenants/x/transfers?status=..."). */
export function pathWithFilters<S extends FilterSpec>(path: string, spec: S, filters: Filters<S>): string {
  const qs = filtersToQuery(spec, filters);
  return qs === '' ? path : `${path}?${qs}`;
}

/** Options of filtersToApiParams. */
export interface ApiParamsOptions {
  /** IANA time zone of the date filters, default the browser's. */
  timeZone?: string;
  /** Page size, default 50 (clamped to 1..200). */
  limit?: number;
  /** Cursor of the next page. */
  cursor?: string;
}

/**
 * Query parameters of an API list call: each filter typed with its value (the enum values of an
 * enum filter, a string otherwise), so that the result is accepted as is by the typed client.
 */
export type ApiParams<S extends FilterSpec> = { -readonly [K in keyof S]?: FilterValue<S[K]> } & {
  limit: number;
  cursor?: string;
};

/**
 * Query parameters of the list operation: the filters (dates converted to RFC 3339 instants in
 * UTC, see dayToInstant; invalid values dropped), the page size (default 50) and the cursor.
 */
export function filtersToApiParams<S extends FilterSpec>(
  spec: S,
  filters: Filters<S>,
  options: ApiParamsOptions = {},
): ApiParams<S> {
  const out: Record<string, string | number> = {};
  for (const name of keys(spec)) {
    const raw = (filters as Record<string, string | undefined>)[name];
    if (raw === undefined || raw.trim() === '') {
      continue;
    }
    const field = spec[name] as FilterField;
    const result = check(field, raw);
    if (!('value' in result)) {
      continue;
    }
    if (field.kind === 'date') {
      out[name] = dayToInstant(result.value, field.bound, options.timeZone) as string;
    } else {
      out[name] = result.value;
    }
  }
  const limit = options.limit ?? DEFAULT_LIMIT;
  out['limit'] = Number.isFinite(limit) ? Math.min(MAX_LIMIT, Math.max(1, Math.trunc(limit))) : DEFAULT_LIMIT;
  if (options.cursor !== undefined && options.cursor !== '') {
    out['cursor'] = options.cursor;
  }
  return out as ApiParams<S>;
}

function rangeIssues<S extends FilterSpec>(spec: S, values: Record<string, string>): FilterIssue<S>[] {
  const starts = keys(spec).filter((n) => {
    const f = spec[n] as FilterField;
    return f.kind === 'date' && f.bound === 'start' && values[n] !== undefined;
  });
  const issues: FilterIssue<S>[] = [];
  for (const end of keys(spec)) {
    const f = spec[end] as FilterField;
    const endValue = values[end];
    if (f.kind !== 'date' || f.bound !== 'end' || endValue === undefined) {
      continue;
    }
    // YYYY-MM-DD days compare as strings.
    if (starts.some((s) => (values[s] as string) > endValue)) {
      issues.push({ field: end, code: 'range' });
    }
  }
  return issues;
}

/**
 * Client-side validation of the filter form, in the order of the spec: an invalid email
 * ("invalid-email"), a value not in the enum, not matching the pattern or not a real day
 * ("invalid-format"), a text longer than its maximum ("too-long"), and an end day before a
 * start day ("range", on the end field). Empty fields are valid (no filter).
 */
export function validateFilters<S extends FilterSpec>(spec: S, form: FilterForm<S>): FilterIssue<S>[] {
  const issues: FilterIssue<S>[] = [];
  const valid: Record<string, string> = {};
  for (const name of keys(spec)) {
    const raw = form[name];
    if (raw === undefined || raw.trim() === '') {
      continue;
    }
    const result = check(spec[name] as FilterField, raw);
    if ('value' in result) {
      valid[name] = result.value;
    } else {
      issues.push({ field: name, code: result.code });
    }
  }
  return [...issues, ...rangeIssues(spec, valid)];
}

/**
 * Filters of a valid form (values trimmed, empty fields omitted), to navigate to; undefined when
 * validateFilters reports an issue.
 */
export function formToFilters<S extends FilterSpec>(spec: S, form: FilterForm<S>): Filters<S> | undefined {
  if (validateFilters(spec, form).length > 0) {
    return undefined;
  }
  const out: Record<string, string> = {};
  for (const name of keys(spec)) {
    const raw = form[name];
    if (raw !== undefined && raw.trim() !== '') {
      out[name] = raw.trim();
    }
  }
  return out as Filters<S>;
}

/** Form values of filters (every field of the spec, "" when not set). */
export function filtersToForm<S extends FilterSpec>(spec: S, filters: Filters<S>): Required<FilterForm<S>> {
  const out: Record<string, string> = {};
  for (const name of keys(spec)) {
    out[name] = (filters as Record<string, string | undefined>)[name] ?? '';
  }
  return out as Required<FilterForm<S>>;
}

/** Reports whether no filter is set (undefined and empty values count as not set). */
export function isEmpty(filters: object): boolean {
  return Object.values(filters).every((v) => v === undefined || v === '');
}
