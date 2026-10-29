// Logic of the abuse detection screen of a tenant (CLAUDE.md sections 10 and 15, version 1.1),
// kept out of the component so that it is unit tested in Node: mapping between the API object
// (AbuseThresholds, where null disables a rule) and the form (an "enabled" box per nullable
// threshold), validation mirroring the specification, time zone suggestions and office hours.
import type { components } from '../../../shared/api/schema';
import type { FieldRef, SummaryError } from '../../components/form';
import type { Translate } from './network';

/** Abuse detection settings of a tenant. */
export type AbuseThresholds = components['schemas']['AbuseThresholds'];
/** Office hours of a tenant. */
export type OfficeHours = components['schemas']['OfficeHours'];

/** A nullable whole number threshold: disabled when not enabled, else the typed text. */
export interface OptionalCount {
  enabled: boolean;
  text: string;
}

/** A nullable size threshold: disabled when not enabled, else bytes (null while invalid). */
export interface OptionalBytes {
  enabled: boolean;
  bytes: number | null;
}

/** Form state of the abuse detection screen. */
export interface AbuseForm {
  maxDailyBytesPerSender: OptionalBytes;
  maxDailyTransfersPerSender: OptionalCount;
  maxRecipientsPerTransfer: OptionalCount;
  blockOnExceed: boolean;
  unusualVolumeFactor: OptionalCount;
  unusualMinHistoryDays: string;
  largeExternalTransferBytes: OptionalBytes;
  timeZone: string;
  officeHoursEnabled: boolean;
  officeStart: string;
  officeEnd: string;
  officeWeekdays: number[];
  maxInvitationsPerInviter: string;
  externalMaxDailyBytes: OptionalBytes;
  externalMaxDailyDeposits: OptionalCount;
}

/** Names of the fields of the form, as in the API (also the keys of the error summary). */
export type AbuseField = keyof AbuseThresholds;

/** Limits of the specification. */
export const LIMITS = {
  maxRecipientsPerTransfer: { min: 1, max: 100 },
  unusualMinHistoryDays: { min: 1, max: 30 },
  maxInvitationsPerInviter: { min: 1, max: 1000 },
  unusualVolumeFactor: { min: 1.5, max: 100 },
} as const;

/** Defaults of the specification, proposed when a threshold is enabled. */
export const DEFAULTS = {
  unusualMinHistoryDays: 7,
  maxInvitationsPerInviter: 20,
  timeZone: 'UTC',
  unusualVolumeFactor: 5,
  officeStart: '08:00',
  officeEnd: '19:00',
  officeWeekdays: [1, 2, 3, 4, 5],
} as const;

/** ISO weekdays, Monday first. */
export const WEEKDAYS: readonly number[] = [1, 2, 3, 4, 5, 6, 7];

const count = (value: number | null): OptionalCount => ({
  enabled: value !== null,
  text: value === null ? '' : String(value),
});
const size = (value: number | null): OptionalBytes => ({ enabled: value !== null, bytes: value });

/** Form state showing saved thresholds. */
export function toForm(a: AbuseThresholds): AbuseForm {
  const office = a.officeHours ?? null;
  return {
    maxDailyBytesPerSender: size(a.maxDailyBytesPerSender),
    maxDailyTransfersPerSender: count(a.maxDailyTransfersPerSender),
    maxRecipientsPerTransfer: count(a.maxRecipientsPerTransfer),
    blockOnExceed: a.blockOnExceed,
    unusualVolumeFactor: count(a.unusualVolumeFactor),
    unusualMinHistoryDays: String(a.unusualMinHistoryDays),
    largeExternalTransferBytes: size(a.largeExternalTransferBytes),
    timeZone: a.timeZone,
    officeHoursEnabled: office !== null,
    officeStart: office?.start ?? DEFAULTS.officeStart,
    officeEnd: office?.end ?? DEFAULTS.officeEnd,
    officeWeekdays: office === null ? [...DEFAULTS.officeWeekdays] : [...office.weekdays],
    maxInvitationsPerInviter: String(a.maxInvitationsPerInviter),
    externalMaxDailyBytes: size(a.externalMaxDailyBytes),
    externalMaxDailyDeposits: count(a.externalMaxDailyDeposits),
  };
}

// ---- Parsing ---------------------------------------------------------------------------------

const INTEGER = /^[0-9]{1,15}$/;
const DECIMAL = /^[0-9]{1,3}([.,][0-9]{1,2})?$/;

/** Parses a whole number text within [min, max]; undefined when not an integer or out of range. */
export function parseInteger(text: string, min: number, max?: number): number | undefined {
  const s = text.trim();
  if (!INTEGER.test(s)) {
    return undefined;
  }
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < min || (max !== undefined && n > max)) {
    return undefined;
  }
  return n;
}

/**
 * Parses the unusual volume factor (1.5 to 100, one decimal: multipleOf 0.1, dot or comma);
 * undefined when invalid.
 */
export function parseFactor(text: string): number | undefined {
  const s = text.trim();
  if (!DECIMAL.test(s)) {
    return undefined;
  }
  const n = Number(s.replace(',', '.'));
  const tenths = Math.round(n * 10);
  if (Math.abs(n * 10 - tenths) > 1e-9) {
    return undefined;
  }
  const value = tenths / 10;
  return value >= LIMITS.unusualVolumeFactor.min && value <= LIMITS.unusualVolumeFactor.max
    ? value
    : undefined;
}

// ---- Time zones ------------------------------------------------------------------------------

/** Common IANA zones, offered when the browser cannot list them. */
export const COMMON_TIME_ZONES: readonly string[] = [
  'UTC',
  'Europe/Paris',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Madrid',
  'Europe/Rome',
  'Europe/Brussels',
  'Europe/Amsterdam',
  'Europe/Zurich',
  'Europe/Lisbon',
  'Europe/Dublin',
  'Africa/Casablanca',
  'Africa/Algiers',
  'Africa/Tunis',
  'Africa/Dakar',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Toronto',
  'America/Montreal',
  'America/Sao_Paulo',
  'Asia/Dubai',
  'Asia/Kolkata',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
  'Pacific/Noumea',
  'Indian/Reunion',
];

/**
 * Time zones suggested by the field: the zones the browser lists (Intl.supportedValuesOf) plus
 * UTC, which some browsers leave out; the common zones when the browser cannot list them.
 */
export function timeZoneSuggestions(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
  try {
    const listed = intl.supportedValuesOf?.('timeZone');
    if (listed !== undefined && listed.length > 0) {
      return ['UTC', ...listed.filter((z) => z !== 'UTC')];
    }
  } catch {
    // Unsupported key: fall back to the common zones.
  }
  return [...COMMON_TIME_ZONES];
}

/** Reports whether the browser knows the IANA time zone (the server has the final word). */
export function isKnownTimeZone(zone: string): boolean {
  const z = zone.trim();
  if (z === '' || z.length > 64) {
    return false;
  }
  try {
    new Intl.DateTimeFormat('en', { timeZone: z });
    return true;
  } catch {
    return false;
  }
}

// ---- Office hours ----------------------------------------------------------------------------

const START = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
const END = /^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$/;

/** Minutes since midnight of an HH:MM time (24:00 allowed), NaN when malformed. */
export function minutesOf(time: string): number {
  const m = /^([0-9]{2}):([0-9]{2})$/.exec(time);
  return m === null ? NaN : Number(m[1]) * 60 + Number(m[2]);
}

/** Problem of the office hours, or undefined when valid. */
export type OfficeHoursIssue = 'start' | 'end' | 'order' | 'weekdays';

/** Validates the office hours: start HH:MM, end HH:MM or 24:00 after start, at least one weekday. */
export function validateOfficeHours(
  start: string,
  end: string,
  weekdays: readonly number[],
): OfficeHoursIssue | undefined {
  if (!START.test(start)) {
    return 'start';
  }
  if (!END.test(end)) {
    return 'end';
  }
  if (minutesOf(end) <= minutesOf(start)) {
    return 'order';
  }
  if (weekdays.length === 0) {
    return 'weekdays';
  }
  return undefined;
}

/** Toggles an ISO weekday in a selection, keeping it sorted. */
export function toggleWeekday(selected: readonly number[], day: number, on: boolean): number[] {
  const without = selected.filter((d) => d !== day);
  return (on ? [...without, day] : without).sort((a, b) => a - b);
}

// ---- Validation and body ---------------------------------------------------------------------

/** Fields of the form, for the error summary (ids of the inputs to focus). */
export type AbuseFields = Record<AbuseField, FieldRef>;

/** Message key (adminAbuse.thresholds.errors.*) of an error code, with its parameters. */
export interface IssueMessage {
  key: string;
  params?: Record<string, string | number>;
}

/** An error of one field of the form. */
export interface AbuseIssue {
  field: AbuseField;
  message: IssueMessage;
}

const ERR = 'adminAbuse.thresholds.errors';

function countIssue(field: AbuseField, o: OptionalCount, min: number, max?: number): AbuseIssue | undefined {
  if (!o.enabled) {
    return undefined;
  }
  if (o.text.trim() === '') {
    return { field, message: { key: `${ERR}.required` } };
  }
  return parseInteger(o.text, min, max) === undefined
    ? max === undefined
      ? { field, message: { key: `${ERR}.integerMin`, params: { min } } }
      : { field, message: { key: `${ERR}.integerRange`, params: { min, max } } }
    : undefined;
}

function bytesIssue(field: AbuseField, o: OptionalBytes): AbuseIssue | undefined {
  return o.enabled && o.bytes === null ? { field, message: { key: `${ERR}.size` } } : undefined;
}

function requiredInteger(field: AbuseField, text: string, min: number, max: number): AbuseIssue | undefined {
  return parseInteger(text, min, max) === undefined
    ? { field, message: { key: `${ERR}.integerRange`, params: { min, max } } }
    : undefined;
}

/** Client-side validation, in the order of the form; the save is refused while it reports. */
export function validateForm(f: AbuseForm): AbuseIssue[] {
  const out: (AbuseIssue | undefined)[] = [
    bytesIssue('maxDailyBytesPerSender', f.maxDailyBytesPerSender),
    countIssue('maxDailyTransfersPerSender', f.maxDailyTransfersPerSender, 1),
    countIssue(
      'maxRecipientsPerTransfer',
      f.maxRecipientsPerTransfer,
      LIMITS.maxRecipientsPerTransfer.min,
      LIMITS.maxRecipientsPerTransfer.max,
    ),
  ];
  if (f.unusualVolumeFactor.enabled) {
    out.push(
      parseFactor(f.unusualVolumeFactor.text) === undefined
        ? {
            field: 'unusualVolumeFactor',
            message: {
              key: `${ERR}.factor`,
              params: { min: LIMITS.unusualVolumeFactor.min, max: LIMITS.unusualVolumeFactor.max },
            },
          }
        : undefined,
    );
  }
  out.push(
    requiredInteger(
      'unusualMinHistoryDays',
      f.unusualMinHistoryDays,
      LIMITS.unusualMinHistoryDays.min,
      LIMITS.unusualMinHistoryDays.max,
    ),
    bytesIssue('largeExternalTransferBytes', f.largeExternalTransferBytes),
    isKnownTimeZone(f.timeZone) ? undefined : { field: 'timeZone', message: { key: `${ERR}.timeZone` } },
  );
  if (f.officeHoursEnabled) {
    const issue = validateOfficeHours(f.officeStart, f.officeEnd, f.officeWeekdays);
    out.push(
      issue === undefined ? undefined : { field: 'officeHours', message: { key: `${ERR}.office.${issue}` } },
    );
  }
  out.push(
    requiredInteger(
      'maxInvitationsPerInviter',
      f.maxInvitationsPerInviter,
      LIMITS.maxInvitationsPerInviter.min,
      LIMITS.maxInvitationsPerInviter.max,
    ),
    bytesIssue('externalMaxDailyBytes', f.externalMaxDailyBytes),
    countIssue('externalMaxDailyDeposits', f.externalMaxDailyDeposits, 1),
  );
  return out.filter((i): i is AbuseIssue => i !== undefined);
}

/** Summary entries of the issues (errors of the error summary of FormSection). */
export function issuesToSummary(
  issues: readonly AbuseIssue[],
  fields: AbuseFields,
  t: Translate,
): SummaryError[] {
  return issues.map((i) => ({
    id: fields[i.field].id,
    label: fields[i.field].label,
    message: t(i.message.key, i.message.params),
  }));
}

const orNull = (o: OptionalCount, min: number, max?: number): number | null =>
  o.enabled ? (parseInteger(o.text, min, max) ?? null) : null;

/**
 * Body of the PUT: every member, null for a disabled rule; undefined while the form is invalid
 * (validateForm reports an issue).
 */
export function toBody(f: AbuseForm): AbuseThresholds | undefined {
  if (validateForm(f).length > 0) {
    return undefined;
  }
  return {
    maxDailyBytesPerSender: f.maxDailyBytesPerSender.enabled ? f.maxDailyBytesPerSender.bytes : null,
    maxDailyTransfersPerSender: orNull(f.maxDailyTransfersPerSender, 1),
    maxRecipientsPerTransfer: orNull(
      f.maxRecipientsPerTransfer,
      LIMITS.maxRecipientsPerTransfer.min,
      LIMITS.maxRecipientsPerTransfer.max,
    ),
    blockOnExceed: f.blockOnExceed,
    unusualVolumeFactor: f.unusualVolumeFactor.enabled
      ? (parseFactor(f.unusualVolumeFactor.text) ?? null)
      : null,
    unusualMinHistoryDays: parseInteger(f.unusualMinHistoryDays, 1, 30) as number,
    largeExternalTransferBytes: f.largeExternalTransferBytes.enabled
      ? f.largeExternalTransferBytes.bytes
      : null,
    timeZone: f.timeZone.trim(),
    officeHours: f.officeHoursEnabled
      ? { start: f.officeStart, end: f.officeEnd, weekdays: [...f.officeWeekdays].sort((a, b) => a - b) }
      : null,
    maxInvitationsPerInviter: parseInteger(f.maxInvitationsPerInviter, 1, 1000) as number,
    externalMaxDailyBytes: f.externalMaxDailyBytes.enabled ? f.externalMaxDailyBytes.bytes : null,
    externalMaxDailyDeposits: orNull(f.externalMaxDailyDeposits, 1),
  };
}

function sameWeekdays(a: readonly number[], b: readonly number[]): boolean {
  return a.length === b.length && a.every((d, i) => d === b[i]);
}

/** Reports whether two sets of thresholds are equal. */
export function sameThresholds(a: AbuseThresholds, b: AbuseThresholds): boolean {
  const ao = a.officeHours ?? null;
  const bo = b.officeHours ?? null;
  const sameOffice =
    ao === null || bo === null
      ? ao === bo
      : ao.start === bo.start && ao.end === bo.end && sameWeekdays(ao.weekdays, bo.weekdays);
  return (
    sameOffice &&
    a.maxDailyBytesPerSender === b.maxDailyBytesPerSender &&
    a.maxDailyTransfersPerSender === b.maxDailyTransfersPerSender &&
    a.maxRecipientsPerTransfer === b.maxRecipientsPerTransfer &&
    a.blockOnExceed === b.blockOnExceed &&
    a.unusualVolumeFactor === b.unusualVolumeFactor &&
    a.unusualMinHistoryDays === b.unusualMinHistoryDays &&
    a.largeExternalTransferBytes === b.largeExternalTransferBytes &&
    a.timeZone === b.timeZone &&
    a.maxInvitationsPerInviter === b.maxInvitationsPerInviter &&
    a.externalMaxDailyBytes === b.externalMaxDailyBytes &&
    a.externalMaxDailyDeposits === b.externalMaxDailyDeposits
  );
}

/**
 * Reports whether the form differs from the saved thresholds. An invalid form always counts as
 * changed, so that the save runs the validation (error summary) instead of "nothing to save".
 */
export function isDirty(saved: AbuseThresholds, form: AbuseForm): boolean {
  const body = toBody(form);
  return body === undefined || !sameThresholds(saved, body);
}
