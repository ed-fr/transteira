// Logic of the security log screens: the tenant log (SecurityLog.svelte, delegated admins,
// auditors and super admin) and the instance log (GlobalSecurityLog.svelte, super admin). The
// log is the database copy of the lines written for fail2ban and CrowdSec: one event is a type
// (the event= token), an optional reason, the client IP and the tenant, never an e-mail
// address. Identical events seen in a short window are coalesced into one entry with an
// occurrence count. The type enumeration is extensible (x-extensible-enum): an unknown type is
// shown as its raw token, never hidden, and can still be used as a filter.
import { securityEventTypeValues, type components } from '../../../shared/api/schema';
import type { SelectEntry } from '../../components/select';
import { CUSTOM_ACTION } from './audit';
import { filterErrors, filterIssueMessage } from './common';
import {
  filtersToApiParams,
  filtersToForm,
  formToFilters,
  validateFilters,
  type DateFilter,
  type FilterIssue,
  type FilterSpec,
  type Filters,
  type TextFilter,
} from './filters';
import type { Translate } from '../../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** A security event. */
export type SecurityEvent = components['schemas']['SecurityEvent'];
/** A security event type known to this version of the specification. */
export type SecurityEventType = components['schemas']['SecurityEventType'];

/** Value of the type select meaning "type a token". */
export const CUSTOM_TYPE = CUSTOM_ACTION;

/** Form of a type token (SecurityEventType). */
export const TYPE_PATTERN = /^[a-z][a-z0-9_]*$/;
/** Maximum length of a type token. */
export const TYPE_MAX_LENGTH = 64;
/** Form of a tenant identifier (TenantId). */
const TENANT_ID_PATTERN = /^ten_[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

const TYPE_FILTER: TextFilter = { kind: 'text', maxLength: TYPE_MAX_LENGTH, pattern: TYPE_PATTERN };

/** Filters of listTenantSecurityEvents (from and to inclusive). */
export const SECURITY_FILTERS = {
  type: TYPE_FILTER,
  from: { kind: 'date', bound: 'start' } as DateFilter,
  to: { kind: 'date', bound: 'end' } as DateFilter,
} satisfies FilterSpec;

/** Filters of listGlobalSecurityEvents: the same, and a tenant. */
export const GLOBAL_SECURITY_FILTERS = {
  tenantId: { kind: 'text', maxLength: 30, pattern: TENANT_ID_PATTERN } as TextFilter,
  ...SECURITY_FILTERS,
} satisfies FilterSpec;

/** Filters of the tenant security log. */
export type SecurityFilters = Filters<typeof SECURITY_FILTERS>;
/** Filters of the instance security log. */
export type GlobalSecurityFilters = Filters<typeof GLOBAL_SECURITY_FILTERS>;

/** Every security event type known to this version, in display order. */
export const SECURITY_EVENT_TYPES: readonly SecurityEventType[] = securityEventTypeValues;

/** Reports whether value is a type of this version of the specification. */
export function isKnownType(value: string): value is SecurityEventType {
  return (SECURITY_EVENT_TYPES as readonly string[]).includes(value);
}

/** Label of a type: translated when known, the raw token otherwise. */
export function typeLabel(type: string, t: Translate): string {
  return isKnownType(type) ? t(`opsSecurity.types.${type}`) : type;
}

/** Entries of the type select: "any type", every known type, "other" (any typed token). */
export function typeEntries(t: Translate): SelectEntry[] {
  return [
    { value: '', label: t('opsSecurity.filters.anyType') },
    ...SECURITY_EVENT_TYPES.map((type) => ({ value: type, label: typeLabel(type, t) })),
    { value: CUSTOM_TYPE, label: t('opsSecurity.filters.customType') },
  ];
}

/** Values of the filter form of a security log. */
export interface SecurityForm {
  /** Selected tenant id, "" for every tenant (instance log only). */
  tenantId: string;
  /** Selected type: "" (any), a known type or CUSTOM_TYPE. */
  typeSelect: string;
  /** Token typed when typeSelect is CUSTOM_TYPE. */
  typeCustom: string;
  from: string;
  to: string;
}

/** Field of the form carrying an issue (the type issue is on the typed token). */
export type SecurityFormField = 'tenantId' | 'typeCustom' | 'from' | 'to';

/** Empty form. */
export function emptySecurityForm(): SecurityForm {
  return { tenantId: '', typeSelect: '', typeCustom: '', from: '', to: '' };
}

/** Form values of filters read from the URL (a known type is selected, others typed). */
export function securityFormOf(filters: GlobalSecurityFilters): SecurityForm {
  const base = filtersToForm(GLOBAL_SECURITY_FILTERS, filters);
  const type = base.type;
  const listed = type !== '' && isKnownType(type);
  return {
    tenantId: base.tenantId,
    typeSelect: type === '' ? '' : listed ? type : CUSTOM_TYPE,
    typeCustom: type === '' || listed ? '' : type,
    from: base.from,
    to: base.to,
  };
}

/** Type of the form: the typed token when "other" is selected, else the selected value. */
export function formType(form: SecurityForm): string {
  return form.typeSelect === CUSTOM_TYPE ? form.typeCustom.trim() : form.typeSelect;
}

/** Field of the form that shows a filter issue. */
export function issueField(issue: FilterIssue<typeof GLOBAL_SECURITY_FILTERS>): SecurityFormField {
  return issue.field === 'type' ? 'typeCustom' : issue.field;
}

/** Result of the validation of the form. */
export type SecurityFormResult =
  | { ok: true; filters: GlobalSecurityFilters }
  | { ok: false; errors: Partial<Record<SecurityFormField, string>>; first: SecurityFormField };

/**
 * Validates the form: the filters to navigate to, or the message of each invalid field. The
 * tenant is only taken into account when global is set (instance log).
 */
export function submitSecurityForm(form: SecurityForm, t: Translate, global = false): SecurityFormResult {
  const values = {
    ...(global ? { tenantId: form.tenantId } : {}),
    type: formType(form),
    from: form.from,
    to: form.to,
  };
  const failed = filterErrors(
    validateFilters(GLOBAL_SECURITY_FILTERS, values),
    (issue) => (issue.code === 'range' ? t('opsAudit.filters.range') : filterIssueMessage(issue.code, t)),
    issueField,
  );
  if (failed !== undefined) {
    return { ok: false, ...failed };
  }
  return { ok: true, filters: formToFilters(GLOBAL_SECURITY_FILTERS, values) as GlobalSecurityFilters };
}

/** Query parameters of listTenantSecurityEvents / listGlobalSecurityEvents. */
export type SecurityParams = {
  tenantId?: string;
  type?: SecurityEventType;
  from?: string;
  to?: string;
  limit: number;
  cursor?: string;
};

/**
 * Query parameters of a list call (dates as RFC 3339 instants). The type is free text checked
 * against the token form only, while the parameter is typed with the enum of the specification:
 * the API accepts any token (an unknown one matches no event). The tenant is sent only when
 * global is set.
 */
export function securityApiParams(
  filters: GlobalSecurityFilters,
  options: { cursor?: string; global?: boolean } = {},
): SecurityParams {
  const p = filtersToApiParams(GLOBAL_SECURITY_FILTERS, filters, { cursor: options.cursor });
  const out: SecurityParams = { limit: p.limit };
  if (options.global === true && p.tenantId !== undefined) {
    out.tenantId = p.tenantId;
  }
  if (p.type !== undefined) {
    out.type = p.type as SecurityEventType;
  }
  if (p.from !== undefined) {
    out.from = p.from;
  }
  if (p.to !== undefined) {
    out.to = p.to;
  }
  if (p.cursor !== undefined) {
    out.cursor = p.cursor;
  }
  return out;
}

/** Number of occurrences an entry stands for (at least 1). */
export function occurrenceCount(event: Pick<SecurityEvent, 'occurrences'>): number {
  const n = event.occurrences;
  return n === undefined || !Number.isFinite(n) || n < 1 ? 1 : Math.floor(n);
}

/** Last occurrence of a coalesced entry; undefined for a single occurrence. */
export function lastSeen(event: Pick<SecurityEvent, 'occurrences' | 'lastSeenAt'>): string | undefined {
  return occurrenceCount(event) > 1 && event.lastSeenAt !== undefined && event.lastSeenAt !== ''
    ? event.lastSeenAt
    : undefined;
}

/** Reason of an event as shown ("None" when it has none). */
export function reasonText(event: Pick<SecurityEvent, 'reason'>, t: Translate): string {
  return event.reason === undefined || event.reason === '' ? t('opsSecurity.list.noReason') : event.reason;
}

/** IP of an event as shown: the address, or "None" when unknown ("-" or empty). */
export function ipText(event: Pick<SecurityEvent, 'ip'>, t: Translate): string {
  return event.ip === '' || event.ip === '-' ? t('opsSecurity.list.noIp') : event.ip;
}

/** Text of the loaded rows ("12 events loaded." and whether more can be loaded). */
export function loadedText(count: number, hasMore: boolean, t: Translate): string {
  return t(hasMore ? 'opsSecurity.list.loadedMore' : 'opsSecurity.list.loaded', { count });
}
