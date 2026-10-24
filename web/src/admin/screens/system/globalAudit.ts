// Logic of the global audit log screen (GlobalAudit.svelte, super admin): the filters reflected in
// the URL (tenant, action), the filter form (tenant select, action chosen in a grouped list with
// every group or typed freely), the query parameters of listGlobalAuditEvents and the content of
// the "Tenant" column.
//
// The API has no "events without tenant only" filter: without tenantId it returns the events of
// every tenant plus the instance events, with tenantId only that tenant's events. The tenant
// select therefore offers "All tenants" and the tenants, never an "Instance only" option (filtering
// a partial page on the client would hide events and mislead); instance events are shown with
// "Instance" in the tenant column of the unfiltered log.
import {
  ACTION_MAX_LENGTH,
  ACTION_PATTERN,
  filtersToApiParams,
  filtersToForm,
  formToFilters,
  isEmpty,
  validateFilters,
  type FilterIssue,
  type FilterSpec,
  type Filters,
  type TextFilter,
} from '../ops/filters';
import { auditActionGroups, isKnownAction, type AuditAction, type Translate } from '../ops/auditLabels';
import { CUSTOM_ACTION } from '../ops/audit';
import { filterErrors, filterIssueMessage } from '../ops/common';
import { tenantPath } from '../../shell';
import type { SelectEntry, SelectOption } from '../../components/select';

export { CUSTOM_ACTION };

/** Form of a tenant identifier (TenantId: "ten_" and a ULID). */
export const TENANT_ID_PATTERN = /^ten_[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
/** Length of a tenant identifier. */
export const TENANT_ID_LENGTH = 30;

/** Filters of listGlobalAuditEvents (no actor or date filter in the API). */
export const GLOBAL_AUDIT_FILTERS = {
  tenantId: { kind: 'text', maxLength: TENANT_ID_LENGTH, pattern: TENANT_ID_PATTERN } as TextFilter,
  action: { kind: 'text', maxLength: ACTION_MAX_LENGTH, pattern: ACTION_PATTERN } as TextFilter,
} satisfies FilterSpec;

/** Filters of the global audit log. */
export type GlobalAuditFilters = Filters<typeof GLOBAL_AUDIT_FILTERS>;

/** Values of the filter form of the global audit log. */
export interface GlobalAuditForm {
  /** Selected tenant id, "" for every tenant (and the instance events). */
  tenantId: string;
  /** Selected action: "" (any), a known action or CUSTOM_ACTION. */
  actionSelect: string;
  /** Action code typed when actionSelect is CUSTOM_ACTION. */
  actionCustom: string;
}

/** Field of the form carrying an issue (the action issue is on the typed code). */
export type GlobalAuditFormField = 'tenantId' | 'actionCustom';

/** A tenant of the tenant list (GET /admin/tenants). */
export interface TenantRef {
  id: string;
  name: string;
}

/** Map of tenant id to tenant name. */
export type TenantNames = ReadonlyMap<string, string>;

/** Entries of the action select: "any action", every group (instance included), "other". */
export function globalActionEntries(t: Translate): SelectEntry[] {
  return [
    { value: '', label: t('opsAudit.filters.anyAction') },
    ...auditActionGroups(t),
    { value: CUSTOM_ACTION, label: t('opsAudit.filters.customAction') },
  ];
}

/**
 * Options of the tenant select: "All tenants" first, then the tenants sorted by name. A selected
 * tenant missing from the list (deleted, or the list could not be loaded) is kept as its raw id
 * so that the select still shows the active filter.
 */
export function tenantOptions(tenants: readonly TenantRef[], selected: string, t: Translate): SelectOption[] {
  const sorted = [...tenants].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  const options: SelectOption[] = [
    { value: '', label: t('sysAudit.filters.allTenants') },
    ...sorted.map((tenant) => ({ value: tenant.id, label: tenant.name })),
  ];
  if (selected !== '' && !tenants.some((tenant) => tenant.id === selected)) {
    options.push({ value: selected, label: selected });
  }
  return options;
}

/** Builds the tenant name map from a tenant list. */
export function tenantNames(tenants: readonly TenantRef[]): Map<string, string> {
  return new Map(tenants.map((tenant) => [tenant.id, tenant.name]));
}

/** Content of the "Tenant" cell of an event. */
export type TenantCell =
  { kind: 'instance' } | { kind: 'tenant'; name: string; path: string } | { kind: 'unknown'; id: string };

/**
 * Tenant cell of an event: "Instance" for an event without tenant, the tenant name linking to its
 * general settings when known, else the raw id (deleted tenant, or names not loaded).
 */
export function tenantCell(event: { tenantId?: string | null }, names: TenantNames): TenantCell {
  const id = event.tenantId;
  if (id === undefined || id === null || id === '') {
    return { kind: 'instance' };
  }
  const name = names.get(id);
  return name === undefined
    ? { kind: 'unknown', id }
    : { kind: 'tenant', name, path: tenantPath(id, 'general') };
}

/** Form values of the filters read from the URL (a known action is selected, others typed). */
export function globalAuditFormOf(filters: GlobalAuditFilters): GlobalAuditForm {
  const base = filtersToForm(GLOBAL_AUDIT_FILTERS, filters);
  const action = base.action;
  const listed = action !== '' && isKnownAction(action);
  return {
    tenantId: base.tenantId,
    actionSelect: action === '' ? '' : listed ? action : CUSTOM_ACTION,
    actionCustom: action === '' || listed ? '' : action,
  };
}

/** Action of the form: the typed code when "other" is selected, else the selected value. */
export function formAction(form: GlobalAuditForm): string {
  return form.actionSelect === CUSTOM_ACTION ? form.actionCustom.trim() : form.actionSelect;
}

/** Field of the form that shows a filter issue. */
export function issueField(issue: FilterIssue<typeof GLOBAL_AUDIT_FILTERS>): GlobalAuditFormField {
  return issue.field === 'action' ? 'actionCustom' : 'tenantId';
}

/** Result of the validation of the form. */
export type GlobalAuditFormResult =
  | { ok: true; filters: GlobalAuditFilters }
  | { ok: false; errors: Partial<Record<GlobalAuditFormField, string>>; first: GlobalAuditFormField };

/** Validates the form: the filters to navigate to, or the message of each invalid field. */
export function submitGlobalAuditForm(form: GlobalAuditForm, t: Translate): GlobalAuditFormResult {
  const values = { tenantId: form.tenantId, action: formAction(form) };
  const failed = filterErrors(
    validateFilters(GLOBAL_AUDIT_FILTERS, values),
    (issue) => filterIssueMessage(issue.code, t),
    issueField,
  );
  if (failed !== undefined) {
    return { ok: false, ...failed };
  }
  return { ok: true, filters: formToFilters(GLOBAL_AUDIT_FILTERS, values) as GlobalAuditFilters };
}

/** Query parameters of listGlobalAuditEvents. */
export type GlobalAuditParams = {
  tenantId?: string;
  action?: AuditAction;
  limit: number;
  cursor?: string;
};

/**
 * Query parameters of listGlobalAuditEvents. The action is free text checked against the
 * "domain.verb" form only, while the parameter is typed with the closed AuditAction enum: the API
 * accepts any value of that form (an unknown action simply matches no event).
 */
export function globalAuditApiParams(filters: GlobalAuditFilters, cursor?: string): GlobalAuditParams {
  const p = filtersToApiParams(GLOBAL_AUDIT_FILTERS, filters, { cursor });
  const out: GlobalAuditParams = { limit: p.limit };
  if (p.tenantId !== undefined) {
    out.tenantId = p.tenantId;
  }
  if (p.action !== undefined) {
    out.action = p.action as AuditAction;
  }
  if (p.cursor !== undefined) {
    out.cursor = p.cursor;
  }
  return out;
}

/** Text shown when the list is empty, depending on whether filters are set. */
export function emptyText(filters: GlobalAuditFilters, t: Translate): string {
  return t(isEmpty(filters) ? 'sysAudit.list.empty' : 'sysAudit.list.emptyFiltered');
}
