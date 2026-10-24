// Logic of the audit log screen of a tenant (AuditLog.svelte): the filter form (action chosen in
// a grouped list or typed freely, actor, period), its validation messages and the loaded-rows
// text. Labels of actions, actors, objects and details come from auditLabels.ts (shared with the
// instance audit log).
import {
  AUDIT_FILTERS,
  filtersToForm,
  formToFilters,
  validateFilters,
  type AuditFilters,
  type FilterForm,
  type FilterIssue,
} from './filters';
import { auditActionGroups, isKnownAction, type Translate } from './auditLabels';
import { filterErrors, filterIssueMessage } from './common';
import type { SelectEntry } from '../../components/select';

/** Value of the action select meaning "type an action code". */
export const CUSTOM_ACTION = '*custom';

/** Values of the filter form of the audit log. */
export interface AuditForm {
  /** Selected action: "" (any), a known action or CUSTOM_ACTION. */
  actionSelect: string;
  /** Action code typed when actionSelect is CUSTOM_ACTION. */
  actionCustom: string;
  actor: string;
  from: string;
  to: string;
}

/** Field of the audit form carrying an issue (the action issue is on the typed code). */
export type AuditFormField = 'actionCustom' | 'actor' | 'from' | 'to';

/**
 * Groups left out of the action select of a tenant log: instance actions and administrator
 * account actions (setup, sign-in, account management) are recorded without a tenant and never
 * appear in a tenant audit log.
 */
export const TENANT_EXCLUDED_GROUPS = ['instance', 'accounts'] as const;

/** Entries of the action select: "any action", the tenant groups, "other" (any typed code). */
export function actionEntries(t: Translate): SelectEntry[] {
  return [
    { value: '', label: t('opsAudit.filters.anyAction') },
    ...auditActionGroups(t, { exclude: TENANT_EXCLUDED_GROUPS }),
    { value: CUSTOM_ACTION, label: t('opsAudit.filters.customAction') },
  ];
}

/**
 * Form values of the filters read from the URL: a known action is selected in the list (an
 * instance or account action is not listed and is kept as typed code), anything else goes to the code.
 */
export function auditFormOf(filters: AuditFilters, t: Translate): AuditForm {
  const base = filtersToForm(AUDIT_FILTERS, filters);
  const action = base.action;
  const listed = action !== '' && isKnownAction(action) && hasListedAction(t, action);
  return {
    actionSelect: action === '' ? '' : listed ? action : CUSTOM_ACTION,
    actionCustom: action === '' || listed ? '' : action,
    actor: base.actor,
    from: base.from,
    to: base.to,
  };
}

function hasListedAction(t: Translate, action: string): boolean {
  return actionEntries(t).some((e) => 'options' in e && e.options.some((o) => o.value === action));
}

/** Action of the form: the typed code when "other" is selected, else the selected value. */
export function formAction(form: AuditForm): string {
  return form.actionSelect === CUSTOM_ACTION ? form.actionCustom.trim() : form.actionSelect;
}

function filterForm(form: AuditForm): FilterForm<typeof AUDIT_FILTERS> {
  return { action: formAction(form), actor: form.actor, from: form.from, to: form.to };
}

/** Field of the audit form that shows a filter issue. */
export function issueField(issue: FilterIssue<typeof AUDIT_FILTERS>): AuditFormField {
  return issue.field === 'action' ? 'actionCustom' : issue.field;
}

/** Message of a filter issue ("range": the end of the period is before its start). */
export function issueMessage(issue: FilterIssue<typeof AUDIT_FILTERS>, t: Translate): string {
  return issue.code === 'range' ? t('opsAudit.filters.range') : filterIssueMessage(issue.code, t);
}

/** Result of the validation of the audit form. */
export type AuditFormResult =
  | { ok: true; filters: AuditFilters }
  | { ok: false; errors: Partial<Record<AuditFormField, string>>; first: AuditFormField };

/** Validates the form: the filters to navigate to, or the message of each invalid field. */
export function submitAuditForm(form: AuditForm, t: Translate): AuditFormResult {
  const values = filterForm(form);
  const failed = filterErrors(
    validateFilters(AUDIT_FILTERS, values),
    (issue) => issueMessage(issue, t),
    issueField,
  );
  if (failed !== undefined) {
    return { ok: false, ...failed };
  }
  return { ok: true, filters: formToFilters(AUDIT_FILTERS, values) as AuditFilters };
}

/** Text of the loaded rows ("12 events loaded." and whether more can be loaded). */
export function loadedText(count: number, hasMore: boolean, t: Translate): string {
  return t(hasMore ? 'opsAudit.list.loadedMore' : 'opsAudit.list.loaded', { count });
}
