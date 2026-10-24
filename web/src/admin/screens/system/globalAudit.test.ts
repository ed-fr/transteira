import { describe, expect, it } from 'vitest';
import { filtersToQuery, parseFilters, pathWithFilters } from '../ops/filters';
import type { Translate } from '../ops/auditLabels';
import {
  CUSTOM_ACTION,
  emptyText,
  formAction,
  GLOBAL_AUDIT_FILTERS,
  globalActionEntries,
  globalAuditApiParams,
  globalAuditFormOf,
  issueField,
  submitGlobalAuditForm,
  tenantCell,
  tenantNames,
  tenantOptions,
  type GlobalAuditForm,
} from './globalAudit';

const t: Translate = (key, params) => (params === undefined ? key : `${key}${JSON.stringify(params)}`);

const TEN_A = 'ten_01JAB00000000000000ENT1TYA';
const TEN_B = 'ten_01JAB00000000000000ENT1TYB';
const tenants = [
  { id: TEN_B, name: 'Entity B' },
  { id: TEN_A, name: 'Entity A' },
];

const blank: GlobalAuditForm = { tenantId: '', actionSelect: '', actionCustom: '' };

describe('GLOBAL_AUDIT_FILTERS parsing', () => {
  it('reads a valid tenant id and action', () => {
    expect(parseFilters(GLOBAL_AUDIT_FILTERS, `?tenantId=${TEN_A}&action=maintenance.enabled`)).toEqual({
      tenantId: TEN_A,
      action: 'maintenance.enabled',
    });
  });

  it('drops invalid tenant ids, invalid actions and unknown parameters', () => {
    expect(
      parseFilters(
        GLOBAL_AUDIT_FILTERS,
        '?tenantId=ten_bad&action=Maintenance&actor=alice&from=2026-10-01&status=x',
      ),
    ).toEqual({});
    expect(parseFilters(GLOBAL_AUDIT_FILTERS, `?tenantId=${TEN_A.toLowerCase()}`)).toEqual({});
    expect(parseFilters(GLOBAL_AUDIT_FILTERS, `?action=${'a'.repeat(60)}.bcdef`)).toEqual({});
  });

  it('keeps an unknown action of the valid form (the list is extensible)', () => {
    expect(parseFilters(GLOBAL_AUDIT_FILTERS, '?action=future.thing')).toEqual({ action: 'future.thing' });
  });

  it('serialises in a stable order', () => {
    expect(filtersToQuery(GLOBAL_AUDIT_FILTERS, { action: 'config.updated', tenantId: TEN_A })).toBe(
      `tenantId=${TEN_A}&action=config.updated`,
    );
    expect(pathWithFilters('/system/audit', GLOBAL_AUDIT_FILTERS, {})).toBe('/system/audit');
  });
});

describe('globalActionEntries', () => {
  it('lists every group, instance and accounts included, between "any" and "other"', () => {
    const entries = globalActionEntries(t);
    expect(entries[0]).toEqual({ value: '', label: 'opsAudit.filters.anyAction' });
    expect(entries.at(-1)).toEqual({ value: CUSTOM_ACTION, label: 'opsAudit.filters.customAction' });
    const groups = entries.flatMap((e) => ('group' in e ? [e.group] : []));
    expect(groups).toContain('transfers');
    expect(groups).toContain('instance');
    expect(groups).toContain('accounts');
  });
});

describe('tenantOptions', () => {
  it('starts with "all" and sorts the tenants by name', () => {
    expect(tenantOptions(tenants, '', t)).toEqual([
      { value: '', label: 'sysAudit.filters.allTenants' },
      { value: TEN_A, label: 'Entity A' },
      { value: TEN_B, label: 'Entity B' },
    ]);
  });

  it('breaks name ties by id', () => {
    const same = [
      { id: TEN_B, name: 'Same' },
      { id: TEN_A, name: 'Same' },
    ];
    expect(tenantOptions(same, TEN_A, t).map((o) => o.value)).toEqual(['', TEN_A, TEN_B]);
  });

  it('keeps a selected tenant missing from the list as its raw id', () => {
    const other = 'ten_01JAB00000000000000ENT1TYC';
    expect(tenantOptions(tenants, other, t).at(-1)).toEqual({ value: other, label: other });
    expect(tenantOptions([], other, t)).toHaveLength(2);
  });
});

describe('tenantNames and tenantCell', () => {
  const names = tenantNames(tenants);

  it('maps ids to names', () => {
    expect(names.get(TEN_A)).toBe('Entity A');
    expect(names.size).toBe(2);
  });

  it('shows "Instance" for events without tenant', () => {
    expect(tenantCell({}, names)).toEqual({ kind: 'instance' });
    expect(tenantCell({ tenantId: null }, names)).toEqual({ kind: 'instance' });
    expect(tenantCell({ tenantId: '' }, names)).toEqual({ kind: 'instance' });
  });

  it('links a known tenant to its general settings', () => {
    expect(tenantCell({ tenantId: TEN_A }, names)).toEqual({
      kind: 'tenant',
      name: 'Entity A',
      path: `/tenants/${TEN_A}/general`,
    });
  });

  it('shows the raw id of an unknown tenant', () => {
    const gone = 'ten_01JAB00000000000000ENT1TYZ';
    expect(tenantCell({ tenantId: gone }, names)).toEqual({ kind: 'unknown', id: gone });
  });
});

describe('globalAuditFormOf and formAction', () => {
  it('fills an empty form without filters', () => {
    expect(globalAuditFormOf({})).toEqual(blank);
  });

  it('selects a known action (instance actions included)', () => {
    expect(globalAuditFormOf({ tenantId: TEN_A, action: 'master_key.rotation_started' })).toEqual({
      tenantId: TEN_A,
      actionSelect: 'master_key.rotation_started',
      actionCustom: '',
    });
  });

  it('types an unknown action as a code', () => {
    const form = globalAuditFormOf({ action: 'future.thing' });
    expect(form).toEqual({ tenantId: '', actionSelect: CUSTOM_ACTION, actionCustom: 'future.thing' });
    expect(formAction({ ...form, actionCustom: ' future.thing ' })).toBe('future.thing');
    expect(formAction({ ...blank, actionSelect: 'config.updated' })).toBe('config.updated');
  });
});

describe('submitGlobalAuditForm', () => {
  it('accepts an empty form', () => {
    expect(submitGlobalAuditForm(blank, t)).toEqual({ ok: true, filters: {} });
  });

  it('returns the filters of a valid form', () => {
    expect(
      submitGlobalAuditForm({ tenantId: TEN_A, actionSelect: CUSTOM_ACTION, actionCustom: 'x.y' }, t),
    ).toEqual({ ok: true, filters: { tenantId: TEN_A, action: 'x.y' } });
  });

  it('reports an invalid typed action on the code field', () => {
    expect(submitGlobalAuditForm({ ...blank, actionSelect: CUSTOM_ACTION, actionCustom: 'Bad' }, t)).toEqual({
      ok: false,
      errors: { actionCustom: 'fieldErrors.invalid-format' },
      first: 'actionCustom',
    });
    const long = submitGlobalAuditForm(
      { ...blank, actionSelect: CUSTOM_ACTION, actionCustom: `${'a'.repeat(60)}.bcdef` },
      t,
    );
    expect(long).toMatchObject({ ok: false, errors: { actionCustom: 'fieldErrors.too-long' } });
  });

  it('reports an invalid tenant id first', () => {
    expect(
      submitGlobalAuditForm({ tenantId: 'ten_bad', actionSelect: CUSTOM_ACTION, actionCustom: 'Bad' }, t),
    ).toEqual({
      ok: false,
      errors: { tenantId: 'fieldErrors.invalid-format', actionCustom: 'fieldErrors.invalid-format' },
      first: 'tenantId',
    });
  });

  it('maps issues to their form field', () => {
    expect(issueField({ field: 'action', code: 'invalid-format' })).toBe('actionCustom');
    expect(issueField({ field: 'tenantId', code: 'invalid-format' })).toBe('tenantId');
  });
});

describe('globalAuditApiParams', () => {
  it('sends only the page size without filters', () => {
    expect(globalAuditApiParams({})).toEqual({ limit: 50 });
  });

  it('sends the filters and the cursor', () => {
    expect(globalAuditApiParams({ tenantId: TEN_A, action: 'maintenance.enabled' }, 'c1')).toEqual({
      tenantId: TEN_A,
      action: 'maintenance.enabled',
      limit: 50,
      cursor: 'c1',
    });
  });

  it('drops invalid values and an empty cursor', () => {
    expect(globalAuditApiParams({ tenantId: 'nope', action: 'Nope' }, '')).toEqual({ limit: 50 });
  });
});

describe('emptyText', () => {
  it('depends on whether filters are set', () => {
    expect(emptyText({}, t)).toBe('sysAudit.list.empty');
    expect(emptyText({ action: 'config.updated' }, t)).toBe('sysAudit.list.emptyFiltered');
  });
});
