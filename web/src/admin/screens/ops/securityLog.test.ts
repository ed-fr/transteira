import { describe, expect, it } from 'vitest';
import {
  CUSTOM_TYPE,
  GLOBAL_SECURITY_FILTERS,
  SECURITY_EVENT_TYPES,
  SECURITY_FILTERS,
  emptySecurityForm,
  formType,
  ipText,
  isKnownType,
  lastSeen,
  loadedText,
  occurrenceCount,
  reasonText,
  securityApiParams,
  securityFormOf,
  submitSecurityForm,
  typeEntries,
  typeLabel,
  issueField,
} from './securityLog';
import { filtersToQuery, parseFilters } from './filters';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

describe('security event types', () => {
  it('knows the types of the specification and falls back to the raw token', () => {
    expect(SECURITY_EVENT_TYPES).toContain('verification_code_invalid');
    expect(isKnownType('rate_limited')).toBe(true);
    expect(isKnownType('brand_new_type')).toBe(false);
    expect(typeLabel('rate_limited', t)).toBe('opsSecurity.types.rate_limited');
    expect(typeLabel('brand_new_type', t)).toBe('brand_new_type');
  });

  it('offers any type, every known type and an "other" entry', () => {
    const entries = typeEntries(t);
    expect(entries[0]).toEqual({ value: '', label: 'opsSecurity.filters.anyType' });
    expect(entries.at(-1)).toEqual({ value: CUSTOM_TYPE, label: 'opsSecurity.filters.customType' });
    expect(entries).toHaveLength(SECURITY_EVENT_TYPES.length + 2);
  });
});

describe('filters in the URL', () => {
  it('reads valid filters and drops invalid ones', () => {
    expect(parseFilters(SECURITY_FILTERS, 'type=rate_limited&from=2026-11-01&to=2026-11-02&x=1')).toEqual({
      type: 'rate_limited',
      from: '2026-11-01',
      to: '2026-11-02',
    });
    expect(parseFilters(SECURITY_FILTERS, 'type=Bad%20Type&from=nope')).toEqual({});
    expect(parseFilters(SECURITY_FILTERS, 'from=2026-11-03&to=2026-11-02')).toEqual({});
    // The tenant is not a filter of the tenant log.
    expect(parseFilters(SECURITY_FILTERS, 'tenantId=ten_01JAB00000000000000ENT1TYA')).toEqual({});
  });

  it('reads the tenant of the global log only when well formed', () => {
    const id = 'ten_01JAB00000000000000ENT1TYA';
    expect(parseFilters(GLOBAL_SECURITY_FILTERS, `tenantId=${id}`)).toEqual({ tenantId: id });
    expect(parseFilters(GLOBAL_SECURITY_FILTERS, 'tenantId=other')).toEqual({});
  });

  it('writes the filters in a stable order', () => {
    expect(filtersToQuery(GLOBAL_SECURITY_FILTERS, { to: '2026-11-02', type: 'sso_failed' })).toBe(
      'type=sso_failed&to=2026-11-02',
    );
  });
});

describe('filter form', () => {
  it('selects a known type and types an unknown one', () => {
    expect(securityFormOf({ type: 'rate_limited' })).toMatchObject({
      typeSelect: 'rate_limited',
      typeCustom: '',
    });
    expect(securityFormOf({ type: 'brand_new_type' })).toMatchObject({
      typeSelect: CUSTOM_TYPE,
      typeCustom: 'brand_new_type',
    });
    expect(securityFormOf({})).toEqual(emptySecurityForm());
  });

  it('takes the typed token when "other" is selected', () => {
    expect(formType({ ...emptySecurityForm(), typeSelect: 'unknown_fqdn' })).toBe('unknown_fqdn');
    expect(formType({ ...emptySecurityForm(), typeSelect: CUSTOM_TYPE, typeCustom: ' new_one ' })).toBe(
      'new_one',
    );
  });

  it('validates the token, the days and the order of the period', () => {
    const bad = submitSecurityForm(
      {
        ...emptySecurityForm(),
        typeSelect: CUSTOM_TYPE,
        typeCustom: 'Bad Token',
        from: '2026-11-03',
        to: '2026-11-01',
      },
      t,
    );
    expect(bad).toEqual({
      ok: false,
      first: 'typeCustom',
      errors: { typeCustom: 'fieldErrors.invalid-format', to: 'opsAudit.filters.range' },
    });
    expect(issueField({ field: 'type', code: 'too-long' })).toBe('typeCustom');
    expect(issueField({ field: 'to', code: 'range' })).toBe('to');
  });

  it('returns the filters of a valid form, the tenant only for the global log', () => {
    const form = {
      ...emptySecurityForm(),
      tenantId: 'ten_01JAB00000000000000ENT1TYA',
      typeSelect: 'sso_failed',
    };
    expect(submitSecurityForm(form, t)).toEqual({ ok: true, filters: { type: 'sso_failed' } });
    expect(submitSecurityForm(form, t, true)).toEqual({
      ok: true,
      filters: { tenantId: 'ten_01JAB00000000000000ENT1TYA', type: 'sso_failed' },
    });
    expect(submitSecurityForm({ ...form, tenantId: 'bad' }, t, true)).toMatchObject({
      ok: false,
      first: 'tenantId',
    });
  });
});

describe('api parameters', () => {
  it('sends the filters, the dates as instants and the cursor', () => {
    const p = securityApiParams(
      { type: 'rate_limited', from: '2026-11-01', to: '2026-11-02' },
      { cursor: 'abc' },
    );
    expect(p).toMatchObject({ type: 'rate_limited', limit: 50, cursor: 'abc' });
    expect(new Date(p.from as string).toISOString()).toBe(p.from);
    expect(new Date(p.to as string).toISOString()).toBe(p.to);
    expect((p.to as string) > (p.from as string)).toBe(true);
  });

  it('sends the tenant of the global log only', () => {
    const filters = { tenantId: 'ten_01JAB00000000000000ENT1TYA', type: 'sso_failed' };
    expect(securityApiParams(filters)).toEqual({ type: 'sso_failed', limit: 50 });
    expect(securityApiParams(filters, { global: true })).toEqual({
      tenantId: 'ten_01JAB00000000000000ENT1TYA',
      type: 'sso_failed',
      limit: 50,
    });
  });

  it('sends only the page size without filters', () => {
    expect(securityApiParams({})).toEqual({ limit: 50 });
  });
});

describe('row formatting', () => {
  it('counts at least one occurrence and shows the last one only when coalesced', () => {
    expect(occurrenceCount({})).toBe(1);
    expect(occurrenceCount({ occurrences: 0 })).toBe(1);
    expect(occurrenceCount({ occurrences: Number.NaN })).toBe(1);
    expect(occurrenceCount({ occurrences: 12 })).toBe(12);
    expect(lastSeen({ occurrences: 1, lastSeenAt: '2026-11-01T10:00:00Z' })).toBeUndefined();
    expect(lastSeen({ occurrences: 3 })).toBeUndefined();
    expect(lastSeen({ occurrences: 3, lastSeenAt: '' })).toBeUndefined();
    expect(lastSeen({ occurrences: 3, lastSeenAt: '2026-11-01T10:00:00Z' })).toBe('2026-11-01T10:00:00Z');
  });

  it('shows placeholders for a missing reason or IP', () => {
    expect(reasonText({}, t)).toBe('opsSecurity.list.noReason');
    expect(reasonText({ reason: '' }, t)).toBe('opsSecurity.list.noReason');
    expect(reasonText({ reason: 'password' }, t)).toBe('password');
    expect(ipText({ ip: '-' }, t)).toBe('opsSecurity.list.noIp');
    expect(ipText({ ip: '' }, t)).toBe('opsSecurity.list.noIp');
    expect(ipText({ ip: '203.0.113.7' }, t)).toBe('203.0.113.7');
  });

  it('words the loaded rows', () => {
    expect(loadedText(3, false, t)).toBe('opsSecurity.list.loaded {"count":3}');
    expect(loadedText(3, true, t)).toBe('opsSecurity.list.loadedMore {"count":3}');
  });
});
