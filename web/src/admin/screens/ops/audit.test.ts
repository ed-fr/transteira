import { describe, expect, it } from 'vitest';
import {
  actionEntries,
  auditFormOf,
  CUSTOM_ACTION,
  formAction,
  issueField,
  issueMessage,
  loadedText,
  submitAuditForm,
  type AuditForm,
} from './audit';
import type { Translate } from './auditLabels';

const t: Translate = (key, params) => (params === undefined ? key : `${key}${JSON.stringify(params)}`);

const blank: AuditForm = { actionSelect: '', actionCustom: '', actor: '', from: '', to: '' };

describe('actionEntries', () => {
  it('starts with "any action", ends with "other" and leaves the instance and account actions out', () => {
    const entries = actionEntries(t);
    expect(entries[0]).toEqual({ value: '', label: 'opsAudit.filters.anyAction' });
    expect(entries.at(-1)).toEqual({ value: CUSTOM_ACTION, label: 'opsAudit.filters.customAction' });
    const groups = entries.filter((e) => 'options' in e).map((e) => ('group' in e ? e.group : ''));
    expect(groups).toContain('transfers');
    expect(groups).not.toContain('instance');
    expect(groups).not.toContain('accounts');
  });
});

describe('auditFormOf', () => {
  it('fills an empty form without filters', () => {
    expect(auditFormOf({}, t)).toEqual(blank);
  });

  it('selects a listed action', () => {
    expect(
      auditFormOf({ action: 'transfer.deleted', actor: 'alice', from: '2026-10-01', to: '2026-10-02' }, t),
    ).toEqual({
      actionSelect: 'transfer.deleted',
      actionCustom: '',
      actor: 'alice',
      from: '2026-10-01',
      to: '2026-10-02',
    });
  });

  it('puts an unlisted or unknown action in the typed code', () => {
    expect(auditFormOf({ action: 'maintenance.enabled' }, t)).toMatchObject({
      actionSelect: CUSTOM_ACTION,
      actionCustom: 'maintenance.enabled',
    });
    expect(auditFormOf({ action: 'admin.login' }, t)).toMatchObject({
      actionSelect: CUSTOM_ACTION,
      actionCustom: 'admin.login',
    });
    expect(auditFormOf({ action: 'report.filed' }, t)).toMatchObject({
      actionSelect: CUSTOM_ACTION,
      actionCustom: 'report.filed',
    });
  });
});

describe('formAction', () => {
  it('uses the typed code only when "other" is selected', () => {
    expect(formAction({ ...blank, actionSelect: 'transfer.created', actionCustom: 'x.y' })).toBe(
      'transfer.created',
    );
    expect(formAction({ ...blank, actionSelect: CUSTOM_ACTION, actionCustom: ' report.filed ' })).toBe(
      'report.filed',
    );
  });
});

describe('submitAuditForm', () => {
  it('gives the filters of a valid form', () => {
    expect(submitAuditForm({ ...blank, actionSelect: 'transfer.created', actor: ' alice ' }, t)).toEqual({
      ok: true,
      filters: { action: 'transfer.created', actor: 'alice' },
    });
    expect(submitAuditForm(blank, t)).toEqual({ ok: true, filters: {} });
  });

  it('reports an invalid typed action on the code field', () => {
    const result = submitAuditForm(
      { ...blank, actionSelect: CUSTOM_ACTION, actionCustom: 'Not-An-Action' },
      t,
    );
    expect(result).toEqual({
      ok: false,
      errors: { actionCustom: 'fieldErrors.invalid-format' },
      first: 'actionCustom',
    });
  });

  it('reports a reversed period on the end field', () => {
    const result = submitAuditForm({ ...blank, from: '2026-10-10', to: '2026-10-01' }, t);
    expect(result).toEqual({ ok: false, errors: { to: 'opsAudit.filters.range' }, first: 'to' });
  });

  it('keeps the first message of each field and the first invalid field', () => {
    const result = submitAuditForm({ ...blank, actor: 'a'.repeat(321), from: 'nope' }, t);
    expect(result).toEqual({
      ok: false,
      errors: { actor: 'fieldErrors.too-long', from: 'fieldErrors.invalid-format' },
      first: 'actor',
    });
  });
});

describe('issues', () => {
  it('maps fields and messages', () => {
    expect(issueField({ field: 'action', code: 'invalid-format' })).toBe('actionCustom');
    expect(issueField({ field: 'from', code: 'invalid-format' })).toBe('from');
    expect(issueMessage({ field: 'to', code: 'range' }, t)).toBe('opsAudit.filters.range');
    expect(issueMessage({ field: 'actor', code: 'too-long' }, t)).toBe('fieldErrors.too-long');
  });
});

describe('loadedText', () => {
  it('tells whether more events can be loaded', () => {
    expect(loadedText(3, false, t)).toBe('opsAudit.list.loaded{"count":3}');
    expect(loadedText(50, true, t)).toBe('opsAudit.list.loadedMore{"count":50}');
  });
});
