import { describe, expect, it } from 'vitest';
import { auditActionValues, auditEventActorKindValues } from '../../../shared/api/schema';
import { lookup, type Messages } from '../../../shared/i18n/messages';
import enAudit from '../../../locales/en/opsAudit.json';
import frAudit from '../../../locales/fr/opsAudit.json';
import {
  AUDIT_ACTION_GROUPS,
  AUDIT_OBJECT_KINDS,
  actionKey,
  actionLabel,
  actorKindLabel,
  actorView,
  auditActionGroups,
  detailEntries,
  detailValue,
  isErased,
  isKnownAction,
  objectKindLabel,
  objectPath,
  objectView,
  type Translate,
} from './auditLabels';

const bundles: Record<string, Messages> = {
  en: { opsAudit: enAudit as Messages },
  fr: { opsAudit: frAudit as Messages },
};

/** Fake translation: the key, with the parameters appended. */
const t: Translate = (key, params) => (params === undefined ? key : `${key}${JSON.stringify(params)}`);

describe('action labels', () => {
  it('has an English and a French label for every action of the specification', () => {
    expect(auditActionValues.length).toBeGreaterThanOrEqual(57);
    for (const [lang, messages] of Object.entries(bundles)) {
      for (const action of auditActionValues) {
        const label = lookup(messages, actionKey(action));
        expect(typeof label, `${lang} ${action}`).toBe('string');
        expect((label as string).trim(), `${lang} ${action}`).not.toBe('');
      }
    }
  });

  it('has labels for every group, actor kind and object kind', () => {
    for (const [lang, messages] of Object.entries(bundles)) {
      for (const group of AUDIT_ACTION_GROUPS) {
        expect(typeof lookup(messages, `opsAudit.groups.${group.id}`), `${lang} ${group.id}`).toBe('string');
      }
      for (const kind of auditEventActorKindValues) {
        expect(typeof lookup(messages, `opsAudit.actorKinds.${kind}`), `${lang} ${kind}`).toBe('string');
      }
      for (const kind of AUDIT_OBJECT_KINDS) {
        expect(typeof lookup(messages, `opsAudit.objectKinds.${kind}`), `${lang} ${kind}`).toBe('string');
      }
    }
  });

  it('translates known actions and shows unknown ones raw', () => {
    expect(actionLabel('transfer.deleted', t)).toBe('opsAudit.actions.transfer.deleted');
    expect(actionLabel('report.filed', t)).toBe('report.filed');
    expect(isKnownAction('setup.completed')).toBe(true);
    expect(isKnownAction('setup')).toBe(false);
  });
});

describe('action groups', () => {
  it('places every action of the specification in exactly one group', () => {
    const grouped = AUDIT_ACTION_GROUPS.flatMap((g) => [...g.actions]);
    expect(new Set(grouped).size).toBe(grouped.length);
    expect([...grouped].sort()).toEqual([...auditActionValues].sort());
  });

  it('builds the optgroups of the select field', () => {
    const groups = auditActionGroups(t);
    expect(groups.map((g) => g.group)).toEqual(AUDIT_ACTION_GROUPS.map((g) => g.id));
    const transfers = groups[0];
    expect(transfers?.label).toBe('opsAudit.groups.transfers');
    expect(transfers?.options[0]).toEqual({
      value: 'transfer.created',
      label: 'opsAudit.actions.transfer.created',
    });
  });

  it('leaves out excluded groups', () => {
    const ids = auditActionGroups(t, { exclude: ['instance', 'accounts'] }).map((g) => g.group);
    expect(ids).not.toContain('instance');
    expect(ids).not.toContain('accounts');
    expect(ids).toContain('transfers');
  });
});

describe('actor and object display', () => {
  it('labels known kinds and keeps unknown ones raw', () => {
    expect(actorKindLabel('admin', t)).toBe('opsAudit.actorKinds.admin');
    expect(actorKindLabel('robot', t)).toBe('robot');
    expect(objectKindLabel('transfer', t)).toBe('opsAudit.objectKinds.transfer');
    expect(objectKindLabel('report', t)).toBe('report');
  });

  it('shows the identifier of each actor kind', () => {
    expect(actorView({ kind: 'admin', id: 'alice' }, t)).toEqual({
      kind: 'opsAudit.actorKinds.admin',
      id: 'alice',
    });
    expect(actorView({ kind: 'depositor', id: 'bob@entity-a.example.com' }, t).id).toBe(
      'bob@entity-a.example.com',
    );
    expect(actorView({ kind: 'api_token', id: 'tok_01' }, t).id).toBe('tok_01');
    expect(actorView({ kind: 'system', id: 'lifecycle' }, t).id).toBe('lifecycle');
    expect(actorView({ kind: 'recipient', id: 'link' }, t).id).toBe('opsAudit.actor.recipientLink');
    expect(actorView({ kind: 'admin', id: 'link' }, t).id).toBe('link');
  });

  it('shows erased pseudonyms as is with a hint', () => {
    const view = actorView({ kind: 'depositor', id: 'erased-3f2a' }, t);
    expect(view.id).toBe('erased-3f2a');
    expect(view.hint).toBe('opsAudit.actor.erasedHint');
    expect(isErased('erased-x')).toBe(true);
    expect(isErased('alice')).toBe(false);
    expect(objectView({ kind: 'data_subject', id: 'erased-3f2a' }, t)).toEqual({
      kind: 'opsAudit.objectKinds.data_subject',
      id: 'erased-3f2a',
      hint: 'opsAudit.actor.erasedHint',
    });
    expect(objectView({ kind: 'file', id: 'fil_1' }, t).hint).toBeUndefined();
  });

  it('links a transfer object to its detail in the tenant', () => {
    expect(objectPath('ten_1', { kind: 'transfer', id: 'trf 1' })).toBe('/tenants/ten_1/transfers/trf%201');
    expect(objectPath('ten_1', { kind: 'file', id: 'fil_1' })).toBeUndefined();
    expect(objectPath('ten_1', { kind: 'transfer', id: '' })).toBeUndefined();
    expect(objectPath(undefined, { kind: 'transfer', id: 'trf_1' })).toBeUndefined();
    expect(objectPath(null, { kind: 'transfer', id: 'trf_1' })).toBeUndefined();
    expect(objectPath('', { kind: 'transfer', id: 'trf_1' })).toBeUndefined();
  });
});

describe('details', () => {
  it('flattens values to text', () => {
    expect(detailValue('<b>x</b>')).toBe('<b>x</b>');
    expect(detailValue(3)).toBe('3');
    expect(detailValue(true)).toBe('true');
    expect(detailValue(null)).toBe('null');
    expect(detailValue(undefined)).toBe('undefined');
    expect(detailValue(['fr', 'en'])).toBe('["fr","en"]');
    expect(detailValue({ a: { b: 1 } })).toBe('{"a":{"b":1}}');
  });

  it('lists the details in order', () => {
    expect(detailEntries({ fileCount: 2, languages: ['fr'], reason: null, nested: { k: 'v' } })).toEqual([
      { key: 'fileCount', value: '2' },
      { key: 'languages', value: '["fr"]' },
      { key: 'reason', value: 'null' },
      { key: 'nested', value: '{"k":"v"}' },
    ]);
  });

  it('gives no lines without details', () => {
    expect(detailEntries(undefined)).toEqual([]);
    expect(detailEntries(null)).toEqual([]);
    expect(detailEntries({})).toEqual([]);
    expect(detailEntries('x' as unknown as Record<string, unknown>)).toEqual([]);
  });
});
