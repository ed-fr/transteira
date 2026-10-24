import { describe, expect, it } from 'vitest';
import enBlocklist from '../../../locales/en/opsBlocklist.json';
import frBlocklist from '../../../locales/fr/opsBlocklist.json';
import enFieldErrors from '../../../locales/en/fieldErrors.json';
import frFieldErrors from '../../../locales/fr/fieldErrors.json';
import enTenants from '../../../locales/en/adminTenants.json';
import frTenants from '../../../locales/fr/adminTenants.json';
import type { ErrorView } from '../../../shared/api/problem';
import {
  afterDelete,
  checkValue,
  createErrorOutcome,
  emptyForm,
  entryBody,
  kindFilterOptions,
  kindLabel,
  kindOptions,
  loadedText,
  prependEntry,
  validateEntry,
  valueHint,
  type BlocklistEntry,
  type BlocklistFields,
  type Translate,
} from './blocklist';
import { emptyList, receivePage, startReset, type PagedList } from './paging';

const fakeT: Translate = (key, params) => (params === undefined ? key : `${key} ${JSON.stringify(params)}`);

const DIGEST = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

const fields: BlocklistFields = {
  kind: { id: 'f-kind', label: 'Kind' },
  value: { id: 'f-value', label: 'Value' },
  comment: { id: 'f-comment', label: 'Comment' },
};

function entry(over: Partial<BlocklistEntry> = {}): BlocklistEntry {
  return {
    id: 'blk_1',
    kind: 'domain',
    value: 'spam.example.net',
    createdBy: 'admin.entity-a',
    createdAt: '2026-10-10T08:00:00Z',
    ...over,
  };
}

function listOf(...rows: BlocklistEntry[]): PagedList<BlocklistEntry> {
  const s = startReset(emptyList<BlocklistEntry>());
  return receivePage(s, s.generation, { items: rows });
}

function view(over: Partial<ErrorView> = {}): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'general',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...over,
  };
}

describe('labels and options', () => {
  it('labels each kind and shows an unknown kind as is', () => {
    expect(kindLabel('email', fakeT)).toBe('opsBlocklist.kind.email');
    expect(kindLabel('domain', fakeT)).toBe('opsBlocklist.kind.domain');
    expect(kindLabel('sha256', fakeT)).toBe('opsBlocklist.kind.sha256');
    expect(kindLabel('ip', fakeT)).toBe('ip');
  });

  it('gives a hint per kind', () => {
    expect(valueHint('email', fakeT)).toBe('opsBlocklist.form.valueHint.email');
    expect(valueHint('domain', fakeT)).toBe('opsBlocklist.form.valueHint.domain');
    expect(valueHint('sha256', fakeT)).toBe('opsBlocklist.form.valueHint.sha256');
  });

  it('lists the kinds, with "all" first in the filter', () => {
    expect(kindOptions(fakeT).map((o) => o.value)).toEqual(['email', 'domain', 'sha256']);
    expect(kindFilterOptions(fakeT).map((o) => o.value)).toEqual(['', 'email', 'domain', 'sha256']);
  });

  it('counts the loaded entries', () => {
    expect(loadedText(2, false, fakeT)).toBe('opsBlocklist.loaded {"count":2}');
    expect(loadedText(50, true, fakeT)).toBe('opsBlocklist.loadedMore {"count":50}');
  });
});

describe('checkValue', () => {
  it('requires a value of at most 320 characters', () => {
    expect(checkValue('email', '   ')).toEqual({ ok: false, key: 'fieldErrors.required' });
    expect(checkValue('domain', 'a'.repeat(321))).toEqual({ ok: false, key: 'fieldErrors.too-long' });
  });

  it('checks an email address and lowercases it', () => {
    expect(checkValue('email', ' Mallory@Example.NET ')).toEqual({ ok: true, value: 'mallory@example.net' });
    expect(checkValue('email', 'mallory')).toEqual({ ok: false, key: 'fieldErrors.invalid-email' });
    expect(checkValue('email', 'Mallory <mallory@example.net>')).toEqual({
      ok: false,
      key: 'fieldErrors.invalid-email',
    });
  });

  it('checks a domain with parseDomain', () => {
    expect(checkValue('domain', 'Spam.Example.NET')).toEqual({ ok: true, value: 'spam.example.net' });
    expect(checkValue('domain', 'user@spam.example.net')).toEqual({
      ok: false,
      key: 'adminTenants.network.errors.domain.syntax',
    });
    expect(checkValue('domain', 'localhost')).toEqual({
      ok: false,
      key: 'adminTenants.network.errors.domain.singleLabel',
    });
    expect(checkValue('domain', 'spam.example.net.')).toEqual({
      ok: false,
      key: 'adminTenants.network.errors.domain.trailingDotSuggestion',
      params: { domain: 'spam.example.net' },
    });
  });

  it('checks a SHA-256 digest, upper case accepted and lowercased', () => {
    expect(checkValue('sha256', DIGEST)).toEqual({ ok: true, value: DIGEST });
    expect(checkValue('sha256', DIGEST.toUpperCase())).toEqual({ ok: true, value: DIGEST });
    expect(checkValue('sha256', DIGEST.slice(1))).toEqual({ ok: false, key: 'opsBlocklist.errors.sha256' });
    expect(checkValue('sha256', `${DIGEST.slice(1)}g`)).toEqual({
      ok: false,
      key: 'opsBlocklist.errors.sha256',
    });
  });
});

describe('validateEntry and entryBody', () => {
  it('starts from an empty email form', () => {
    expect(emptyForm()).toEqual({ kind: 'email', value: '', comment: '' });
  });

  it('reports the value and comment errors on their fields', () => {
    expect(validateEntry({ kind: 'sha256', value: 'abc', comment: 'x'.repeat(501) }, fields, fakeT)).toEqual([
      { id: 'f-value', label: 'Value', message: 'opsBlocklist.errors.sha256' },
      { id: 'f-comment', label: 'Comment', message: 'fieldErrors.too-long' },
    ]);
    expect(
      validateEntry({ kind: 'domain', value: 'example.com.', comment: '' }, fields, fakeT)[0]?.message,
    ).toBe('adminTenants.network.errors.domain.trailingDotSuggestion {"domain":"example.com"}');
    expect(
      validateEntry({ kind: 'email', value: 'a@example.com', comment: 'x'.repeat(500) }, fields, fakeT),
    ).toEqual([]);
  });

  it('builds the body with the normalised value, the comment trimmed or omitted', () => {
    expect(entryBody({ kind: 'sha256', value: DIGEST.toUpperCase(), comment: '  Known malware  ' })).toEqual({
      kind: 'sha256',
      value: DIGEST,
      comment: 'Known malware',
    });
    expect(entryBody({ kind: 'email', value: 'mallory@example.net', comment: '   ' })).toEqual({
      kind: 'email',
      value: 'mallory@example.net',
    });
    expect(entryBody({ kind: 'domain', value: 'bad', comment: '' })).toBeUndefined();
  });
});

describe('createErrorOutcome', () => {
  it('reports 409 already-exists on the value field', () => {
    const expected = {
      ok: false,
      errors: [{ id: 'f-value', label: 'Value', message: 'opsBlocklist.errors.alreadyExists' }],
    };
    expect(createErrorOutcome(view({ code: 'already-exists', status: 409 }), fields, fakeT)).toEqual(
      expected,
    );
    expect(createErrorOutcome(view({ status: 409 }), fields, fakeT)).toEqual(expected);
  });

  it('maps validation errors to the fields', () => {
    const v = view({
      code: 'validation-failed',
      status: 400,
      fields: { value: { code: 'invalid-domain', message: 'bad domain' } },
    });
    expect(createErrorOutcome(v, fields, fakeT)).toEqual({
      ok: false,
      errors: [{ id: 'f-value', label: 'Value', message: 'bad domain' }],
    });
  });

  it('adds the general message for unknown fields or other errors', () => {
    const unmatched = view({
      status: 400,
      fields: { value: { code: 'invalid', message: 'bad' }, other: { code: 'invalid', message: 'x' } },
    });
    expect(createErrorOutcome(unmatched, fields, fakeT)).toEqual({
      ok: false,
      errors: [{ id: 'f-value', label: 'Value', message: 'bad' }],
      message: 'general',
    });
    expect(createErrorOutcome(view({ status: 500 }), fields, fakeT)).toEqual({
      ok: false,
      errors: [],
      message: 'general',
    });
  });
});

describe('list updates', () => {
  it('prepends the created entry unless filtered on another kind', () => {
    const state = listOf(entry());
    const created = entry({ id: 'blk_2', kind: 'sha256', value: DIGEST });
    expect(prependEntry(state, created, {}).items.map((r) => r.id)).toEqual(['blk_2', 'blk_1']);
    expect(prependEntry(state, created, { kind: 'sha256' }).items.map((r) => r.id)).toEqual([
      'blk_2',
      'blk_1',
    ]);
    expect(prependEntry(state, created, { kind: 'domain' })).toBe(state);
  });

  it('does not duplicate an entry already shown', () => {
    const state = listOf(entry());
    expect(prependEntry(state, entry({ comment: 'new' }), {}).items).toEqual([entry({ comment: 'new' })]);
  });

  it('removes a deleted entry', () => {
    expect(afterDelete(listOf(entry(), entry({ id: 'blk_2' })), 'blk_1').items.map((r) => r.id)).toEqual([
      'blk_2',
    ]);
  });
});

describe('message keys', () => {
  const bundles: Record<string, [unknown, unknown]> = {
    opsBlocklist: [enBlocklist, frBlocklist],
    fieldErrors: [enFieldErrors, frFieldErrors],
    adminTenants: [enTenants, frTenants],
  };

  function lookup(bundle: unknown, path: string[]): unknown {
    let node = bundle;
    for (const part of path) {
      node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
    }
    return node;
  }

  it('exist in English and French', () => {
    const keys: string[] = [];
    const t: Translate = (key) => {
      keys.push(key);
      return key;
    };
    kindOptions(t);
    kindFilterOptions(t);
    for (const k of ['email', 'domain', 'sha256'] as const) {
      valueHint(k, t);
    }
    loadedText(1, false, t);
    loadedText(1, true, t);
    validateEntry({ kind: 'sha256', value: '', comment: 'x'.repeat(501) }, fields, t);
    validateEntry({ kind: 'sha256', value: 'x', comment: '' }, fields, t);
    validateEntry({ kind: 'email', value: 'x', comment: '' }, fields, t);
    validateEntry({ kind: 'domain', value: 'x', comment: '' }, fields, t);
    createErrorOutcome(view({ status: 409 }), fields, t);
    for (const key of keys) {
      const [area, ...path] = key.split('.') as [string, ...string[]];
      const pair = bundles[area];
      expect(pair, key).toBeDefined();
      expect(lookup(pair?.[0], path), key).toBeDefined();
      expect(lookup(pair?.[1], path), key).toBeDefined();
    }
  });
});
