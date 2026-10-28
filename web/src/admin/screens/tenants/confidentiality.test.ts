import { describe, expect, it } from 'vitest';
import {
  addLevel,
  fromDraft,
  levelsBody,
  levelsChanged,
  moveLevel,
  newDraft,
  parseCap,
  parseServerPath,
  removeLevel,
  serverLevelErrors,
  setDefault,
  toDraft,
  validateLevels,
  type ConfidentialityLevel,
  type FieldRefOf,
  type LevelDraft,
} from './confidentiality';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const ref: FieldRefOf = (index, field) => ({ id: `l${index}-${field}`, label: `${index}/${field}` });

const level: ConfidentialityLevel = {
  key: 'confidential',
  labels: { fr: 'Confidentiel', en: 'Confidential' },
  descriptions: { en: 'Sensitive files' },
  isDefault: true,
  rules: {
    requireRecipientVerification: true,
    requirePassword: true,
    allowedExpiryDays: [1, 7],
    internalRecipientsOnly: true,
    forceDeleteAfterFirstDownload: false,
    maxDownloads: 3,
  },
};

function valid(uid: number, key: string, isDefault: boolean): LevelDraft {
  const d = newDraft(uid, isDefault);
  d.key = key;
  d.labels = { fr: `Niveau ${key}`, en: `Level ${key}` };
  return d;
}

describe('drafts', () => {
  it('round-trips a level', () => {
    expect(fromDraft(toDraft(level, 1))).toEqual(level);
  });

  it('omits empty descriptions and trims texts', () => {
    const d = valid(1, ' a ', true);
    d.labels = { fr: ' A ', en: 'A' };
    d.descriptions = { fr: '  ', en: '' };
    d.allowedExpiryDays = [30, 1];
    d.maxDownloadsText = ' 10 ';
    const out = fromDraft(d);
    expect(out.key).toBe('a');
    expect(out.labels).toEqual({ fr: 'A', en: 'A' });
    expect(out.descriptions).toBeUndefined();
    expect(out.rules.allowedExpiryDays).toEqual([1, 30]);
    expect(out.rules.maxDownloads).toBe(10);
  });

  it('reads the cap', () => {
    expect(parseCap('')).toBeNull();
    // bind:value on a number input yields a number, or null when empty.
    expect(parseCap(2)).toBe(2);
    expect(parseCap(null)).toBeNull();
    expect(parseCap('1000')).toBe(1000);
    expect(parseCap('1001')).toBeUndefined();
    expect(parseCap('0')).toBeUndefined();
    expect(parseCap('x')).toBeUndefined();
    expect(fromDraft({ ...valid(1, 'a', true), maxDownloadsText: 'x' }).rules.maxDownloads).toBeNull();
  });

  it('detects changes', () => {
    const drafts = [toDraft(level, 1)];
    expect(levelsChanged([level], drafts)).toBe(false);
    drafts[0]!.requirePassword = false;
    expect(levelsChanged([level], drafts)).toBe(true);
    expect(levelsBody(drafts).items).toHaveLength(1);
  });
});

describe('list operations', () => {
  const list = [valid(1, 'a', true), valid(2, 'b', false), valid(3, 'c', false)];

  it('moves levels', () => {
    expect(moveLevel(list, 1, -1).map((d) => d.key)).toEqual(['b', 'a', 'c']);
    expect(moveLevel(list, 1, 1).map((d) => d.key)).toEqual(['a', 'c', 'b']);
    expect(moveLevel(list, 0, -1).map((d) => d.key)).toEqual(['a', 'b', 'c']);
    expect(moveLevel(list, 2, 1).map((d) => d.key)).toEqual(['a', 'b', 'c']);
    expect(moveLevel(list, 9, -1)).toHaveLength(3);
  });

  it('keeps exactly one default', () => {
    expect(setDefault(list, 2).map((d) => d.isDefault)).toEqual([false, false, true]);
    expect(removeLevel(list, 0).map((d) => d.isDefault)).toEqual([true, false]);
    expect(removeLevel(list, 1).map((d) => d.isDefault)).toEqual([true, false]);
    expect(removeLevel([list[0]!], 0)).toEqual([]);
  });

  it('adds up to ten levels', () => {
    expect(addLevel([], 1)[0]?.isDefault).toBe(true);
    const added = addLevel(list, 4);
    expect(added).toHaveLength(4);
    expect(added[3]?.isDefault).toBe(false);
    let many = list;
    for (let i = 0; i < 10; i++) many = addLevel(many, 10 + i);
    expect(many).toHaveLength(10);
  });
});

describe('validateLevels', () => {
  it('accepts a valid list', () => {
    expect(validateLevels([valid(1, 'a', true), valid(2, 'b', false)], ref, t)).toEqual([]);
  });

  it('refuses an empty list', () => {
    expect(validateLevels([], ref, t).map((e) => e.message)).toEqual([
      'adminTenants.confidentiality.errors.noLevel',
    ]);
  });

  it('refuses too many levels and a wrong number of defaults', () => {
    const many = Array.from({ length: 11 }, (_v, i) => valid(i, `k${i}`, false));
    const messages = validateLevels(many, ref, t).map((e) => e.message);
    expect(messages).toContain('adminTenants.confidentiality.errors.tooMany {"max":10}');
    expect(messages).toContain('adminTenants.confidentiality.errors.defaultCount');
    const two = [valid(1, 'a', true), valid(2, 'b', true)];
    expect(validateLevels(two, ref, t)[0]?.id).toBe('l0-list');
  });

  it('checks keys, labels, descriptions, durations and cap', () => {
    const a = valid(1, '', true);
    const b = valid(2, 'Bad Key', false);
    const c = valid(3, 'b2', false);
    c.labels = { fr: '', en: 'x'.repeat(51) };
    c.descriptions = { fr: 'y'.repeat(501), en: '' };
    c.allowedExpiryDays = [];
    c.maxDownloadsText = '5000';
    const d = valid(4, 'b2', false);
    const out = validateLevels([a, b, c, d], ref, t);
    const byId = Object.fromEntries(out.map((e) => [e.id, e.message]));
    expect(byId['l0-key']).toBe('adminTenants.confidentiality.errors.keyRequired');
    expect(byId['l1-key']).toBe('adminTenants.confidentiality.errors.keyFormat');
    expect(byId['l2-key']).toBe('adminTenants.confidentiality.errors.keyDuplicate');
    expect(byId['l2-label.fr']).toBe('adminTenants.confidentiality.errors.labelRequired');
    expect(byId['l2-label.en']).toContain('labelTooLong');
    expect(byId['l2-description.fr']).toContain('descriptionTooLong');
    expect(byId['l2-days']).toBe('adminTenants.confidentiality.errors.daysRequired');
    expect(byId['l2-maxDownloads']).toContain('capInvalid');
    expect(byId['l3-key']).toBe('adminTenants.confidentiality.errors.keyDuplicate');
  });
});

describe('server errors', () => {
  it('parses field paths', () => {
    expect(parseServerPath('items')).toBe('list');
    expect(parseServerPath('items.1.key')).toEqual({ index: 1, field: 'key' });
    expect(parseServerPath('items.0.labels.fr')).toEqual({ index: 0, field: 'label.fr' });
    expect(parseServerPath('items.0.descriptions.en')).toEqual({ index: 0, field: 'description.en' });
    expect(parseServerPath('items.2.rules.allowedExpiryDays.0')).toEqual({ index: 2, field: 'days' });
    expect(parseServerPath('items.2.rules.maxDownloads')).toEqual({ index: 2, field: 'maxDownloads' });
    expect(parseServerPath('items.x.key')).toBeUndefined();
    expect(parseServerPath('items.0.labels.de')).toBeUndefined();
    expect(parseServerPath('other')).toBeUndefined();
  });

  it('maps errors to fields and keeps the others unmatched', () => {
    const drafts = [valid(1, 'a', true), valid(2, 'b', false)];
    const mapped = serverLevelErrors(
      {
        'items.1.key': { code: 'duplicate', message: 'dup' },
        'items.1.rules.maxDownloads': { code: 'too-large', message: 'big' },
        'items.5.key': { code: 'duplicate', message: 'ghost' },
        items: { code: 'too-many', message: 'many' },
        'items.0.labels.en': { code: 'required', message: 'req' },
      },
      drafts,
      ref,
    );
    expect(mapped.errors.map((e) => [e.id, e.message])).toEqual([
      ['l1-key', 'dup'],
      ['l1-maxDownloads', 'big'],
      ['l0-label.en', 'req'],
    ]);
    expect(mapped.unmatched).toEqual(['items.5.key', 'items']);
  });
});
