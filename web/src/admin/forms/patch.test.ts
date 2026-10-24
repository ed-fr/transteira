import { describe, expect, it } from 'vitest';
import { buildPatch, deepEqual, isEmptyPatch } from './patch';

describe('deepEqual', () => {
  it('compares primitives, arrays and objects structurally', () => {
    expect(deepEqual(1, 1)).toBe(true);
    expect(deepEqual(NaN, NaN)).toBe(true);
    expect(deepEqual('a', 'b')).toBe(false);
    expect(deepEqual(null, {})).toBe(false);
    expect(deepEqual({}, null)).toBe(false);
    expect(deepEqual(1, '1')).toBe(false);
    expect(deepEqual(['a', 'b'], ['a', 'b'])).toBe(true);
    expect(deepEqual(['a', 'b'], ['b', 'a'])).toBe(false);
    expect(deepEqual(['a'], ['a', 'b'])).toBe(false);
    expect(deepEqual(['a'], { 0: 'a' })).toBe(false);
    expect(deepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] })).toBe(true);
    expect(deepEqual({ a: 1 }, { a: 1, b: 2 })).toBe(false);
    expect(deepEqual({ a: 1, c: 3 }, { a: 1, b: 3 })).toBe(false);
    expect(deepEqual({ a: 1 }, { a: 2 })).toBe(false);
  });
});

interface Tenant {
  name: string;
  fqdn: string;
  defaultLanguage: string;
  maxTransferBytes: number;
  tags?: string[] | null;
}

const original: Tenant = {
  name: 'Entity A',
  fqdn: 'transfer.entity-a.example.com',
  defaultLanguage: 'fr',
  maxTransferBytes: 1024,
  tags: ['a'],
};

describe('buildPatch', () => {
  it('returns only the changed allowed fields', () => {
    const edited = { ...original, name: 'Entity B', defaultLanguage: 'en', maxTransferBytes: 2048 };
    expect(buildPatch(original, edited, ['defaultLanguage', 'maxTransferBytes'])).toEqual({
      defaultLanguage: 'en',
      maxTransferBytes: 2048,
    });
  });

  it('is empty when nothing changed', () => {
    const patch = buildPatch(original, { ...original, tags: ['a'] }, ['name', 'tags']);
    expect(patch).toEqual({});
    expect(isEmptyPatch(patch)).toBe(true);
  });

  it('compares arrays by value', () => {
    expect(buildPatch(original, { ...original, tags: ['a', 'b'] }, ['tags'])).toEqual({ tags: ['a', 'b'] });
  });

  it('never sends null or undefined', () => {
    const patch = buildPatch(original, { ...original, tags: null }, ['tags']);
    expect(patch).toEqual({});
    const { tags: _tags, ...withoutTags } = original;
    expect(buildPatch<Tenant, 'tags'>(original, withoutTags, ['tags'])).toEqual({});
    expect(isEmptyPatch({ name: 'x' })).toBe(false);
  });
});
