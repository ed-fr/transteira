import { describe, expect, it } from 'vitest';
import { joinLines, parseLineList, splitLines, type ParseResult } from './lines';

function upper(raw: string): ParseResult<'bad'> {
  if (raw === 'bad') {
    return { ok: false, error: 'bad' };
  }
  if (raw === 'fixable') {
    return { ok: false, error: 'bad', suggestion: 'FIXED' };
  }
  return { ok: true, value: raw.toUpperCase() };
}

describe('lines', () => {
  it('splits on every line break', () => {
    expect(splitLines('a\nb\r\nc\rd')).toEqual(['a', 'b', 'c', 'd']);
  });

  it('parses each line with its number, skipping blanks and duplicates', () => {
    const r = parseLineList('a\n\n  bad \nA\nfixable\nb', upper);
    expect(r.values).toEqual(['A', 'B']);
    expect(r.errors).toEqual([
      { line: 3, raw: 'bad', error: 'bad' },
      { line: 5, raw: 'fixable', error: 'bad', suggestion: 'FIXED' },
    ]);
    expect(r.duplicates).toEqual([4]);
    expect(r.tooMany).toBe(false);
  });

  it('flags more values than the maximum', () => {
    expect(parseLineList('a\nb\nc', upper, 2).tooMany).toBe(true);
    expect(parseLineList('a\nb', upper, 2).tooMany).toBe(false);
    expect(parseLineList('', upper, 0).values).toEqual([]);
  });

  it('joins values one per line', () => {
    expect(joinLines(['a', 'b'])).toBe('a\nb');
  });
});
