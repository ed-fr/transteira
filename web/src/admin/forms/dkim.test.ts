import { describe, expect, it } from 'vitest';
import { MAX_DKIM_SELECTORS, dkimSelectorsValid, isDkimSelector, parseDkimSelectors } from './dkim';

describe('dkim selectors', () => {
  it('follows the pattern of the API', () => {
    expect(isDkimSelector('selector1')).toBe(true);
    expect(isDkimSelector('s1.mail-2024')).toBe(true);
    expect(isDkimSelector('-bad')).toBe(false);
    expect(isDkimSelector('bad-')).toBe(false);
    expect(isDkimSelector('a..b')).toBe(false);
    expect(isDkimSelector('under_score')).toBe(false);
    expect(isDkimSelector('a'.repeat(64))).toBe(false);
    expect(isDkimSelector('a'.repeat(63))).toBe(true);
  });

  it('parses a separated list without duplicates', () => {
    const r = parseDkimSelectors(' selector1, selector2\nselector1;bad_one  ');
    expect(r).toEqual({ selectors: ['selector1', 'selector2'], invalid: ['bad_one'], tooMany: false });
    expect(dkimSelectorsValid(r)).toBe(false);
    expect(dkimSelectorsValid(parseDkimSelectors(''))).toBe(true);
  });

  it('flags more selectors than allowed', () => {
    const many = Array.from({ length: MAX_DKIM_SELECTORS + 1 }, (_, i) => `s${i}`).join(' ');
    const r = parseDkimSelectors(many);
    expect(r.tooMany).toBe(true);
    expect(dkimSelectorsValid(r)).toBe(false);
  });
});
