import { describe, expect, it } from 'vitest';
import { checkPath, checkSegment } from './filepath';

describe('checkSegment', () => {
  it('accepts ordinary names and normalises to NFC', () => {
    expect(checkSegment('report.pdf')).toEqual({ ok: true, value: 'report.pdf' });
    expect(checkSegment('.env')).toEqual({ ok: true, value: '.env' });
    expect(checkSegment('e\u0301.txt')).toEqual({ ok: true, value: '\u00e9.txt' });
  });

  it.each([
    ['', 'empty'],
    ['a'.repeat(256), 'too-long'],
    ['\u00e9'.repeat(128), 'too-long'],
    ['a\\b', 'path-separator'],
    ['a:b', 'path-separator'],
    ['a\u2215b', 'path-separator'],
    ['a\u0000b', 'control-character'],
    ['a\u202eb', 'bidi-control'],
    ['a\u200bb', 'invisible-character'],
    ['a   b', 'space-run'],
    ['..', 'dot-name'],
    [' a', 'leading-or-trailing-space-or-dot'],
    ['a ', 'leading-or-trailing-space-or-dot'],
    ['a.', 'leading-or-trailing-space-or-dot'],
    ['nul.txt', 'reserved-name'],
    ['Com1.tar.gz', 'reserved-name'],
    ['AUX .log', 'reserved-name'],
    ['LPT\u00b9', 'reserved-name'],
    ['CONIN$', 'reserved-name'],
  ])('refuses %j (%s)', (name, reason) => {
    expect(checkSegment(name)).toEqual({ ok: false, reason });
  });

  it('allows two consecutive spaces and names that only start like a reserved name', () => {
    expect(checkSegment('a  b').ok).toBe(true);
    expect(checkSegment('console.txt').ok).toBe(true);
    expect(checkSegment('com10').ok).toBe(true);
  });
});

describe('checkPath', () => {
  it('accepts the root and nested folders', () => {
    expect(checkPath('')).toEqual({ ok: true, value: '' });
    expect(checkPath('a/b c/.git')).toEqual({ ok: true, value: 'a/b c/.git' });
  });

  it.each([
    ['/a', 'empty-segment'],
    ['a/', 'empty-segment'],
    ['a//b', 'empty-segment'],
    ['a/./b', 'dot-name'],
    ['a/../b', 'dot-name'],
    ['a\\b', 'path-separator'],
    ['C:/x', 'path-separator'],
    [Array.from({ length: 17 }, () => 'd').join('/'), 'too-deep'],
    [Array.from({ length: 5 }, () => 'd'.repeat(250)).join('/'), 'path-too-long'],
    ['ok/nul', 'reserved-name'],
  ])('refuses %j (%s)', (path, reason) => {
    expect(checkPath(path)).toEqual({ ok: false, reason });
  });

  it('accepts 16 folders', () => {
    expect(checkPath(Array.from({ length: 16 }, () => 'd').join('/')).ok).toBe(true);
  });
});
