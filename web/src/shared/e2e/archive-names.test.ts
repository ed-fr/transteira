import { describe, expect, it } from 'vitest';
import { ARCHIVE_NAME, FALLBACK_NAME, archiveEntries, safeFileName, validEntryNames } from './archive-names';
import { byteLength, checkPath } from '../validation/filepath';

// Cases mirrored from internal/filename/archive_test.go.
const root = (...names: string[]): string[] => archiveEntries(names.map((name) => ({ path: '', name })));
const second = (name: string): string => root(name, name)[1]!;

describe('safeFileName', () => {
  it('keeps valid names and replaces what Windows refuses', () => {
    expect(safeFileName('report.pdf')).toBe('report.pdf');
    expect(safeFileName('Why?.pdf')).toBe('Why_.pdf');
    expect(safeFileName('é.txt')).toBe('é.txt');
    expect(safeFileName('../x')).toBe(FALLBACK_NAME);
    expect(safeFileName('a‮b')).toBe(FALLBACK_NAME);
    expect(ARCHIVE_NAME).toBe('transfer.zip');
  });
});

describe('archiveEntries', () => {
  it('numbers duplicate names like the server', () => {
    const steps: [string, string][] = [
      ['a.txt', 'a.txt'],
      ['a.txt', 'a (2).txt'],
      ['A.TXT', 'A (3).TXT'],
      ['a (4).txt', 'a (4).txt'],
      ['a.txt', 'a (5).txt'],
      ['b', 'b'],
      ['B', 'B (2)'],
      ['archive.tar.gz', 'archive.tar.gz'],
      ['archive.tar.gz', 'archive.tar (2).gz'],
      ['', FALLBACK_NAME],
      ['../x', `${FALLBACK_NAME} (2)`],
      ['CON', `${FALLBACK_NAME} (3)`],
      ['Why?.pdf', 'Why_.pdf'],
      ['a<b>c"d|e*f', 'a_b_c_d_e_f'],
      ['é.txt', 'é.txt'],
      ['É.TXT', 'É (2).TXT'],
      ['.env', '.env'],
      ['.ENV', '.ENV (2)'],
      ['..env', '..env'],
      ['..env', '. (2).env'],
      ['.a.b', '.a.b'],
      ['.a.b', '.a (2).b'],
      ['q  .txt', 'q  .txt'],
      ['q  .txt', 'q (2).txt'],
      ['ǰ.txt', 'ǰ.txt'],
      ['J̌.txt', 'J̌ (2).txt'],
    ];
    expect(root(...steps.map((s) => s[0]))).toEqual(steps.map((s) => s[1]));
    expect(archiveEntries([])).toEqual([]);
  });

  it('keeps numbered names within 255 bytes', () => {
    expect(second('a'.repeat(251) + '.txt')).toBe('a'.repeat(247) + ' (2).txt');
    const multi = second('é'.repeat(125) + '.txt');
    expect(byteLength(multi)).toBeLessThanOrEqual(255);
    expect(multi.endsWith(' (2).txt')).toBe(true);
    const hugeExt = 'a.' + 'x'.repeat(252);
    expect(second(hugeExt)).toBe(hugeExt.slice(0, 251) + ' (2)');
    expect(second('a'.repeat(245) + '  .  b.txt')).toBe('a'.repeat(245) + ' (2).txt');
    for (const got of root(...Array<string>(30).fill('z'.repeat(255)))) {
      expect(checkPath(got)).toEqual({ ok: true, value: got });
    }
  });

  it('falls back when nothing is left of the stem', () => {
    const name = '. '.repeat(124) + 'ab.txt';
    expect(byteLength(name)).toBe(254);
    expect(second(name)).toBe(`${FALLBACK_NAME} (2)`);
  });

  it('merges folders and keeps files apart from them', () => {
    const files = [
      { path: 'Plans/2026', name: 'a.pdf' },
      { path: 'PLANS/2026', name: 'b.pdf' },
      { path: 'plans/2026', name: 'A.PDF' },
      { path: 'Plans/Site?', name: 'c.pdf' },
      { path: 'plans/site_', name: 'd.pdf' },
      { path: 'été', name: 'x' },
      { path: 'ÉTÉ', name: 'y' },
      { path: '../etc', name: 'passwd' },
      { path: 'a//b', name: 'z' },
      { path: '%2e%2e', name: 'lit' },
      { path: 'Plans', name: '2026' },
      { path: '', name: 'PLANS.txt' },
      { path: 'Plans/Sub', name: 'x' },
      { path: '', name: 'Docs' },
      { path: 'docs', name: 'readme' },
      { path: '', name: 'plans' },
      { path: '', name: 'plans (2)' },
      { path: 'Plans', name: 'sub' },
      { path: 'Docs (2)', name: 'f' },
      { path: 'Plans/2026', name: 'a (2).pdf' },
    ];
    expect(archiveEntries(files)).toEqual([
      'Plans/2026/a.pdf',
      'Plans/2026/b.pdf',
      'Plans/2026/A (2).PDF',
      'Plans/Site_/c.pdf',
      'Plans/Site_/d.pdf',
      'été/x',
      'été/y',
      'passwd',
      'z',
      '%2e%2e/lit',
      'Plans/2026 (2)',
      'PLANS.txt',
      'Plans/Sub/x',
      'Docs (3)',
      'docs/readme',
      'plans (2)',
      'plans (2) (2)',
      'Plans/sub (2)',
      'Docs (2)/f',
      'Plans/2026/a (2) (2).pdf',
    ]);
  });
});

describe('validEntryNames', () => {
  it('accepts valid, normalised and distinct entry paths', () => {
    expect(validEntryNames(['a.txt', 'dir/b.txt', 'dir/c.txt'])).toBe(true);
    expect(validEntryNames([])).toBe(true);
  });

  it('refuses empty, invalid, unnormalised or duplicate paths', () => {
    expect(validEntryNames([''])).toBe(false);
    expect(validEntryNames(['../a'])).toBe(false);
    expect(validEntryNames(['a/'])).toBe(false);
    expect(validEntryNames(['é.txt'])).toBe(false);
    expect(validEntryNames(['A.txt', 'a.TXT'])).toBe(false);
  });
});
