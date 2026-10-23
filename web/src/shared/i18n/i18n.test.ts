import { describe, expect, it, vi } from 'vitest';
import {
  createI18n,
  formatBytes,
  formatDate,
  formatNumber,
  groupLoaders,
  i18n,
  interpolate,
  locale,
  lookup,
  setLocale,
  supportedLanguages,
  t,
  type LocaleLoader,
  type Messages,
} from './i18n.svelte';

function mod(messages: Messages): LocaleLoader {
  return async () => ({ default: messages });
}

const loaders: Record<string, LocaleLoader> = {
  '../../locales/en/common.json': mod({
    hello: 'Hello {name}',
    files: { one: '{count} file', other: '{count} files' },
    nested: { deep: { key: 'Deep' } },
    total: 'Total {n}',
  }),
  '../../locales/en/errors.json': mod({ 'not-found': 'Not found' }),
  '../../locales/fr/common.json': mod({
    hello: 'Bonjour {name}',
    files: { one: '{count} fichier', other: '{count} fichiers' },
  }),
  '../../locales/fr/broken.json': async () => ({ default: 'not an object' }),
  'ignored/path.txt': mod({}),
};

describe('helpers', () => {
  it('groups loaders by language and area, ignoring other paths', () => {
    const grouped = groupLoaders(loaders);
    expect([...grouped.keys()].sort()).toEqual(['en', 'fr']);
    expect([...(grouped.get('en')?.keys() ?? [])].sort()).toEqual(['common', 'errors']);
  });

  it('looks up dotted keys without prototype access', () => {
    const tree: Messages = { a: { b: 'x' } };
    expect(lookup(tree, 'a.b')).toBe('x');
    expect(lookup(tree, 'a.c')).toBeUndefined();
    expect(lookup(tree, 'a.b.c')).toBeUndefined();
    expect(lookup(tree, 'toString')).toBeUndefined();
    expect(lookup(tree, 'a.constructor')).toBeUndefined();
  });

  it('interpolates, formats numbers and keeps unknown placeholders', () => {
    const nf = new Intl.NumberFormat('en');
    expect(interpolate('{a} and {b} {c}', { a: 'x', b: 1234 }, nf)).toBe('x and 1,234 {c}');
    expect(interpolate('{a}', undefined, nf)).toBe('{a}');
    expect(interpolate('{toString}', {}, nf)).toBe('{toString}');
  });

  it('lists the API languages', () => {
    expect(supportedLanguages).toEqual(['fr', 'en']);
  });
});

describe('createI18n', () => {
  it('returns keys before any bundle is loaded and reports them as missing', () => {
    const onMissing = vi.fn();
    const inst = createI18n({ loaders, onMissing });
    expect(inst.locale.current).toBe('');
    expect(inst.t('common.hello')).toBe('common.hello');
    expect(onMissing).toHaveBeenCalledWith('common.hello', '');
  });

  it('loads a language, merges areas under their names and sets the root lang', async () => {
    const root = { lang: '' };
    const inst = createI18n({ loaders, root });
    expect(await inst.setLocale('en')).toBe('en');
    expect(inst.locale.current).toBe('en');
    expect(root.lang).toBe('en');
    expect(inst.languages).toEqual(['en', 'fr']);
    expect(inst.t('common.hello', { name: 'Ada' })).toBe('Hello Ada');
    expect(inst.t('errors.not-found')).toBe('Not found');
    expect(inst.t('common.nested.deep.key')).toBe('Deep');
    expect(inst.has('common.hello')).toBe(true);
    expect(inst.has('common.files')).toBe(true);
    expect(inst.has('common.nested')).toBe(false);
    expect(inst.has('common.absent')).toBe(false);
  });

  it('selects plural forms with Intl.PluralRules', async () => {
    const inst = createI18n({ loaders });
    await inst.setLocale('en');
    expect(inst.t('common.files', { count: 1 })).toBe('1 file');
    expect(inst.t('common.files', { count: 0 })).toBe('0 files');
    expect(inst.t('common.files', { count: 2000 })).toBe('2,000 files');
    expect(inst.t('common.files')).toBe('{count} files');
    expect(inst.t('common.files.one', { count: 5 })).toBe('5 file');
    await inst.setLocale('fr');
    // French: 0 and 1 are "one".
    expect(inst.t('common.files', { count: 0 })).toBe('0 fichier');
    expect(inst.t('common.files', { count: 2 })).toBe('2 fichiers');
  });

  it('falls back to "other" when the plural category is absent', async () => {
    const inst = createI18n({
      loaders: { '/en/a.json': mod({ p: { other: '{count} x' }, bad: { one: 'x', other: { no: 'y' } } }) },
    });
    await inst.setLocale('en');
    expect(inst.t('a.p', { count: 1 })).toBe('1 x');
    expect(inst.t('a.bad', { count: 2 })).toBe('a.bad');
  });

  it('renders missing keys and non-string nodes as the key', async () => {
    const inst = createI18n({ loaders });
    await inst.setLocale('en');
    expect(inst.t('common.nested')).toBe('common.nested');
    expect(inst.t('nope.nope')).toBe('nope.nope');
  });

  it('falls back to the fallback language for unknown languages and ignores bad modules', async () => {
    const inst = createI18n({ loaders, fallbackLanguage: 'fr' });
    expect(await inst.setLocale('de')).toBe('fr');
    expect(inst.t('common.hello', { name: 'A' })).toBe('Bonjour A');
    expect(inst.has('broken.x')).toBe(false);
    const empty = createI18n({ loaders: {} });
    expect(await empty.setLocale('xx')).toBe('en');
    expect(empty.t('a')).toBe('a');
  });

  it('caches bundles and lets the latest of overlapping loads win', async () => {
    let calls = 0;
    let release: () => void = () => {};
    const slow: LocaleLoader = () =>
      new Promise((resolve) => {
        calls++;
        release = () => resolve({ default: { k: 'slow' } });
      });
    const inst = createI18n({ loaders: { '/en/a.json': slow, '/fr/a.json': mod({ k: 'fast' }) } });
    const first = inst.setLocale('en');
    await inst.setLocale('fr');
    release();
    await first;
    expect(inst.locale.current).toBe('fr');
    expect(inst.t('a.k')).toBe('fast');
    await inst.setLocale('en');
    await inst.setLocale('en');
    expect(calls).toBe(1);
    expect(inst.t('a.k')).toBe('slow');
  });

  it('formats bytes with binary multiples', async () => {
    const inst = createI18n({ loaders });
    expect(inst.formatBytes(0)).toBe('0 byte');
    await inst.setLocale('en');
    expect(inst.formatBytes(-5)).toBe('0 byte');
    expect(inst.formatBytes(512)).toBe('512 byte');
    expect(inst.formatBytes(1536)).toBe('1.5 kB');
    expect(inst.formatBytes(20 * 1024 ** 3)).toBe('20 GB');
    expect(inst.formatBytes(150 * 1024 ** 2)).toBe('150 MB');
    expect(inst.formatBytes(2 * 1024 ** 6)).toBe('2,048 PB');
    await inst.setLocale('fr');
    expect(inst.formatBytes(20 * 1024 ** 3)).toBe('20 Go');
  });

  it('formats dates and numbers', async () => {
    const inst = createI18n({ loaders });
    await inst.setLocale('en');
    const iso = '2026-10-19T16:00:00Z';
    expect(inst.formatDate(iso, { dateStyle: 'medium', timeZone: 'UTC' })).toBe('Oct 19, 2026');
    expect(inst.formatDate(new Date(iso))).toContain('2026');
    expect(inst.formatDate(Date.parse(iso))).toContain('2026');
    expect(inst.formatDate('not a date')).toBe('');
    expect(inst.formatNumber(1234.5)).toBe('1,234.5');
    expect(inst.formatNumber(0.5, { style: 'percent' })).toBe('50%');
  });
});

describe('shared instance', () => {
  it('loads the real bundles through import.meta.glob', async () => {
    expect(i18n.languages).toEqual(expect.arrayContaining(['fr', 'en']));
    expect(await setLocale('fr')).toBe('fr');
    expect(locale.current).toBe('fr');
    expect(t('common.appName')).toBe('TransTeira');
    expect(t('common.attemptsRemaining', { count: 2 })).toBe('2 essais restants.');
    expect(formatBytes(1024)).toBe('1 ko');
    expect(formatNumber(1000)).toBe('1 000');
    expect(formatDate('2026-10-19T16:00:00Z', { year: 'numeric', timeZone: 'UTC' })).toBe('2026');
    await setLocale('en');
    expect(t('errors.not-found')).toBe('This page or resource does not exist.');
  });
});
