import { describe, expect, it, vi } from 'vitest';
import {
  LANGUAGE_STORAGE_KEY,
  browserStorage,
  changeLanguage,
  initLanguage,
  pickInitialLanguage,
  readStoredLanguage,
  storeLanguage,
  type LanguageStorage,
} from './language';

function memoryStorage(
  initial: Record<string, string> = {},
): LanguageStorage & { data: Record<string, string> } {
  const data = { ...initial };
  return {
    data,
    getItem: (key) => data[key] ?? null,
    setItem: (key, value) => {
      data[key] = value;
    },
  };
}

const throwing: LanguageStorage = {
  getItem: () => {
    throw new Error('SecurityError');
  },
  setItem: () => {
    throw new Error('QuotaExceededError');
  },
};

describe('storage access', () => {
  it('reads and writes tt.lang', () => {
    const storage = memoryStorage();
    expect(readStoredLanguage(storage)).toBeUndefined();
    storeLanguage(storage, 'fr');
    expect(storage.data[LANGUAGE_STORAGE_KEY]).toBe('fr');
    expect(readStoredLanguage(storage)).toBe('fr');
  });

  it('tolerates missing or throwing storage', () => {
    expect(readStoredLanguage(undefined)).toBeUndefined();
    expect(readStoredLanguage(throwing)).toBeUndefined();
    expect(() => storeLanguage(throwing, 'fr')).not.toThrow();
    expect(() => storeLanguage(undefined, 'fr')).not.toThrow();
  });

  it('returns undefined outside a browser and when localStorage access throws', () => {
    expect(browserStorage()).toBeUndefined();
    vi.stubGlobal('localStorage', memoryStorage());
    expect(browserStorage()).toBeDefined();
    vi.unstubAllGlobals();
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get() {
        throw new Error('SecurityError');
      },
    });
    expect(browserStorage()).toBeUndefined();
    Reflect.deleteProperty(globalThis, 'localStorage');
  });
});

describe('pickInitialLanguage', () => {
  const base = { available: ['fr', 'en'], tenantLanguage: 'fr' };

  it('prefers a stored language offered by the tenant', () => {
    expect(
      pickInitialLanguage({ ...base, storage: memoryStorage({ 'tt.lang': 'en' }), browserLanguages: ['fr'] }),
    ).toBe('en');
  });

  it('ignores a stored language the tenant does not offer', () => {
    expect(
      pickInitialLanguage({ ...base, available: ['fr'], storage: memoryStorage({ 'tt.lang': 'en' }) }),
    ).toBe('fr');
    expect(pickInitialLanguage({ ...base, storage: memoryStorage({ 'tt.lang': '<script>' }) })).toBe('fr');
  });

  it('uses the first offered browser language, by primary subtag', () => {
    expect(pickInitialLanguage({ ...base, browserLanguages: ['de-DE', 'EN-gb', 'fr'] })).toBe('en');
    expect(pickInitialLanguage({ ...base, browserLanguages: ['de', ''] })).toBe('fr');
  });

  it('falls back to the tenant language', () => {
    expect(pickInitialLanguage({ ...base, storage: throwing })).toBe('fr');
    expect(pickInitialLanguage({ available: ['fr', 'en'], tenantLanguage: 'en' })).toBe('en');
  });
});

describe('initLanguage and changeLanguage', () => {
  it('loads the picked language', async () => {
    const setLocale = vi.fn(async (lang: string) => lang);
    expect(await initLanguage({ setLocale }, { available: ['fr', 'en'], tenantLanguage: 'en' })).toBe('en');
    expect(setLocale).toHaveBeenCalledWith('en');
  });

  it('remembers the applied language', async () => {
    const storage = memoryStorage();
    const setLocale = vi.fn(async () => 'en');
    expect(await changeLanguage({ setLocale }, 'xx', storage)).toBe('en');
    expect(storage.data['tt.lang']).toBe('en');
  });
});
