import { describe, expect, it, vi } from 'vitest';
import {
  bootstrapTenant,
  documentTitle,
  guessLanguage,
  isPublishedLegalDocument,
  legalPath,
  maintenanceNotice,
  type BootstrapDeps,
  type PublicTenant,
} from './bootstrap';

function tenant(overrides: Partial<PublicTenant> = {}): PublicTenant {
  return {
    name: 'Entity A',
    language: 'fr',
    availableLanguages: ['fr', 'en'],
    branding: {
      primaryColor: '#123456',
      accentColor: '#654321',
      hasLogo: false,
      hasBackground: false,
      backgroundUrl: '/api/v1/tenant/assets/background',
    },
    limits: { maxTransferBytes: 1024, expiryDays: [1, 7, 30] },
    maintenance: false,
    legalDocuments: ['legal-notice'],
    ...overrides,
  };
}

function deps(overrides: Partial<BootstrapDeps> = {}): BootstrapDeps & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetchTenant: vi.fn(async () => {
      calls.push('fetch');
      return tenant();
    }),
    setLocale: vi.fn(async (lang: string) => {
      calls.push(`locale:${lang}`);
      return lang;
    }),
    supported: ['fr', 'en'],
    fallback: 'en',
    browserLanguages: [],
    storage: undefined,
    ...overrides,
  };
}

describe('guessLanguage', () => {
  it('uses the browser language among the supported ones, else the fallback', async () => {
    expect(await guessLanguage(deps({ browserLanguages: ['de-DE', 'fr-CA'] }))).toBe('fr');
    expect(await guessLanguage(deps({ browserLanguages: ['de'] }))).toBe('en');
  });

  it('prefers the stored language', async () => {
    const storage = { getItem: () => 'fr', setItem: () => undefined };
    expect(await guessLanguage(deps({ storage, browserLanguages: ['en'] }))).toBe('fr');
  });
});

describe('bootstrapTenant', () => {
  it('fetches the tenant once when the guess matches the tenant choice', async () => {
    const d = deps({ browserLanguages: ['fr'] });
    const result = await bootstrapTenant(d);
    expect(result.name).toBe('Entity A');
    expect(d.calls).toEqual(['locale:fr', 'fetch', 'locale:fr']);
  });

  it('fetches the tenant again in the tenant language when the guess differs', async () => {
    // Browser in German: guess "en" (fallback), tenant default "fr".
    const d = deps({ browserLanguages: ['de'] });
    await bootstrapTenant(d);
    expect(d.calls).toEqual(['locale:en', 'fetch', 'locale:fr', 'fetch']);
  });

  it('only picks a language the tenant offers', async () => {
    const d = deps({
      browserLanguages: ['en'],
      fetchTenant: async () => tenant({ availableLanguages: ['fr'] }),
    });
    await bootstrapTenant(d);
    expect(d.setLocale).toHaveBeenLastCalledWith('fr');
  });

  it('rejects when the tenant cannot be fetched, with the guessed language active', async () => {
    const d = deps({
      fetchTenant: async () => {
        throw new Error('down');
      },
    });
    await expect(bootstrapTenant(d)).rejects.toThrow('down');
    expect(d.setLocale).toHaveBeenCalledWith('en');
  });
});

describe('helpers', () => {
  it('builds legal paths and checks published documents', () => {
    expect(legalPath('privacy-policy')).toBe('/legal/privacy-policy');
    const current = tenant();
    expect(isPublishedLegalDocument(current, 'legal-notice')).toBe(true);
    expect(isPublishedLegalDocument(current, 'privacy-policy')).toBe(false);
    expect(isPublishedLegalDocument(current, '../x')).toBe(false);
  });

  it('describes the maintenance notice', () => {
    expect(maintenanceNotice(tenant())).toBeUndefined();
    expect(maintenanceNotice(tenant({ maintenance: true }))).toEqual({
      message: undefined,
      language: undefined,
    });
    expect(
      maintenanceNotice(
        tenant({ maintenance: true, maintenanceMessage: '  ', maintenanceMessageLanguage: 'fr' }),
      ),
    ).toEqual({ message: undefined, language: undefined });
    expect(
      maintenanceNotice(
        tenant({ maintenance: true, maintenanceMessage: ' Back at 6 ', maintenanceMessageLanguage: 'en' }),
      ),
    ).toEqual({ message: 'Back at 6', language: 'en' });
  });

  it('builds document titles', () => {
    expect(documentTitle('Download', 'Entity A')).toBe('Download – Entity A');
    expect(documentTitle('Download', undefined)).toBe('Download');
    expect(documentTitle('Download', '')).toBe('Download');
    expect(documentTitle('Entity A', 'Entity A')).toBe('Entity A');
  });
});
