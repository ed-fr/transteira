// Choice of the initial interface language (CLAUDE.md section 14):
//   1. the language the user picked earlier on this browser (localStorage "tt.lang"), if the
//      tenant offers it;
//   2. else the first browser language (navigator.languages) the tenant offers;
//   3. else the tenant default language.
// localStorage holds the language only (threat model T-160). Every access is wrapped in
// try/catch: storage may be disabled, full or throw in private windows.
import type { I18n } from './i18n.svelte';

/** localStorage key of the language picked by the user. */
export const LANGUAGE_STORAGE_KEY = 'tt.lang';

/** Minimal storage interface (window.localStorage in the browser). */
export type LanguageStorage = Pick<Storage, 'getItem' | 'setItem'>;

/** Inputs of the initial language choice. */
export interface LanguageContext {
  /** Languages offered by the tenant (PublicTenant.availableLanguages). */
  available: readonly string[];
  /** Tenant default language (PublicTenant.language). */
  tenantLanguage: string;
  /** Browser preferred languages (navigator.languages), most preferred first. */
  browserLanguages?: readonly string[];
  /** Storage holding the picked language (window.localStorage); undefined when unavailable. */
  storage?: LanguageStorage | undefined;
}

/** Reads the stored language; undefined when absent or when storage throws. */
export function readStoredLanguage(storage: LanguageStorage | undefined): string | undefined {
  try {
    return storage?.getItem(LANGUAGE_STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

/** Stores the picked language; storage failures are ignored. */
export function storeLanguage(storage: LanguageStorage | undefined, lang: string): void {
  try {
    storage?.setItem(LANGUAGE_STORAGE_KEY, lang);
  } catch {
    // Storage disabled or full: the choice only lasts for this page.
  }
}

/** Picks the initial language from the context (pure). */
export function pickInitialLanguage(ctx: LanguageContext): string {
  const stored = readStoredLanguage(ctx.storage);
  if (stored !== undefined && ctx.available.includes(stored)) {
    return stored;
  }
  for (const tag of ctx.browserLanguages ?? []) {
    const primary = tag.toLowerCase().split('-')[0] ?? '';
    if (ctx.available.includes(primary)) {
      return primary;
    }
  }
  return ctx.tenantLanguage;
}

/** Picks the initial language, loads it and sets <html lang>; resolves to the language applied. */
export function initLanguage(i18n: Pick<I18n, 'setLocale'>, ctx: LanguageContext): Promise<string> {
  return i18n.setLocale(pickInitialLanguage(ctx));
}

/** Switches language on user request and remembers the choice. */
export async function changeLanguage(
  i18n: Pick<I18n, 'setLocale'>,
  lang: string,
  storage: LanguageStorage | undefined,
): Promise<string> {
  const applied = await i18n.setLocale(lang);
  storeLanguage(storage, applied);
  return applied;
}

/** Returns window.localStorage, or undefined when it is missing or access throws. */
export function browserStorage(): LanguageStorage | undefined {
  try {
    return typeof localStorage === 'undefined' ? undefined : localStorage;
  } catch {
    return undefined;
  }
}
