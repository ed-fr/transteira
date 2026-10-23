/// <reference types="vite/client" />
// Translations of the web interface (CLAUDE.md section 14).
//
// Bundles live in src/locales/<lang>/<area>.json. Each area file is a nested JSON object and is
// mounted under its area name: the key "title" of upload.json is translated as "upload.title".
// Only the bundle of the active language is loaded (dynamic import through import.meta.glob),
// all its areas merged. Pure helpers live in messages.ts.
//
// Messages use {name} placeholders. Plurals: a key whose value is an object with plural
// categories ("one", "other", and optionally "zero", "two", "few", "many") is resolved with
// Intl.PluralRules on the numeric parameter `count`; "other" is the fallback category.
// A missing key renders as the key itself (visible but harmless) and is reported to onMissing.
import { languageValues } from '../api/schema';
import {
  formatBytesIn,
  formatDateIn,
  groupLoaders,
  interpolate,
  isPluralGroup,
  loadBundle,
  lookup,
  type LocaleLoader,
  type Messages,
  type TranslateParams,
} from './messages';

export {
  formatBytesIn,
  formatDateIn,
  groupLoaders,
  interpolate,
  isPluralGroup,
  loadBundle,
  lookup,
  type LocaleLoader,
  type Messages,
  type TranslateParams,
};

/** Languages the interface ships translations for (the API Language enum). */
export const supportedLanguages: readonly string[] = languageValues;

/** Language used when the requested one has no bundle. */
export const FALLBACK_LANGUAGE = 'en';

/** Options of an i18n instance. */
export interface I18nOptions {
  /** Locale modules keyed by path ".../<lang>/<area>.json" (import.meta.glob shape). */
  loaders: Record<string, LocaleLoader>;
  /** Language used for an unknown language (default "en"). */
  fallbackLanguage?: string;
  /** Element receiving the lang attribute (document.documentElement in the browser). */
  root?: { lang: string } | undefined;
  /** Called for each lookup of a missing key. */
  onMissing?: (key: string, language: string) => void;
}

/** An i18n instance. Reading `locale.current` or calling t() inside a component is reactive. */
export interface I18n {
  /** Reactive current language (empty until the first setLocale resolves). */
  readonly locale: { readonly current: string };
  /** Languages with a bundle. */
  readonly languages: readonly string[];
  /** Translates key with params. */
  t(key: string, params?: TranslateParams): string;
  /** Reports whether key resolves to a message (or a plural group) in the active bundle. */
  has(key: string): boolean;
  /** Loads the bundle of lang (or the fallback language) and makes it active. */
  setLocale(lang: string): Promise<string>;
  /** Formats a byte count with binary multiples (20 << 30 → "20 GB" / "20 Go"). */
  formatBytes(n: number): string;
  /** Formats a date (Date, ISO string or epoch milliseconds) for the active language. */
  formatDate(d: Date | string | number, options?: Intl.DateTimeFormatOptions): string;
  /** Formats a number for the active language. */
  formatNumber(n: number, options?: Intl.NumberFormatOptions): string;
}

/** Creates an i18n instance (the application uses the shared instance below). */
export function createI18n(options: I18nOptions): I18n {
  const grouped = groupLoaders(options.loaders);
  const fallback = options.fallbackLanguage ?? FALLBACK_LANGUAGE;
  const cache: Record<string, Messages> = {};
  const state = $state<{ locale: string; messages: Messages }>({ locale: '', messages: {} });
  let requested = 0;

  const tag = (): string => state.locale || fallback;

  function resolve(key: string, params: TranslateParams | undefined): string | undefined {
    const node = lookup(state.messages, key);
    if (typeof node === 'string') {
      return node;
    }
    if (node !== undefined && isPluralGroup(node)) {
      const count = params?.['count'];
      const category = typeof count === 'number' ? new Intl.PluralRules(tag()).select(count) : 'other';
      const chosen = node[category] ?? node['other'];
      return typeof chosen === 'string' ? chosen : undefined;
    }
    return undefined;
  }

  return {
    locale: {
      get current(): string {
        return state.locale;
      },
    },
    languages: [...grouped.keys()],
    t(key, params) {
      const message = resolve(key, params);
      if (message === undefined) {
        options.onMissing?.(key, state.locale);
        return key;
      }
      return interpolate(message, params, new Intl.NumberFormat(tag()));
    },
    has(key) {
      const node = lookup(state.messages, key);
      return typeof node === 'string' || (node !== undefined && isPluralGroup(node));
    },
    async setLocale(lang) {
      const target = grouped.has(lang) ? lang : fallback;
      const ticket = ++requested;
      let messages = Object.hasOwn(cache, target) ? cache[target] : undefined;
      if (messages === undefined) {
        messages = await loadBundle(grouped.get(target));
        cache[target] = messages;
      }
      // A later call wins when two loads overlap.
      if (ticket === requested) {
        state.messages = messages;
        state.locale = target;
        if (options.root !== undefined) {
          options.root.lang = target;
        }
      }
      return target;
    },
    formatBytes(n) {
      return formatBytesIn(tag(), n);
    },
    formatDate(d, opts) {
      return formatDateIn(tag(), d, opts);
    },
    formatNumber(n, opts) {
      return new Intl.NumberFormat(tag(), opts).format(n);
    },
  };
}

/** Every locale module of the application, loaded lazily per language. */
export const localeLoaders: Record<string, LocaleLoader> = import.meta.glob('../../locales/*/*.json');

/** The shared i18n instance of the application. */
export const i18n: I18n = createI18n({
  loaders: localeLoaders,
  root: typeof document === 'undefined' ? undefined : document.documentElement,
});

/** Translates key with params (shared instance). Reactive in components. */
export function t(key: string, params?: TranslateParams): string {
  return i18n.t(key, params);
}

/** Reactive current language of the shared instance: read `locale.current`. */
export const locale: { readonly current: string } = i18n.locale;

/** Loads and activates a language on the shared instance; resolves to the language applied. */
export function setLocale(lang: string): Promise<string> {
  return i18n.setLocale(lang);
}

/** Formats a byte count for the current language (binary multiples). */
export function formatBytes(n: number): string {
  return i18n.formatBytes(n);
}

/** Formats a date for the current language. */
export function formatDate(d: Date | string | number, options?: Intl.DateTimeFormatOptions): string {
  return i18n.formatDate(d, options);
}

/** Formats a number for the current language. */
export function formatNumber(n: number, options?: Intl.NumberFormatOptions): string {
  return i18n.formatNumber(n, options);
}
