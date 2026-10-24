// Pure helpers of the i18n module: locale bundle loading, key lookup, interpolation and
// Intl formatting. No reactive state here (see i18n.svelte.ts).

/** A nested message tree, as stored in the locale JSON files. */
export interface Messages {
  [key: string]: string | Messages;
}

/** Interpolation parameters of a message. Numbers are formatted for the active language. */
export type TranslateParams = Record<string, string | number>;

/** Translation function (the t of the i18n module), passed to the pure logic modules. */
export type Translate = (key: string, params?: TranslateParams) => string;

/** Lazy loader of one locale module ({ default: Messages }), as returned by import.meta.glob. */
export type LocaleLoader = () => Promise<unknown>;

const LOCALE_PATH = /\/([a-z]{2,3}(?:-[A-Za-z0-9]+)?)\/([a-zA-Z0-9_-]+)\.json$/;
const PLURAL_CATEGORIES: ReadonlySet<string> = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);
const PLACEHOLDER = /\{([a-zA-Z0-9_]+)\}/g;
const BYTE_UNITS = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte', 'petabyte'] as const;

/** Groups locale loaders by language: language → area → loader. */
export function groupLoaders(loaders: Record<string, LocaleLoader>): Map<string, Map<string, LocaleLoader>> {
  const out = new Map<string, Map<string, LocaleLoader>>();
  for (const [path, loader] of Object.entries(loaders)) {
    const match = LOCALE_PATH.exec(path);
    if (match === null) {
      continue;
    }
    const [, lang, area] = match as unknown as [string, string, string];
    let areas = out.get(lang);
    if (areas === undefined) {
      areas = new Map();
      out.set(lang, areas);
    }
    areas.set(area, loader);
  }
  return out;
}

function isMessages(value: unknown): value is Messages {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Loads and merges every area of one language: { <area>: <content of area.json> }. */
export async function loadBundle(areas: Map<string, LocaleLoader> | undefined): Promise<Messages> {
  const entries = await Promise.all(
    [...(areas ?? [])].map(async ([area, loader]): Promise<[string, Messages]> => {
      const mod = await loader();
      const content = isMessages(mod) ? mod['default'] : undefined;
      return [area, isMessages(content) ? content : {}];
    }),
  );
  return Object.fromEntries(entries);
}

/** Resolves a dotted key in a message tree. */
export function lookup(messages: Messages, key: string): string | Messages | undefined {
  let node: string | Messages | undefined = messages;
  for (const part of key.split('.')) {
    if (!isMessages(node) || !Object.hasOwn(node, part)) {
      return undefined;
    }
    node = node[part];
  }
  return node;
}

/** Reports whether a node is a plural group (categories only, "other" included). */
export function isPluralGroup(node: Messages): boolean {
  const keys = Object.keys(node);
  return keys.includes('other') && keys.every((k) => PLURAL_CATEGORIES.has(k));
}

/** Replaces {name} placeholders; unknown placeholders are left as they are. */
export function interpolate(
  message: string,
  params: TranslateParams | undefined,
  numberFormat: Intl.NumberFormat,
): string {
  if (params === undefined) {
    return message;
  }
  return message.replace(PLACEHOLDER, (whole, name: string) => {
    if (!Object.hasOwn(params, name)) {
      return whole;
    }
    const value = params[name];
    return typeof value === 'number' ? numberFormat.format(value) : String(value);
  });
}

/** Formats a byte count with binary multiples (20 << 30 → "20 GB" in English, "20 Go" in French). */
export function formatBytesIn(locale: string, n: number): string {
  let value = Math.max(0, n);
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  return new Intl.NumberFormat(locale, {
    style: 'unit',
    unit: BYTE_UNITS[unit],
    unitDisplay: 'short',
    maximumFractionDigits: unit === 0 || value >= 100 ? 0 : 1,
  }).format(value);
}

/** Formats a date (Date, ISO string or epoch milliseconds); an invalid date gives "". */
export function formatDateIn(
  locale: string,
  d: Date | string | number,
  options: Intl.DateTimeFormatOptions = { dateStyle: 'long', timeStyle: 'short' },
): string {
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  return new Intl.DateTimeFormat(locale, options).format(date);
}
