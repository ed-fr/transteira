// Messages of the web interface (web/src/locales/<lang>/<namespace>.json), so that a scenario
// can find the same elements in French and in English (screenshots, language passes).
import fs from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from './env';

/** Languages of the interface. */
export type Lang = 'en' | 'fr';
export const LANGS: readonly Lang[] = ['en', 'fr'];
/** Browser locale used for each language (Accept-Language and navigator.languages). */
export const BROWSER_LOCALE: Record<Lang, string> = { en: 'en-US', fr: 'fr-FR' };

const LOCALES_DIR = path.join(REPO_ROOT, 'web', 'src', 'locales');
const bundles = new Map<string, unknown>();

/**
 * Message `namespace.path.to.key` in lang, with {placeholders} replaced by vars. Fails when the
 * key is missing, so that a renamed key breaks the scenario instead of matching nothing.
 */
export function msg(lang: Lang, key: string, vars: Record<string, string | number> = {}): string {
  const [ns, ...rest] = key.split('.');
  const id = `${lang}/${ns}`;
  if (!bundles.has(id)) {
    bundles.set(id, JSON.parse(fs.readFileSync(path.join(LOCALES_DIR, lang, `${ns}.json`), 'utf8')));
  }
  let node: unknown = bundles.get(id);
  for (const part of rest) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== 'string') throw new Error(`no ${lang} message for ${key}`);
  return node.replace(/\{(\w+)\}/g, (m, name: string) => (name in vars ? String(vars[name]) : m));
}
