// On-demand loading of the generated guides (src/help/generated/<lang>-<app>.ts): one dynamic
// import per language and application, so that neither the guides nor their screenshots are
// downloaded before the help is opened, and the public application never loads the admin guides.
import type { HelpApp, HelpGuideSet } from './types';

/** Lazy loader of one generated module (import.meta.glob shape). */
export type HelpModuleLoader = () => Promise<{ default: HelpGuideSet }>;

/** Loads the guide set of an application in a language. */
export type HelpLoader = (app: HelpApp, lang: string) => Promise<HelpGuideSet>;

/** Language of the guides used when a language has none. */
export const HELP_FALLBACK_LANGUAGE = 'en';

/**
 * Creates a loader over generated modules keyed by path ("./generated/fr-public.ts"). A language
 * without guides falls back to English (the set returned tells its language); results are cached,
 * a failed load is retried on the next call.
 */
export function createHelpLoader(modules: Record<string, HelpModuleLoader>): HelpLoader {
  const cache = new Map<string, Promise<HelpGuideSet>>();
  const path = (app: HelpApp, lang: string): string => `./generated/${lang}-${app}.ts`;
  return (app, lang) => {
    const key = modules[path(app, lang)] !== undefined ? path(app, lang) : path(app, HELP_FALLBACK_LANGUAGE);
    const cached = cache.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const loader = modules[key];
    if (loader === undefined) {
      return Promise.reject(new Error(`integrated help: no guides for ${app} (${key})`));
    }
    const pending = loader().then((module) => module.default);
    cache.set(key, pending);
    pending.catch(() => cache.delete(key));
    return pending;
  };
}
