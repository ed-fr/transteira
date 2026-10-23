// Consistency of the translation bundles (src/locales/<lang>/<area>.json):
// - every language has the same areas and the same keys, no empty message, the same
//   placeholders in each message;
// - every API ProblemCode has errors.<code> in every language;
// - every literal key used in the sources (t('…'), titleKey: '…') exists in every language.
//   Keys built at runtime (t(`errors.${code}`)) are not scanned: cover them with explicit tests.
import { describe, expect, it } from 'vitest';
import { languageValues, problemCodeValues } from '../api/schema';
import type { Messages } from './i18n.svelte';

const bundles = import.meta.glob<Messages>('../../locales/*/*.json', { eager: true, import: 'default' });
const sources = import.meta.glob<string>(
  ['../../**/*.ts', '../../**/*.svelte', '!../../**/*.test.ts', '!../../shared/api/schema.ts'],
  {
    eager: true,
    query: '?raw',
    import: 'default',
  },
);

type Flat = Map<string, string>;

function byLanguage(): Map<string, Map<string, Messages>> {
  const out = new Map<string, Map<string, Messages>>();
  for (const [path, content] of Object.entries(bundles)) {
    const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
    if (match === null) {
      continue;
    }
    const [, lang, area] = match as unknown as [string, string, string];
    if (!out.has(lang)) {
      out.set(lang, new Map());
    }
    out.get(lang)?.set(area, content);
  }
  return out;
}

function flatten(node: unknown, prefix: string, out: Flat, problems: string[]): Flat {
  if (typeof node === 'string') {
    out.set(prefix, node);
  } else if (typeof node === 'object' && node !== null && !Array.isArray(node)) {
    for (const [key, value] of Object.entries(node)) {
      if (key === '' || key.includes('.')) {
        problems.push(`${prefix}: invalid key "${key}"`);
      }
      flatten(value, `${prefix}.${key}`, out, problems);
    }
  } else {
    problems.push(`${prefix}: not a string or an object`);
  }
  return out;
}

function flatLanguage(areas: Map<string, Messages>, problems: string[]): Flat {
  const out: Flat = new Map();
  for (const [area, content] of areas) {
    flatten(content, area, out, problems);
  }
  return out;
}

function placeholders(message: string): string[] {
  return [...message.matchAll(/\{([a-zA-Z0-9_]+)\}/g)].map((m) => m[1] as string).sort();
}

/** Resolves a key like the i18n module: a message, or a plural group (with "other"). */
function resolves(flat: Flat, key: string): boolean {
  return flat.has(key) || flat.has(`${key}.other`);
}

const languages = byLanguage();
const reference = languageValues[0] as string;

describe('locale bundles', () => {
  it('exist for every API language', () => {
    expect([...languages.keys()].sort()).toEqual([...languageValues].sort());
  });

  it('have the same areas in every language', () => {
    const areas = [...(languages.get(reference)?.keys() ?? [])].sort();
    expect(areas).toEqual(expect.arrayContaining(['common', 'errors', 'fieldErrors']));
    for (const [lang, bundle] of languages) {
      expect([...bundle.keys()].sort(), lang).toEqual(areas);
    }
  });

  it('have well-formed trees, the same keys, no empty message and the same placeholders', () => {
    const problems: string[] = [];
    const flats = new Map([...languages].map(([lang, areas]) => [lang, flatLanguage(areas, problems)]));
    const ref = flats.get(reference) as Flat;
    for (const [lang, flat] of flats) {
      for (const key of ref.keys()) {
        if (!flat.has(key)) {
          problems.push(`${lang}: missing ${key}`);
        }
      }
      for (const [key, message] of flat) {
        if (!ref.has(key)) {
          problems.push(`${lang}: extra ${key}`);
        }
        if (message.trim() === '') {
          problems.push(`${lang}: empty ${key}`);
        }
        const expected = ref.get(key);
        if (expected !== undefined && placeholders(expected).join() !== placeholders(message).join()) {
          problems.push(`${lang}: placeholders of ${key} differ from ${reference}`);
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it('translate every ProblemCode and the client-side errors', () => {
    const missing: string[] = [];
    for (const [lang, areas] of languages) {
      const flat = flatLanguage(areas, []);
      for (const code of [...problemCodeValues, 'network', 'unknown']) {
        if (!flat.has(`errors.${code}`)) {
          missing.push(`${lang}: errors.${code}`);
        }
      }
      if (!flat.has('fieldErrors.invalid')) {
        missing.push(`${lang}: fieldErrors.invalid`);
      }
    }
    expect(missing).toEqual([]);
  });
});

describe('translation keys used in the sources', () => {
  const keyPatterns = [/\bt\(\s*(['"`])([A-Za-z0-9_.-]+)\1/g, /\btitleKey:\s*(['"`])([A-Za-z0-9_.-]+)\1/g];

  function usedKeys(): Map<string, string> {
    const used = new Map<string, string>();
    for (const [path, source] of Object.entries(sources)) {
      for (const pattern of keyPatterns) {
        for (const match of source.matchAll(pattern)) {
          used.set(match[2] as string, path);
        }
      }
    }
    return used;
  }

  it('finds the keys of the shared core', () => {
    expect(usedKeys().has('common.navigation.pageLoaded')).toBe(true);
  });

  it('exist in every language', () => {
    const missing: string[] = [];
    for (const [lang, areas] of languages) {
      const flat = flatLanguage(areas, []);
      for (const [key, path] of usedKeys()) {
        if (!resolves(flat, key)) {
          missing.push(`${lang}: ${key} (${path})`);
        }
      }
    }
    expect(missing).toEqual([]);
  });
});
