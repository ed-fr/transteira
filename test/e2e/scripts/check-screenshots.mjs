// Consistency of the documentation screenshots (make screenshots-check, part of make check):
//   - docs/user/screenshots/manifest.json lists { name, screen, profile, path } entries, sorted
//     by name without duplicates, with kebab-case names, a known profile and
//     path = "{lang}/<name>.png";
//   - every entry has its image in fr/ and en/: a 1280x800 PNG of reasonable size;
//   - no image (or other file) in fr/ or en/ is outside the manifest;
//   - the manifest matches SCREENSHOT_CATALOG of support/screenshots.ts (same names, screens and
//     profiles): a catalog edited without `make screenshots` fails.
// Runs with node:test (`node --test scripts/check-screenshots.mjs`), in well under a second.
// SCREENSHOTS_DIR overrides the directory and SCREENSHOTS_CATALOG the catalog file (tests of
// this script).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const DIR =
  process.env.SCREENSHOTS_DIR ??
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'docs', 'user', 'screenshots');
const CATALOG =
  process.env.SCREENSHOTS_CATALOG ??
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'support', 'screenshots.ts');
const LANGS = ['en', 'fr'];
const PROFILES = new Set(['depositor', 'recipient', 'delegated-admin', 'super-admin']);
const KEBAB = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const WIDTH = 1280;
const HEIGHT = 800;
/** Upper bound of one image: keeps the repository light. */
const MAX_BYTES = 600 * 1024;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function readManifest() {
  return JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
}

test('manifest entries are well formed and sorted by name', () => {
  const manifest = readManifest();
  assert.ok(Array.isArray(manifest) && manifest.length > 0, 'manifest.json must be a non-empty array');
  const problems = [];
  manifest.forEach((e, i) => {
    const keys = Object.keys(e).sort().join(',');
    if (keys !== 'name,path,profile,screen') problems.push(`entry ${i}: fields ${keys}`);
    if (typeof e.name !== 'string' || !KEBAB.test(e.name))
      problems.push(`entry ${i}: name "${e.name}" is not kebab-case`);
    if (typeof e.screen !== 'string' || e.screen.trim() === '') problems.push(`${e.name}: empty screen`);
    if (!PROFILES.has(e.profile)) problems.push(`${e.name}: unknown profile "${e.profile}"`);
    if (e.path !== `{lang}/${e.name}.png`)
      problems.push(`${e.name}: path "${e.path}" is not "{lang}/${e.name}.png"`);
    const prev = manifest[i - 1];
    if (prev && !(prev.name < e.name))
      problems.push(`${e.name}: not sorted after "${prev.name}" (or duplicate)`);
  });
  assert.deepEqual(problems, []);
});

for (const lang of LANGS) {
  test(`every manifest entry has its ${lang} image (1280x800 PNG)`, () => {
    const problems = [];
    for (const { name } of readManifest()) {
      const file = path.join(DIR, lang, `${name}.png`);
      if (!fs.existsSync(file)) {
        problems.push(`${lang}/${name}.png is missing (run make screenshots)`);
        continue;
      }
      const data = fs.readFileSync(file);
      if (data.length < 33 || !data.subarray(0, 8).equals(PNG_SIGNATURE)) {
        problems.push(`${lang}/${name}.png is not a PNG`);
        continue;
      }
      // IHDR is the first chunk: width and height are big-endian at offsets 16 and 20.
      const width = data.readUInt32BE(16);
      const height = data.readUInt32BE(20);
      if (width !== WIDTH || height !== HEIGHT) problems.push(`${lang}/${name}.png is ${width}x${height}`);
      if (data.length > MAX_BYTES) problems.push(`${lang}/${name}.png weighs ${data.length} bytes`);
    }
    assert.deepEqual(problems, []);
  });

  test(`no ${lang} file outside the manifest`, () => {
    const names = new Set(readManifest().map((e) => `${e.name}.png`));
    const orphans = fs.readdirSync(path.join(DIR, lang)).filter((f) => !names.has(f));
    assert.deepEqual(orphans, [], `orphan files in ${lang}/: remove them or add them to the catalog`);
  });
}

/**
 * Entries of SCREENSHOT_CATALOG, read from the TypeScript source (no TypeScript toolchain here):
 * every object literal of the array, with single-quoted name, screen and profile in this order.
 */
function readCatalog() {
  const source = fs.readFileSync(CATALOG, 'utf8');
  const start = source.indexOf('SCREENSHOT_CATALOG');
  const end = source.indexOf('\n];', start);
  assert.ok(start >= 0 && end > start, `SCREENSHOT_CATALOG array not found in ${CATALOG}`);
  const block = source.slice(start, end);
  const entry = /\{\s*name:\s*'([^']*)',\s*screen:\s*'([^']*)',\s*profile:\s*'([^']*)',?\s*\}/g;
  const entries = [...block.matchAll(entry)].map(([, name, screen, profile]) => ({ name, screen, profile }));
  // Every object of the block must have been understood: count the "name:" keys.
  const declared = (block.match(/\bname:/g) ?? []).length;
  assert.equal(entries.length, declared, `${declared - entries.length} catalog entries could not be parsed`);
  return entries;
}

test('the manifest matches the catalog of support/screenshots.ts', () => {
  const catalog = readCatalog()
    .sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0))
    .map((e) => ({ ...e, path: `{lang}/${e.name}.png` }));
  assert.deepEqual(readManifest(), catalog, 'manifest.json is out of date: run make screenshots');
});

test('the screenshots directory only holds the manifest and the language folders', () => {
  const extra = fs.readdirSync(DIR).filter((f) => f !== 'manifest.json' && !LANGS.includes(f));
  assert.deepEqual(extra, []);
});
