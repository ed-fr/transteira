// Generates the integrated help (CLAUDE.md section 4.2) from the user guides:
//
//   docs/user/<lang>/<guide>.md + docs/user/screenshots/manifest.json
//     -> src/help/generated/<lang>-<app>.ts (git-ignored)
//
// One module per language and application (public: depositor and recipient guides; admin:
// delegated-admin and super-admin guides), loaded on demand by the help screen. The parsing and
// the checks live in src/help/build.ts (run here through Node's type stripping, tested by
// Vitest); this script only reads and writes files. Any error (Markdown outside the accepted
// subset, missing screenshot, duplicate topic, broken link, topics differing between languages)
// is printed as file:line and fails with exit code 1.
//
// Run by `npm run help:gen`, and before dev, check, test and build. Files are only rewritten when
// their content changes (no needless reload of the dev server).
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  GUIDE_IDS,
  HELP_LANGUAGES,
  buildHelp,
  formatError,
  generateModule,
  moduleFileName,
  parseManifest,
  pngSize,
} from '../src/help/build.ts';

const web = fileURLToPath(new URL('..', import.meta.url));
const repo = join(web, '..');
const docs = join(repo, 'docs', 'user');
const screenshots = join(docs, 'screenshots');
const outDir = join(web, 'src', 'help', 'generated');
const posix = (path) => path.split(sep).join('/');

function fail(problems) {
  console.error(`help:gen: ${problems.length} error(s) in docs/user`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}

const manifestPath = join(screenshots, 'manifest.json');
const manifestFile = posix(relative(repo, manifestPath));
if (!existsSync(manifestPath)) {
  fail([`${manifestFile}:1: missing screenshots manifest (run make screenshots)`]);
}
const manifest = parseManifest(readFileSync(manifestPath, 'utf8'), manifestFile);
if (manifest.errors.length > 0) {
  fail(manifest.errors.map(formatError));
}

// A missing guide is not read here: buildHelp reports it (once) with the other errors.
const sources = [];
for (const lang of HELP_LANGUAGES) {
  for (const id of GUIDE_IDS) {
    const path = join(docs, lang, `${id}.md`);
    if (existsSync(path)) {
      sources.push({ lang, id, file: posix(relative(repo, path)), source: readFileSync(path, 'utf8') });
    }
  }
}

const imagePath = (lang, name) => join(screenshots, lang, `${name}.png`);
const { sets, errors } = buildHelp(sources, {
  manifest: manifest.names,
  imageExists: (lang, name) => existsSync(imagePath(lang, name)),
  imageSize: (lang, name) => pngSize(readFileSync(imagePath(lang, name))),
});
const problems = errors.map(formatError);
if (problems.length > 0) {
  fail(problems);
}

mkdirSync(outDir, { recursive: true });
const importBase = posix(relative(outDir, screenshots));
const expected = new Set();
let written = 0;
for (const set of sets) {
  const name = moduleFileName(set);
  expected.add(name);
  const path = join(outDir, name);
  const content = generateModule(set, importBase);
  if (!existsSync(path) || readFileSync(path, 'utf8') !== content) {
    writeFileSync(path, content);
    written++;
  }
}
for (const name of readdirSync(outDir)) {
  if (!expected.has(name)) rmSync(join(outDir, name), { recursive: true, force: true });
}
console.log(`help:gen: ${sets.length} modules (${written} updated) from ${sources.length} guides`);
