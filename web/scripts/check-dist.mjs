// Checks that the web build (dist/) is compatible with the strict CSP served by
// internal/httpserver/webui.go (threat model T-91, T-95):
//
//   - both entry pages exist and every asset they reference (transitively) exists;
//   - no inline <script> (every <script> has a same-origin src), no <style> element, no inline
//     event handler attribute (onclick=...) in the HTML;
//   - no style= attribute anywhere, including in the HTML templates compiled into the JS
//     (Svelte builds the DOM from template strings, an inline style would be blocked);
//   - no absolute http(s):// URL except XML namespaces (w3.org) and the Svelte error
//     documentation links embedded in the runtime messages (never fetched);
//   - no data: URI in the files of the public application (img-src 'self'; the admin app may
//     display data: images received from the API, but never ships one);
//   - every file has an extension of the allowlist of webui.go (uiContentTypes, plus .html for
//     the entry pages): any other file would silently not be served (hidden files are skipped,
//     as by the server);
//   - no @import in a stylesheet, and every url(...) of a stylesheet targets /assets/ or a
//     relative same-origin path (no scheme, no protocol-relative or other absolute path).
//
// Exits 1 with the list of violations.
import { readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const TEXT = /\.(html|js|css|svg|txt|json)$/;
// Extensions served by internal/httpserver/webui.go (uiContentTypes) and the entry pages.
const SERVED = /\.(html|js|css|svg|png|ico|txt)$/;

const URL_ALLOW = [
  /^https?:\/\/www\.w3\.org\//, // XML namespaces (SVG, XLink, MathML)
  /^https:\/\/svelte\.dev\/e\//, // Svelte runtime error documentation links (text only)
];

const violations = [];
const report = (file, message) => violations.push(`${file}: ${message}`);

async function listFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.name.startsWith('.')) {
      // Hidden files (dist/.gitkeep) are never served.
      continue;
    }
    if (entry.isDirectory()) {
      out.push(...(await listFiles(full)));
    } else {
      out.push(relative(dist, full).split(sep).join('/'));
    }
  }
  return out;
}

let files;
try {
  files = await listFiles(dist);
} catch {
  console.error('check-dist: dist/ is missing, run `npm run build`');
  process.exit(1);
}
const contents = new Map();
for (const file of files) {
  if (!SERVED.test(file)) {
    report(file, 'extension not served by webui.go (uiContentTypes)');
  }
  if (TEXT.test(file)) {
    contents.set(file, await readFile(join(dist, file), 'utf8'));
  }
}

for (const entry of ['public/index.html', 'admin/index.html']) {
  if (!contents.has(entry)) {
    report(entry, 'missing entry page');
  }
}

// Files reachable from an entry page through /assets/ references.
function reachable(entry) {
  const seen = new Set();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    const text = contents.get(file);
    if (text === undefined) continue;
    for (const match of text.matchAll(/assets\/[A-Za-z0-9_.-]+\.[A-Za-z0-9]+/g)) {
      const ref = match[0];
      if (!files.includes(ref)) {
        report(file, `references missing asset ${ref}`);
      } else {
        queue.push(ref);
      }
    }
  }
  return seen;
}
const publicFiles = contents.has('public/index.html') ? reachable('public/index.html') : new Set();
if (contents.has('admin/index.html')) reachable('admin/index.html');

for (const [file, text] of contents) {
  if (file.endsWith('.html')) {
    for (const match of text.matchAll(/<script\b([^>]*)>/gi)) {
      const src = /\ssrc\s*=\s*"([^"]*)"/i.exec(match[1] ?? '');
      if (src === null) {
        report(file, 'inline <script> (no src)');
      } else if (!src[1].startsWith('/assets/')) {
        report(file, `<script> src outside /assets/: ${src[1]}`);
      }
    }
    if (/<style\b/i.test(text)) report(file, 'inline <style> element');
    if (/\son[a-z]+\s*=/i.test(text)) report(file, 'inline event handler attribute');
  }
  // style= attribute in HTML or in compiled templates (also escaped forms in JS strings).
  if (/[\s"'`]style\s*=\s*\\?["'`{]/.test(text)) report(file, 'inline style attribute (style=)');
  for (const match of text.matchAll(/https?:\/\/[^\s"'`)<>\\]+/g)) {
    if (!URL_ALLOW.some((re) => re.test(match[0]))) {
      report(file, `external URL ${match[0]}`);
    }
  }
  if (file.endsWith('.css')) {
    if (/@import\b/i.test(text)) report(file, '@import in a stylesheet');
    for (const match of text.matchAll(/url\(\s*(['"]?)([^'")]*)\1\s*\)/gi)) {
      const target = match[2].trim();
      const absolute = /^[a-z][a-z0-9+.-]*:/i.test(target) || /^[/\\]/.test(target);
      if (absolute && !target.startsWith('/assets/')) {
        report(file, `stylesheet url() outside /assets/: ${target}`);
      }
    }
  }
  if (publicFiles.has(file) && /\bdata:[a-z]+\/[a-z0-9.+-]+[;,]/i.test(text)) {
    report(file, 'data: URI in the public application');
  }
}

if (violations.length > 0) {
  console.error(`check-dist: ${violations.length} violation(s)`);
  for (const v of violations) console.error(`  ${v}`);
  process.exit(1);
}
console.log(`check-dist: ${files.length} files OK`);
