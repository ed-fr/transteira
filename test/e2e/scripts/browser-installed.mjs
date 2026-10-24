// Exits 0 when every download of `playwright install chromium` (Chromium, its headless shell and
// their helpers) is already in the browser cache, 1 otherwise. Used by `make e2e-browser`, so that
// the installer (and the network) is only used when something is missing.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'node_modules',
  'playwright',
  'cli.js',
);
const out = execFileSync(process.execPath, [cli, 'install', '--dry-run', 'chromium'], { encoding: 'utf8' });
const locations = [...out.matchAll(/Install location:\s+(.+)/g)].map((m) => m[1].trim());
const missing = locations.filter((dir) => !fs.existsSync(dir));
if (locations.length === 0 || missing.length > 0) {
  console.log(`missing: ${missing.join(', ') || 'no install location reported'}`);
  process.exit(1);
}
