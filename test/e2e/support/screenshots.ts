// Catalog of the documentation screenshots (CLAUDE.md section 4.2), captured by
// specs/screenshots.spec.ts with `make screenshots` in French and in English:
//   docs/user/screenshots/<lang>/<name>.png
//   docs/user/screenshots/manifest.json  [{ name, screen, profile, path }], sorted by name,
// where path is relative to the manifest with "{lang}" standing for fr or en. The user guides
// (docs/user/) cite the images by name; scripts/check-screenshots.mjs (make check) verifies that
// every entry has both images and that no image is left outside the manifest.
import fs from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from './env';
import type { Lang } from './i18n';

/** Profile of the user guide a screenshot belongs to. */
export type Profile = 'depositor' | 'recipient' | 'delegated-admin' | 'super-admin';

/** One screenshot of the catalog. */
export interface ScreenshotEntry {
  /** Kebab-case name, also the file name (without .png). */
  name: string;
  /** Screen shown: host ("public" tenant host or "admin" host), route and state. */
  screen: string;
  profile: Profile;
}

/** Every screenshot, in capture order of specs/screenshots.spec.ts. */
export const SCREENSHOT_CATALOG: readonly ScreenshotEntry[] = [
  // Depositor (public tenant host).
  { name: 'deposit-email', screen: 'public / (email step)', profile: 'depositor' },
  { name: 'deposit-code', screen: 'public / (verification code step)', profile: 'depositor' },
  { name: 'deposit-form', screen: 'public / (transfer form, files selected)', profile: 'depositor' },
  { name: 'deposit-sent', screen: 'public / (recap: transfer sent)', profile: 'depositor' },
  { name: 'invite', screen: 'public /invite', profile: 'depositor' },
  { name: 'invitation-landing', screen: 'public /i/:token', profile: 'depositor' },
  { name: 'legal-notice', screen: 'public /legal/legal-notice', profile: 'depositor' },
  // Recipient.
  { name: 'download', screen: 'public /d/:token', profile: 'recipient' },
  { name: 'download-password', screen: 'public /d/:token (password required)', profile: 'recipient' },
  // Delegated admin (admin host, entity A).
  { name: 'admin-login', screen: 'admin /admin/login', profile: 'delegated-admin' },
  { name: 'admin-activation', screen: 'admin /admin/activate', profile: 'delegated-admin' },
  { name: 'admin-home-delegate', screen: 'admin /admin/', profile: 'delegated-admin' },
  { name: 'admin-tenant-general', screen: 'admin /admin/tenants/:id/general', profile: 'delegated-admin' },
  { name: 'admin-tenant-branding', screen: 'admin /admin/tenants/:id/branding', profile: 'delegated-admin' },
  { name: 'admin-tenant-network', screen: 'admin /admin/tenants/:id/network', profile: 'delegated-admin' },
  { name: 'admin-tenant-smtp', screen: 'admin /admin/tenants/:id/smtp', profile: 'delegated-admin' },
  {
    name: 'admin-tenant-templates',
    screen: 'admin /admin/tenants/:id/templates',
    profile: 'delegated-admin',
  },
  {
    name: 'admin-tenant-template-editor',
    screen: 'admin /admin/tenants/:id/templates/:key/:lang',
    profile: 'delegated-admin',
  },
  { name: 'admin-tenant-legal', screen: 'admin /admin/tenants/:id/legal', profile: 'delegated-admin' },
  {
    name: 'admin-tenant-legal-editor',
    screen: 'admin /admin/tenants/:id/legal/:document/:lang',
    profile: 'delegated-admin',
  },
  { name: 'admin-transfers', screen: 'admin /admin/tenants/:id/transfers', profile: 'delegated-admin' },
  {
    name: 'admin-transfer-detail',
    screen: 'admin /admin/tenants/:id/transfers/:transferId',
    profile: 'delegated-admin',
  },
  { name: 'admin-invitations', screen: 'admin /admin/tenants/:id/invitations', profile: 'delegated-admin' },
  { name: 'admin-blocklist', screen: 'admin /admin/tenants/:id/blocklist', profile: 'delegated-admin' },
  { name: 'admin-tokens', screen: 'admin /admin/tenants/:id/tokens', profile: 'delegated-admin' },
  {
    name: 'admin-token-secret',
    screen: 'admin /admin/tenants/:id/tokens/new (secret shown once)',
    profile: 'delegated-admin',
  },
  {
    name: 'admin-webhooks',
    screen: 'admin /admin/tenants/:id/webhooks',
    profile: 'delegated-admin',
  },
  { name: 'admin-audit', screen: 'admin /admin/tenants/:id/audit', profile: 'delegated-admin' },
  { name: 'admin-stats', screen: 'admin /admin/tenants/:id/stats', profile: 'delegated-admin' },
  {
    name: 'admin-privacy',
    screen: 'admin /admin/tenants/:id/privacy (search result)',
    profile: 'delegated-admin',
  },
  { name: 'admin-account', screen: 'admin /admin/account', profile: 'delegated-admin' },
  {
    name: 'admin-account-totp',
    screen: 'admin /admin/account (two-factor enrollment)',
    profile: 'delegated-admin',
  },
  {
    name: 'admin-tenants',
    screen: 'admin /admin/tenants (delegated admin of two entities)',
    profile: 'delegated-admin',
  },
  // Super admin.
  { name: 'admin-home-super', screen: 'admin /admin/', profile: 'super-admin' },
  { name: 'admin-tenant-create', screen: 'admin /admin/tenants/new', profile: 'super-admin' },
  { name: 'admin-admins', screen: 'admin /admin/admins', profile: 'super-admin' },
  { name: 'admin-admin-create', screen: 'admin /admin/admins/new', profile: 'super-admin' },
  { name: 'admin-system', screen: 'admin /admin/system', profile: 'super-admin' },
  { name: 'admin-system-settings', screen: 'admin /admin/system/settings', profile: 'super-admin' },
  { name: 'admin-system-audit', screen: 'admin /admin/system/audit', profile: 'super-admin' },
  { name: 'admin-system-master-key', screen: 'admin /admin/system/master-key', profile: 'super-admin' },
  {
    name: 'admin-system-webhooks',
    screen: 'admin /admin/system/webhooks',
    profile: 'super-admin',
  },
  {
    name: 'admin-system-maintenance',
    screen: 'admin /admin/system/maintenance (mode on)',
    profile: 'super-admin',
  },
  { name: 'maintenance', screen: 'public / (maintenance page)', profile: 'depositor' },
];

/** Directory of the screenshots (versioned). */
export const SCREENSHOT_DIR = path.join(REPO_ROOT, 'docs', 'user', 'screenshots');
export const MANIFEST_FILE = path.join(SCREENSHOT_DIR, 'manifest.json');

/** Image file of one screenshot. */
export function screenshotFile(lang: Lang, name: string): string {
  return path.join(SCREENSHOT_DIR, lang, `${name}.png`);
}

/** Manifest content: the catalog sorted by name, with the image path template. */
export function manifest(): (ScreenshotEntry & { path: string })[] {
  return [...SCREENSHOT_CATALOG]
    .sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0))
    .map((e) => ({ name: e.name, screen: e.screen, profile: e.profile, path: `{lang}/${e.name}.png` }));
}

/** Writes manifest.json and removes the images of screens no longer in the catalog. */
export function writeManifest(langs: readonly Lang[]): void {
  const names = new Set(SCREENSHOT_CATALOG.map((e) => e.name));
  for (const lang of langs) {
    const dir = path.join(SCREENSHOT_DIR, lang);
    fs.mkdirSync(dir, { recursive: true });
    for (const f of fs.readdirSync(dir)) {
      if (f.endsWith('.png') && !names.has(f.slice(0, -4))) fs.rmSync(path.join(dir, f));
    }
  }
  fs.writeFileSync(MANIFEST_FILE, `${JSON.stringify(manifest(), null, 2)}\n`);
}
