// Documentation screenshots (CLAUDE.md section 4.2, plan step 19 section 4): every screen of the
// catalog (support/screenshots.ts) is captured in English and in French into
// docs/user/screenshots/<lang>/<name>.png, and manifest.json is rewritten from the catalog.
//
// Only active with SCREENSHOTS=1 (`make screenshots`, SQLite only): the "screenshots" project of
// playwright.config.ts then runs this file alone, on one worker, in order; normal runs exclude it.
// Determinism: the run contains only the seed and the fixed data below (fictitious names and
// example.com / example.org / example.net addresses, fixed file names and contents), the browser
// clock is frozen, the viewport is 1280x800 with reduced motion, and the values that change at
// every run (identifiers, SHA-256 fingerprints, token prefixes, dates and times, TOTP secrets)
// are masked.
import type { BrowserContext, Locator, Page } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { request } from '../support/api';
import { makeFile, textFile, type GeneratedFile } from '../support/data';
import { createInvitation, downloadPath, openDepositSession, tokenDeposit } from '../support/deposit';
import { HOSTS, ORIGINS, RUN_DIR, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { expect, test, type NewContextOptions } from '../support/fixtures';
import { BROWSER_LOCALE, LANGS, msg, type Lang } from '../support/i18n';
import { mailLink } from '../support/publicflow';
import { re } from '../support/regexp';
import { waitForCode, waitForMail } from '../support/mailpit';
import { screenshotFile, writeManifest } from '../support/screenshots';
import { loadState, superAdminApi } from '../support/state';

test.skip(process.env.SCREENSHOTS !== '1', 'captured by `make screenshots` (SCREENSHOTS=1) only');

/** Neutral gray drawn over the masked areas. */
const MASK_COLOR = '#c9ced6';

/** Browser time of every capture (frozen: no ticking countdown or relative date). */
const FIXED_TIME = new Date();
FIXED_TIME.setSeconds(0, 0);

/** Depositors identified through the public screens (one per language: each needs a first code). */
const DEPOSITOR: Record<Lang, string> = { en: 'alice@example.com', fr: 'camille@example.com' };
/** Recipient of the transfers deposited through the screens. */
const RECIPIENT: Record<Lang, string> = { en: 'dana@example.org', fr: 'dominique@example.org' };
/** Fixed client addresses (shown in the audit logs): browser contexts per profile, API session. */
const CLIENT_IP = { public: '10.1.0.10', api: '10.1.0.11', delegate: '10.2.0.20', super: '10.3.0.30' };
/** Internal sender of the transfers and invitations created through the API. */
const API_SENDER = 'bob@example.com';

/** Fixed data created once per run (kept in .run/ so that a restarted worker reuses it). */
interface ScreenshotData {
  /** Download page path of a transfer per language (message in that language). */
  download: Record<Lang, string>;
  /** Identifier of the English transfer (admin detail screen). */
  transferId: string;
  /** Download page path of a password-protected transfer. */
  downloadPassword: string;
  /** Invitation landing path per language. */
  invitation: Record<Lang, string>;
  /** Activation page path of a pending delegated admin. */
  activation: string;
  /** Password of the activated delegated admin of entities A and B (list of entities). */
  multiDelegatePassword: string;
}

/** Delegated admin of both entities: the list of entities is only shown with several. */
const MULTI_DELEGATE = 'morgan';

const DATA_FILE = path.join(RUN_DIR, 'screenshots-data.json');

const MESSAGES: Record<Lang, string> = {
  en: 'Hello Dana, here are the documents for the Monday meeting.',
  fr: 'Bonjour Dominique, voici les documents pour la réunion de lundi.',
};

const LEGAL: Record<Lang, string> = {
  en: '# Legal notice\n\nThis service is published by **Entity A**, 1 Example Street, Example City.\n\nIt is hosted on the servers of Entity A.\n\n## Contact\n\nlegal@entity-a.example.com',
  fr: "# Mentions légales\n\nCe service est édité par **Entity A**, 1 rue de l'Exemple, Ville-Exemple.\n\nIl est hébergé sur les serveurs d'Entity A.\n\n## Contact\n\nlegal@entity-a.example.com",
};

/** Files of the transfers created through the API (contents derived from the names). */
function apiFiles(lang: Lang): GeneratedFile[] {
  const names =
    lang === 'en'
      ? ['quarterly-report.pdf', 'site-photos.zip', 'meeting-notes.txt']
      : ['rapport-trimestriel.pdf', 'photos-chantier.zip', 'compte-rendu.txt'];
  return [
    makeFile(names[0]!, 180 * 1024, { mimeType: 'application/pdf' }),
    // Larger than the antivirus limit of the run: shown as "not analysed (too large)".
    makeFile(names[1]!, 1536 * 1024, { mimeType: 'application/zip' }),
    textFile(names[2]!, lang === 'en' ? 'Agenda of the meeting.\n' : 'Ordre du jour de la réunion.\n'),
  ];
}

/** Admin API call with a JSON Merge Patch body (the AdminApi helper only sends JSON). */
async function mergePatch(apiPath: string, body: unknown): Promise<void> {
  const s = loadState();
  const res = await request(s.serverPort, 'PATCH', `/api/v1${apiPath}`, {
    body: Buffer.from(JSON.stringify(body)),
    headers: {
      'Content-Type': 'application/merge-patch+json',
      Cookie: `__Host-tt_admin=${s.superAdmin.apiSession.cookie}`,
      'X-CSRF-Token': s.superAdmin.apiSession.csrf,
      Origin: ORIGINS.admin,
      'Sec-Fetch-Site': 'same-origin',
    },
  });
  if (res.status !== 200) throw new Error(`PATCH ${apiPath} -> ${res.status} ${res.text.slice(0, 300)}`);
}

/** Path, query and fragment of a URL (to be opened on a given origin). */
function pathOf(url: string): string {
  const u = new URL(url, 'https://placeholder.localhost');
  return u.pathname + u.search + u.hash;
}

async function createData(): Promise<ScreenshotData> {
  const s = loadState();
  const a = s.tenants.a.id;
  const api = superAdminApi();

  // The seeded API token gets a realistic name.
  const tokens = await api.ok<{ items?: { id: string; name: string }[] } | { id: string; name: string }[]>(
    'GET',
    `/admin/tenants/${a}/api-tokens`,
  );
  const list = Array.isArray(tokens) ? tokens : (tokens.items ?? []);
  for (const t of list) {
    if (t.name === 'e2e seed token')
      await mergePatch(`/admin/tenants/${a}/api-tokens/${t.id}`, { name: 'Accounting export' });
  }

  await api.ok(
    'POST',
    `/admin/tenants/${a}/blocklist`,
    { kind: 'domain', value: 'spam.example.net', comment: 'Spam campaign' },
    [201],
  );
  await api.ok(
    'POST',
    `/admin/tenants/${a}/blocklist`,
    { kind: 'email', value: 'mallory@example.org', comment: 'Repeated abuse' },
    [201],
  );
  for (const lang of LANGS) {
    await api.ok('PUT', `/admin/tenants/${a}/legal/legal-notice/${lang}`, { markdown: LEGAL[lang] });
  }

  const download = {} as Record<Lang, string>;
  let transferId = '';
  for (const lang of LANGS) {
    const t = await tokenDeposit(
      s.apiTokenA,
      API_SENDER,
      {
        recipients: [RECIPIENT[lang]],
        files: apiFiles(lang),
        message: MESSAGES[lang],
        language: lang,
      },
      { host: HOSTS.a },
    );
    download[lang] = downloadPath(t.downloadUrl!);
    if (lang === 'en') transferId = t.id;
  }
  const protectedTransfer = await tokenDeposit(
    s.apiTokenA,
    API_SENDER,
    {
      recipients: ['erin@example.net'],
      files: [makeFile('contract-draft.docx', 64 * 1024, { mimeType: 'application/octet-stream' })],
      password: 'correct horse battery staple',
      language: 'en',
    },
    { host: HOSTS.a },
  );

  // Invitations of external people by the internal sender (links read in Mailpit).
  const session = await openDepositSession(API_SENDER, { host: HOSTS.a, clientIp: CLIENT_IP.api });
  const invitation = {} as Record<Lang, string>;
  const guests: Record<Lang, [string, string]> = {
    en: ['erin@example.org', 'Hi Erin, please send me the signed contract.'],
    fr: ['elise@example.org', 'Bonjour Élise, merci de m’envoyer le contrat signé.'],
  };
  for (const lang of LANGS) {
    const [guest, message] = guests[lang];
    const after = Date.now() - 2000;
    await createInvitation(session, guest, message);
    const mail = await waitForMail(guest, { after });
    invitation[lang] = pathOf(mailLink(mail, '/i/', ORIGINS.a));
  }

  // A delegated admin who has not activated the account yet.
  const created = await api.ok<{ activationUrl: string }>(
    'POST',
    '/admin/admins',
    {
      username: 'jordan',
      email: 'jordan@example.com',
      role: 'delegated_admin',
      tenantIds: [a],
      requireTotp: true,
    },
    [201],
  );

  // A delegated admin of entities A and B, activated through the API (no second factor): a
  // delegated admin with a single entity goes straight to its settings instead of the list.
  const multi = await api.ok<{ activationUrl: string }>(
    'POST',
    '/admin/admins',
    {
      username: MULTI_DELEGATE,
      email: 'morgan@example.com',
      role: 'delegated_admin',
      tenantIds: [a, s.tenants.b.id],
      requireTotp: false,
    },
    [201],
  );
  const multiDelegatePassword = `screenshots-${crypto.randomBytes(12).toString('base64url')}`;
  const activated = await request(s.serverPort, 'POST', '/api/v1/admin/activation', {
    body: { activationToken: new URL(multi.activationUrl).hash.slice(1), password: multiDelegatePassword },
    headers: { Origin: ORIGINS.admin, 'Sec-Fetch-Site': 'same-origin' },
  });
  if (activated.status < 200 || activated.status >= 300) {
    throw new Error(`activation -> ${activated.status} ${activated.text.slice(0, 300)}`);
  }

  return {
    download,
    transferId,
    downloadPassword: downloadPath(protectedTransfer.downloadUrl!),
    invitation,
    activation: pathOf(created.activationUrl),
    multiDelegatePassword,
  };
}

let data: ScreenshotData;

test.beforeAll(async () => {
  test.setTimeout(120_000);
  writeManifest(LANGS);
  if (fs.existsSync(DATA_FILE)) {
    data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) as ScreenshotData;
    return;
  }
  data = await createData();
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
});

/** Regular expression matching a label that starts with text (labels may end with "(required)"). */
function startsWith(text: string): RegExp {
  return re(text, { start: true });
}

/** Opens a page in a fresh guarded context in lang, with the frozen clock. */
async function openPage(
  newContext: (o?: NewContextOptions) => Promise<BrowserContext>,
  lang: Lang,
  storageState?: string,
): Promise<Page> {
  const context = await newContext({
    // A fixed client address per profile: the audit logs show the same IPs at every run.
    clientIp:
      storageState === STORAGE_SUPER
        ? CLIENT_IP.super
        : storageState === STORAGE_DELEGATE
          ? CLIENT_IP.delegate
          : CLIENT_IP.public,
    locale: BROWSER_LOCALE[lang],
    reducedMotion: 'reduce',
    ...(storageState ? { storageState } : {}),
  });
  const page = await context.newPage();
  await page.clock.setFixedTime(FIXED_TIME);
  return page;
}

/** Waits for the level-1 heading of a screen (message key, or any heading when omitted). */
async function heading(page: Page, lang: Lang, key?: string, vars?: Record<string, string>): Promise<void> {
  const h1 = key
    ? page.getByRole('heading', { level: 1, name: msg(lang, key, vars), exact: true })
    : page.getByRole('heading', { level: 1 });
  await expect(h1.first()).toBeVisible({ timeout: 30_000 });
}

/**
 * Values that change at every run, as [pattern, how to neutralise it]: identifiers (prefix and
 * ULID or random suffix: ten_..., trf_..., mk_...), SHA-256 fingerprints and other hexadecimal
 * digests, API token prefixes and secrets, dates and times (server timestamps).
 */
const VOLATILE: readonly [string, 'id' | 'hex' | 'token' | 'digits' | 'ip'][] = [
  [/\b[a-z]{2,4}_(?=[0-9A-Za-z]*\d)[0-9A-Za-z]{12,}\b/.source, 'id'],
  // SHA-256 fingerprints, pseudonyms of erased addresses and other digests (letters and digits).
  [/\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{12,}\b/.source, 'hex'],
  [/\b[0-9a-f]{8}(?:-[0-9a-f]{4,})+\b/.source, 'hex'],
  [/\btt_[A-Za-z0-9_-]{4,}/.source, 'token'],
  // Dates (10/24/26, 24/10/2026, 2026-10-24, Oct 24, 2026) and times (7:58 PM, 19:58:50); the
  // lookarounds keep IPv4 addresses and IPv6 examples (2001:db8::) out.
  [
    /(?<![\d.])\d{1,4}[/.-]\d{1,2}[/.-]\d{2,4}(?![\d.])|\b20\d\d\b(?!:)|\b\d{1,2}:\d{2}(?::\d{2})?\b/.source,
    'digits',
  ],
  // Client addresses other than the fixed ones of this spec (e.g. the sign-ins of the global
  // setup), but not the ranges of the network settings (followed by a prefix length).
  [/\b\d{1,3}(?:\.\d{1,3}){3}\b(?!\/)/.source, 'ip'],
];

/**
 * Neutralises the volatile values in the text of the page and marks their elements with
 * data-e2e-volatile (masked in the capture). Masking alone is not enough: the width of a
 * random value moves the columns of a table from one run to the next. The values are replaced
 * by fixed characters of the same length, so that the layout no longer depends on them.
 */
async function neutraliseVolatileText(page: Page): Promise<void> {
  await page.evaluate(
    ({ rules, fixedIps }) => {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const nodes: Text[] = [];
      while (walker.nextNode()) nodes.push(walker.currentNode as Text);
      for (const node of nodes) {
        const before = node.nodeValue ?? '';
        let text = before;
        for (const [source, kind] of rules) {
          text = text.replace(new RegExp(source, 'g'), (m) => {
            if (kind === 'id')
              return m.replace(/_(.*)$/, (_all, rest: string) => `_${'0'.repeat(rest.length)}`);
            if (kind === 'hex') return m.replace(/[0-9a-f]/g, '0');
            if (kind === 'token') return `tt_${'X'.repeat(m.length - 3)}`;
            if (kind === 'ip') return fixedIps.includes(m) ? m : '000.000.000.000';
            return m.replace(/\d/g, '0');
          });
        }
        if (text !== before) {
          node.nodeValue = text;
          node.parentElement?.setAttribute('data-e2e-volatile', '');
        }
      }
    },
    { rules: VOLATILE, fixedIps: [...Object.values(CLIENT_IP), '127.0.0.1'] },
  );
}

/** Areas masked in every capture. */
function volatileAreas(page: Page, lang: Lang): Locator[] {
  return [
    page.locator('[data-e2e-volatile]'),
    // Disk space of the machine running the capture (home and system overview).
    page
      .locator('.tt-quota')
      .filter({ has: page.getByRole('meter', { name: msg(lang, 'sysStats.disk.label') }) }),
    page.locator('input[type="date"], input[type="datetime-local"], input[type="time"]'),
  ];
}

/** Lets the screen settle, then writes docs/user/screenshots/<lang>/<name>.png. */
async function shoot(
  page: Page,
  lang: Lang,
  name: string,
  mask: Locator[] = [],
  opts: { inPlace?: Locator[] } = {},
): Promise<void> {
  await page.waitForLoadState('networkidle');
  // Masks are drawn in the page and cannot cover a modal dialog (top layer): the volatile
  // elements of a dialog are painted over in place instead.
  for (const locator of opts.inPlace ?? []) {
    // Through the CSSOM: a style element or attribute would violate the CSP (and fail the guards).
    await locator.evaluateAll((els, color) => {
      for (const el of els) {
        if (!(el instanceof HTMLElement)) continue;
        el.style.setProperty('color', 'transparent', 'important');
        el.style.setProperty('background', color, 'important');
      }
    }, MASK_COLOR);
  }
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
  await neutraliseVolatileText(page);
  await page.evaluate(async () => {
    await document.fonts.ready;
    // No focus ring left by the last click or by the focus moved to the heading.
    const active = document.activeElement;
    if (active instanceof HTMLElement && !active.closest('[role="dialog"]')) active.blur();
  });
  await page.screenshot({
    path: screenshotFile(lang, name),
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
    mask: [...volatileAreas(page, lang), ...mask],
    maskColor: MASK_COLOR,
  });
}

test.describe('depositor', () => {
  test('deposit flow and invitation screen', async ({ newContext }) => {
    test.setTimeout(120_000);
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      const email = DEPOSITOR[lang];
      await page.goto(`${ORIGINS.a}/`);
      await heading(page, lang, 'deposit.email.title');
      await page.getByLabel(startsWith(msg(lang, 'deposit.email.label'))).fill(email);
      await shoot(page, lang, 'deposit-email');

      const after = Date.now() - 2000;
      await page.getByRole('button', { name: msg(lang, 'deposit.email.submit'), exact: true }).click();
      await heading(page, lang, 'deposit.code.title');
      await shoot(page, lang, 'deposit-code');
      await page
        .getByLabel(startsWith(msg(lang, 'deposit.code.label')))
        .fill(await waitForCode(email, after));
      await page.getByRole('button', { name: msg(lang, 'deposit.code.submit'), exact: true }).click();

      await heading(page, lang, 'deposit.form.title');
      await page.getByLabel(startsWith(msg(lang, 'deposit.form.recipients.label'))).fill(RECIPIENT[lang]);
      await page.getByLabel(startsWith(msg(lang, 'deposit.form.message.label'))).fill(MESSAGES[lang]);
      const files =
        lang === 'en'
          ? [
              makeFile('project-plan.pdf', 240 * 1024, { mimeType: 'application/pdf' }),
              makeFile('floor-plans.zip', 620 * 1024, { mimeType: 'application/zip' }),
            ]
          : [
              makeFile('plan-du-projet.pdf', 240 * 1024, { mimeType: 'application/pdf' }),
              makeFile('plans-des-etages.zip', 620 * 1024, { mimeType: 'application/zip' }),
            ];
      await page
        .getByLabel(startsWith(msg(lang, 'deposit.form.files.label')))
        .setInputFiles(files.map((f) => ({ name: f.name, mimeType: f.mimeType, buffer: f.buffer })));
      for (const f of files) await expect(page.getByText(f.name).first()).toBeVisible();
      // The selected files are at the bottom of the form: scroll down to the send button, so that
      // the capture (one viewport, 1280 x 800) shows the file list with the options above it.
      await page
        .getByRole('button', { name: msg(lang, 'deposit.form.submit'), exact: true })
        .evaluate((el) => el.scrollIntoView({ block: 'end' }));
      await shoot(page, lang, 'deposit-form');

      await page.getByRole('button', { name: msg(lang, 'deposit.form.submit'), exact: true }).click();
      await heading(page, lang, 'deposit.done.title');
      await shoot(page, lang, 'deposit-sent');

      await page.goto(`${ORIGINS.a}/invite`);
      await heading(page, lang, 'invitation.invite.title');
      await shoot(page, lang, 'invite');
    }
  });

  test('invitation landing', async ({ newContext }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.a}${data.invitation[lang]}`);
      await heading(page, lang, 'invitation.landing.title');
      await shoot(page, lang, 'invitation-landing');
    }
  });

  test('legal notice', async ({ newContext }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.a}/legal/legal-notice`);
      await expect(
        page.getByRole('heading', { name: lang === 'en' ? 'Legal notice' : 'Mentions légales' }).first(),
      ).toBeVisible();
      await shoot(page, lang, 'legal-notice');
    }
  });
});

test.describe('recipient', () => {
  test('download page', async ({ newContext }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.a}${data.download[lang]}`);
      await heading(page, lang, 'download.title');
      await expect(page.getByText(apiFiles(lang)[0]!.name).first()).toBeVisible();
      await shoot(page, lang, 'download');
    }
  });

  test('password-protected download page', async ({ newContext }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.a}${data.downloadPassword}`);
      await heading(page, lang, 'download.locked.title');
      await shoot(page, lang, 'download-password');
    }
  });
});

test.describe('delegated admin', () => {
  test('sign-in screen', async ({ newContext }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.admin}/admin/login`);
      await heading(page, lang, 'adminAuth.login.title');
      await shoot(page, lang, 'admin-login');
    }
  });

  test('account activation', async ({ newContext }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.admin}${data.activation}`);
      await heading(page, lang, 'adminAuth.activation.title');
      await shoot(page, lang, 'admin-activation');
    }
  });

  // Screens of entity A as its delegated admin: [name, path below /admin/tenants/<id>, title key].
  const tenantScreens: [string, (lang: Lang) => string, string?][] = [
    ['admin-tenant-general', () => 'general', 'adminTenants.general.title'],
    ['admin-tenant-branding', () => 'branding', 'adminTenants.branding.title'],
    ['admin-tenant-network', () => 'network', 'adminTenants.network.title'],
    ['admin-tenant-smtp', () => 'smtp', 'adminTenants.smtp.title'],
    ['admin-tenant-templates', () => 'templates', 'adminTenants.templates.title'],
    ['admin-tenant-template-editor', (lang) => `templates/transfer-notification/${lang}`],
    ['admin-tenant-legal', () => 'legal', 'adminTenants.legal.title'],
    ['admin-tenant-legal-editor', (lang) => `legal/legal-notice/${lang}`],
    ['admin-transfers', () => 'transfers', 'adminOps.transfers.title'],
    ['admin-transfer-detail', () => `transfers/${data.transferId}`, 'adminOps.transfers.detailTitle'],
    ['admin-invitations', () => 'invitations', 'adminOps.invitations.title'],
    ['admin-blocklist', () => 'blocklist', 'adminOps.blocklist.title'],
    ['admin-tokens', () => 'tokens', 'adminOps.tokens.title'],
    ['admin-audit', () => 'audit', 'adminOps.audit.title'],
    ['admin-stats', () => 'stats', 'adminOps.stats.title'],
  ];

  test('home and entity screens', async ({ newContext, state }) => {
    test.setTimeout(180_000);
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang, STORAGE_DELEGATE);
      await page.goto(`${ORIGINS.admin}/admin/`);
      await heading(page, lang, 'admin.home.title');
      await shoot(page, lang, 'admin-home-delegate');
      for (const [name, sub, key] of tenantScreens) {
        await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/${sub(lang)}`);
        await heading(page, lang, key);
        await shoot(page, lang, name);
      }
    }
  });

  test('list of entities', async ({ newContext }) => {
    for (const lang of LANGS) {
      // Signed in as the delegated admin of both entities (its own context, not the shared one).
      const page = await openPage(newContext, lang);
      await page.goto(`${ORIGINS.admin}/admin/login`);
      await heading(page, lang, 'adminAuth.login.title');
      await page.getByLabel(startsWith(msg(lang, 'adminAuth.login.username.label'))).fill(MULTI_DELEGATE);
      await page
        .getByLabel(startsWith(msg(lang, 'adminAuth.login.password.label')))
        .fill(data.multiDelegatePassword);
      await page.getByRole('button', { name: msg(lang, 'adminAuth.login.submit'), exact: true }).click();
      await heading(page, lang, 'admin.home.title');
      await page.goto(`${ORIGINS.admin}/admin/tenants`);
      await heading(page, lang, 'adminTenants.list.title');
      // The view of a delegated admin: no creation link, no Administrators or System menu.
      await expect(page.getByRole('link', { name: msg(lang, 'adminTenants.list.create') })).toHaveCount(0);
      await shoot(page, lang, 'admin-tenants');
    }
  });

  test('personal data search', async ({ newContext, state }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang, STORAGE_DELEGATE);
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/privacy`);
      await heading(page, lang, 'adminOps.privacy.title');
      await page.getByLabel(startsWith(msg(lang, 'opsPrivacy.search.email'))).fill(RECIPIENT.en);
      await page.getByRole('button', { name: msg(lang, 'opsPrivacy.search.submit'), exact: true }).click();
      await expect(page.getByRole('region', { name: msg(lang, 'opsPrivacy.summary.title') })).toBeVisible();
      await shoot(page, lang, 'admin-privacy');
    }
  });

  test('API token secret shown once', async ({ newContext, state }) => {
    const names: Record<Lang, string> = { en: 'Backup script', fr: 'Script de sauvegarde' };
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang, STORAGE_DELEGATE);
      await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/tokens/new`);
      await heading(page, lang, 'adminOps.tokens.createTitle');
      await page.getByLabel(startsWith(msg(lang, 'opsTokens.form.name.label'))).fill(names[lang]);
      await page.getByLabel(startsWith(msg(lang, 'opsTokens.form.cidrs.label'))).fill('192.0.2.10/32');
      await page.getByRole('button', { name: msg(lang, 'opsTokens.form.submit'), exact: true }).click();
      const modal = page.getByRole('dialog', {
        name: msg(lang, 'opsTokens.secret.title', { name: names[lang] }),
      });
      await expect(modal).toBeVisible();
      await shoot(page, lang, 'admin-token-secret', [], { inPlace: [modal.locator('code')] });
    }
  });

  test('account and two-factor enrollment', async ({ newContext, state }) => {
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang, STORAGE_DELEGATE);
      await page.goto(`${ORIGINS.admin}/admin/account`);
      await heading(page, lang, 'adminAuth.account.title');
      await shoot(page, lang, 'admin-account');

      // The section opens a password form, whose submit button has the same name.
      const totp = page.getByRole('region', { name: msg(lang, 'adminAuth.account.totp.title') });
      const enable = totp.getByRole('button', {
        name: msg(lang, 'adminAuth.account.totp.reenroll.enableAction'),
        exact: true,
      });
      await enable.click();
      await totp
        .getByRole('textbox', { name: startsWith(msg(lang, 'adminAuth.account.totp.currentPassword')) })
        .fill(state.delegate.password);
      await enable.click();
      const qr = page.getByRole('img', { name: msg(lang, 'adminAuth.enroll.qrAlt') });
      await expect(qr).toBeVisible();
      // The enrollment steps at the top of the viewport.
      await totp
        .getByRole('heading', { name: msg(lang, 'adminAuth.enroll.title') })
        .evaluate((el) => el.scrollIntoView({ block: 'start' }));
      await shoot(page, lang, 'admin-account-totp', [qr, page.locator('.tt-enroll code')]);
    }
  });
});

test.describe('super admin', () => {
  const screens: [string, string, string][] = [
    ['admin-home-super', '/admin/', 'admin.home.title'],
    ['admin-tenant-create', '/admin/tenants/new', 'adminTenants.create.title'],
    ['admin-admins', '/admin/admins', 'adminAccounts.list.title'],
    ['admin-admin-create', '/admin/admins/new', 'adminAccounts.form.createTitle'],
    ['admin-system', '/admin/system', 'adminSystem.overview.title'],
    ['admin-system-settings', '/admin/system/settings', 'adminSystem.settings.title'],
    ['admin-system-audit', '/admin/system/audit', 'adminSystem.audit.title'],
    ['admin-system-master-key', '/admin/system/master-key', 'adminSystem.masterKey.title'],
  ];

  test('home, entities, administrators and system screens', async ({ newContext }) => {
    test.setTimeout(120_000);
    for (const lang of LANGS) {
      const page = await openPage(newContext, lang, STORAGE_SUPER);
      for (const [name, url, key] of screens) {
        await page.goto(`${ORIGINS.admin}${url}`);
        await heading(page, lang, key);
        await shoot(page, lang, name);
      }
    }
  });

  test('maintenance mode: admin screen and public page', async ({ newContext }) => {
    const api = superAdminApi();
    await api.ok('PUT', '/admin/system/maintenance', {
      enabled: true,
      message: {
        en: 'Upgrade in progress: the service is back at 8 pm.',
        fr: 'Mise à jour en cours : le service revient à 20 h.',
      },
    });
    try {
      for (const lang of LANGS) {
        const admin = await openPage(newContext, lang, STORAGE_SUPER);
        await admin.goto(`${ORIGINS.admin}/admin/system/maintenance`);
        await heading(admin, lang, 'adminSystem.maintenance.title');
        await shoot(admin, lang, 'admin-system-maintenance');

        const pub = await openPage(newContext, lang);
        await pub.goto(`${ORIGINS.a}/`);
        await heading(pub, lang, 'deposit.maintenance.title');
        await shoot(pub, lang, 'maintenance');
      }
    } finally {
      await api.ok('PUT', '/admin/system/maintenance', { enabled: false });
    }
  });
});
