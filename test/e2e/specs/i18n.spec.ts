// Scenario 11: French pass (CLAUDE.md section 14). With a French browser (locale fr-FR, hence
// Accept-Language and navigator.languages in French), the public deposit home, the download
// page, the admin sign-in screen and representative admin screens (dashboard, tenant
// configuration, tenant operations, system) are rendered in French: <html lang="fr">, French
// headings (read from the shipped fr bundles), no raw translation key in the visible text or the
// accessible names, and no accessibility violation. The language switch of the footer changes
// the language at once and persists the choice in localStorage under "tt.lang" only.
import type { Page } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { internalEmail, textFile } from '../support/data';
import { HOSTS, ORIGINS, REPO_ROOT, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { downloadPath, tokenDeposit } from '../support/deposit';
import { msg } from '../support/i18n';

const LOCALES_DIR = path.join(REPO_ROOT, 'web', 'src', 'locales');

/** Translation namespaces (one JSON file per namespace in web/src/locales/<lang>/). */
const NAMESPACES = fs
  .readdirSync(path.join(LOCALES_DIR, 'en'))
  .filter((f) => f.endsWith('.json'))
  .map((f) => f.slice(0, -'.json'.length));

/** French message of a key "namespace.path.to.message" (fails when the key is missing). */
function fr(key: string): string {
  return msg('fr', key);
}

/** Generic shape of a raw key: a camelCase namespace followed by a dotted path. */
const CAMEL_KEY = /\b[a-z]+[A-Z][a-zA-Z]*\.[a-z][a-zA-Z.]+\b/g;
/** A known namespace followed by a dotted path (e.g. "common.notFound.title"). */
const NAMESPACE_KEY = new RegExp(
  `\\b(?:${NAMESPACES.join('|')})\\.[a-zA-Z][a-zA-Z0-9]*(?:\\.[a-zA-Z][a-zA-Z0-9]*)*\\b`,
  'g',
);
/** Host names and addresses legitimately shown (e.g. "admin.localhost"). */
const NOT_A_KEY = /\.(?:localhost|example|com|org|net|txt|json)(?:\.|$)/;

/** Fails when the visible text or an accessible name of the page holds a raw translation key. */
async function expectNoRawKeys(page: Page): Promise<void> {
  const text = await page.evaluate(() => {
    const parts = [document.body.innerText, document.title];
    for (const el of document.querySelectorAll('[aria-label],[placeholder],[title],[alt]')) {
      for (const attr of ['aria-label', 'placeholder', 'title', 'alt']) {
        const v = el.getAttribute(attr);
        if (v) parts.push(v);
      }
    }
    return parts.join('\n');
  });
  const found = [...(text.match(CAMEL_KEY) ?? []), ...(text.match(NAMESPACE_KEY) ?? [])].filter(
    (k) => !NOT_A_KEY.test(k),
  );
  expect(found, `raw translation keys on ${page.url()}`).toEqual([]);
}

/** Checks one French screen: language, heading, no raw key, accessibility. */
async function expectFrenchScreen(page: Page, headingKey: string): Promise<void> {
  await expect(page.getByRole('heading', { name: fr(headingKey), level: 1 })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  await expectNoRawKeys(page);
  await checkA11y(page);
}

/**
 * Switches the footer language selector to English, checks the switch applies at once, that
 * localStorage holds only tt.lang=en, and that the choice survives a reload.
 */
async function switchToEnglish(page: Page, englishHeading: string): Promise<void> {
  await page.getByRole('combobox', { name: fr('components.languageSwitch.label') }).selectOption('en');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('heading', { name: englishHeading, level: 1 })).toBeVisible();
  expect(await page.evaluate(() => ({ ...localStorage }))).toEqual({ 'tt.lang': 'en' });
  await expectCleanStorage(page);

  await page.reload();
  await expect(page.getByRole('heading', { name: englishHeading, level: 1 })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('combobox', { name: 'Language' })).toHaveValue('en');
  expect(await page.evaluate(() => ({ ...localStorage }))).toEqual({ 'tt.lang': 'en' });
}

test.describe('French pass', () => {
  test.use({ locale: 'fr-FR' });

  test.describe('public interface', () => {
    test('deposit home in French, language switch persists tt.lang only', async ({ page, state }) => {
      await page.goto(`${state.tenants.a.origin}/`);
      await expectFrenchScreen(page, 'deposit.email.title');
      await expect(page.getByLabel(fr('deposit.email.label'))).toBeVisible();
      await expectCleanStorage(page);
      // Nothing is stored until the user picks a language.
      expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);

      await switchToEnglish(page, 'Send files');
    });

    test('download page in French', async ({ page, state }) => {
      const file = textFile('rapport-trimestriel.txt', 'contenu du rapport');
      const transfer = await tokenDeposit(
        state.apiTokenA,
        internalEmail('i18n-sender'),
        {
          recipients: [internalEmail('i18n-recipient')],
          files: [file],
          message: 'Bonjour, voici le rapport.',
          language: 'fr',
        },
        { host: HOSTS.a },
      );
      await page.goto(`${state.tenants.a.origin}${downloadPath(transfer.downloadUrl!)}`);
      await expectFrenchScreen(page, 'download.title');
      await expect(page.getByRole('table', { name: fr('download.files.caption') })).toBeVisible();
      await expect(page.getByText(file.sha256)).toBeVisible();
      await expect(
        page
          .getByRole('button', { name: fr('download.archive.button') })
          .or(page.getByRole('link', { name: fr('download.archive.button') })),
      ).toBeVisible();
      await expectCleanStorage(page);
    });
  });

  test.describe('administration', () => {
    test('sign-in screen in French, language switch persists tt.lang only', async ({ page }) => {
      await page.goto(`${ORIGINS.admin}/admin/login`);
      await expectFrenchScreen(page, 'adminAuth.login.title');
      await expectCleanStorage(page);
      expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);

      await switchToEnglish(page, 'Sign in to the administration');
    });

    test.describe('signed in as the super admin', () => {
      test.use({ storageState: STORAGE_SUPER });

      test('dashboard, tenant, operations and system screens in French', async ({ page, state }) => {
        const a = state.tenants.a.id;
        const screens: [string, string][] = [
          ['/admin/', 'admin.home.title'],
          [`/admin/tenants/${a}/general`, 'adminTenants.general.title'],
          [`/admin/tenants/${a}/transfers`, 'adminOps.transfers.title'],
          ['/admin/system', 'adminSystem.overview.title'],
        ];
        for (const [url, headingKey] of screens) {
          await page.goto(`${ORIGINS.admin}${url}`);
          await expectFrenchScreen(page, headingKey);
        }
        await expect(page.getByRole('navigation', { name: fr('admin.nav.label') })).toBeVisible();
        await expectCleanStorage(page);
      });
    });
  });
});
