// Export and import of a tenant configuration by the super admin (since 2.0), through the admin
// interface:
//   - the export link of the general settings downloads a valid JSON file (schemaVersion 1) that
//     never holds a secret, with a link that follows the "include the branding" checkbox;
//   - "Duplicate" in the list opens the import screen, fetches the export itself and ends on the
//     setup wizard of the new tenant, which keeps the configuration of the source; its imported
//     network rules leave the network steps to do until they are confirmed in the wizard;
//   - the import from a file: a file that is not JSON is refused in the browser, an invalid
//     configuration is located by its JSON pointer, then a valid file creates the tenant.
// Every test works on its own throwaway tenants (FQDN t-<random>.localhost).
import type { Page } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { ORIGINS, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { superAdminApi } from '../support/state';

const GiB = 2 ** 30;
const uniq = (): string => crypto.randomBytes(4).toString('hex');

interface TempTenant {
  id: string;
  name: string;
  fqdn: string;
}

/** Creates a throwaway tenant with a few settings to carry over (a network rule). */
async function createSource(): Promise<TempTenant> {
  const id = uniq();
  const body = {
    name: `E2E source ${id}`,
    fqdn: `t-${id}.localhost`,
    defaultLanguage: 'en',
    storageQuotaBytes: GiB,
    maxTransferBytes: GiB,
    maxTransferCeiling: GiB,
  };
  const api = superAdminApi();
  const t = await api.ok<{ id: string }>('POST', '/admin/tenants', body, [201]);
  await api.ok('PUT', `/admin/tenants/${t.id}/network`, {
    internalCidrs: ['10.77.0.0/16'],
    internalDomains: [`${id}.example.com`],
  });
  return { id: t.id, name: body.name, fqdn: body.fqdn };
}

async function deleteTenant(tenant: { id: string; name: string } | undefined): Promise<void> {
  if (!tenant) return;
  await superAdminApi().call(
    'DELETE',
    `/admin/tenants/${tenant.id}?confirm=${encodeURIComponent(tenant.name)}`,
  );
}

async function expectHeading(page: Page, name: string | RegExp): Promise<void> {
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

test.describe('tenant configuration export and import', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('exports the configuration as a JSON file', async ({ page }) => {
    const source = await createSource();
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants/${source.id}/general`);
      await expectHeading(page, 'General');
      const section = page.getByRole('region', { name: 'Exporting the configuration' });
      await expect(section.getByText(/never contains a secret/)).toBeVisible();
      await checkA11y(page);

      const link = section.getByRole('link', { name: /Download the configuration/ });
      await expect(link).toHaveAttribute('href', /includeBranding=false$/);
      await section.getByRole('checkbox', { name: 'Include the logo and the background image' }).check();
      await expect(link).toHaveAttribute('href', /includeBranding=true$/);

      const [download] = await Promise.all([page.waitForEvent('download'), link.click()]);
      expect(download.suggestedFilename()).toMatch(/\.json$/);
      const file = await download.path();
      const exported = JSON.parse(fs.readFileSync(file, 'utf8')) as {
        schemaVersion: number;
        network?: { internalCidrs?: string[] };
      };
      expect(exported.schemaVersion).toBe(1);
      expect(exported.network?.internalCidrs).toEqual(['10.77.0.0/16']);
    } finally {
      await deleteTenant(source);
    }
  });

  test('duplicates a tenant from the list and lands on the setup wizard', async ({ page, guards }) => {
    // The first attempt reuses the FQDN of the source: 409, shown on the field.
    guards.allowHttpError(409, /\/api\/v1\/admin\/tenants\/import$/);
    const source = await createSource();
    let copy: TempTenant | undefined;
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants`);
      await expectHeading(page, 'Entities');
      await page.getByRole('link', { name: `Duplicate ${source.name}` }).click();
      await expectHeading(page, `Duplicate the entity ${source.name}`);
      await expect(page).toHaveURL(new RegExp(`/admin/tenants/import\\?from=${source.id}$`));
      await checkA11y(page);

      // The storage quota of the source is proposed; an FQDN already used is refused on its field.
      await expect(page.getByRole('textbox', { name: /^Storage quota/ })).toHaveValue('1');
      const id = uniq();
      const name = `E2E copy ${id}`;
      await page.getByRole('textbox', { name: /^Entity name/ }).fill(name);
      await page.getByRole('textbox', { name: /^Address \(FQDN\)/ }).fill(source.fqdn);
      await page.getByRole('button', { name: 'Create the entity' }).click();
      await expect(page.getByText('This address is already used by another entity.').first()).toBeVisible();

      const fqdn = `t-${id}.localhost`;
      await page.getByRole('textbox', { name: /^Address \(FQDN\)/ }).fill(fqdn);
      await page.getByRole('button', { name: 'Create the entity' }).click();
      await expectHeading(page, 'Setup');
      await expect(page).toHaveURL(/\/admin\/tenants\/[^/]+\/setup$/);
      const copyId = /\/tenants\/([^/]+)\/setup$/.exec(page.url())![1]!;
      copy = { id: copyId, name, fqdn };
      const steps = page.getByRole('list', { name: 'Setup steps' });
      await expect(steps).toBeVisible();

      const network = await superAdminApi().ok<{ internalCidrs: string[] }>(
        'GET',
        `/admin/tenants/${copyId}/network`,
      );
      expect(network.internalCidrs).toEqual(['10.77.0.0/16']);

      // The imported ranges and domains must be confirmed (T-307): the network steps stay to do,
      // the wizard lists the rules with a "Confirm" button.
      const step = (label: string) => steps.getByRole('listitem').filter({ hasText: label });
      await expect(step('Internal IP ranges')).toContainText('To do');
      await expect(step('Internal mail domains')).toContainText('To do');
      const review = page.locator('.tt-alert').filter({
        hasText: 'These ranges and domains were imported: check them, then confirm.',
      });
      await expect(review).toBeVisible();
      await expect(review.getByText('10.77.0.0/16')).toBeVisible();
      await checkA11y(page);
      await review.getByRole('button', { name: 'Confirm' }).click();
      await expect(page.getByText('The internal ranges and domains are confirmed.')).toBeVisible();
      await expect(review).toBeHidden();
      await expect(step('Internal IP ranges')).toContainText('Done');
      await expect(step('Internal mail domains')).toContainText('Done');
      const setup = await superAdminApi().ok<{ networkReviewedAt: string | null }>(
        'GET',
        `/admin/tenants/${copyId}/setup`,
      );
      expect(setup.networkReviewedAt).not.toBeNull();
    } finally {
      await deleteTenant(copy);
      await deleteTenant(source);
    }
  });

  test('imports a configuration file: not JSON, invalid, then valid', async ({ page, guards }) => {
    // The invalid document is refused by the server: 422, located in the file.
    guards.allowHttpError(422, /\/api\/v1\/admin\/tenants\/import$/);
    const source = await createSource();
    let created: TempTenant | undefined;
    try {
      const exported = await superAdminApi().ok<Record<string, unknown>>(
        'GET',
        `/admin/tenants/${source.id}/export`,
      );

      await page.goto(`${ORIGINS.admin}/admin/tenants`);
      await page.getByRole('link', { name: 'Import a configuration' }).click();
      await expectHeading(page, 'Import a configuration');
      await checkA11y(page);
      const picker = page.getByLabel(/^Configuration file \(JSON\)/);

      // Not JSON: refused in the browser, with a clear message.
      await picker.setInputFiles({
        name: 'config.json',
        mimeType: 'application/json',
        buffer: Buffer.from('nope'),
      });
      await expect(page.getByText('This file is not valid JSON.')).toBeVisible();

      // A document the server refuses: the location of the first error is shown.
      // Both members of network are required (strict import): only the range is wrong.
      const invalid = {
        ...exported,
        network: { internalCidrs: ['10.0.0.0/8', 'not-a-cidr'], internalDomains: ['example.com'] },
      };
      const id = uniq();
      const name = `E2E import ${id}`;
      await picker.setInputFiles({
        name: 'invalid.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify(invalid)),
      });
      await page.getByRole('textbox', { name: /^Entity name/ }).fill(name);
      await page.getByRole('textbox', { name: /^Address \(FQDN\)/ }).fill(`t-${id}.localhost`);
      await page.getByRole('textbox', { name: /^Storage quota/ }).fill('1');
      await page.getByRole('combobox', { name: 'Unit of Storage quota' }).selectOption('GiB');
      await page.getByRole('button', { name: 'Create the entity' }).click();
      await expect(
        page.getByText(/Error in the file at \/config\/network\/internalCidrs\/1/).first(),
      ).toBeVisible();

      // The valid file creates the tenant, in the setup state.
      await picker.setInputFiles({
        name: 'config.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify(exported)),
      });
      await page.getByRole('button', { name: 'Create the entity' }).click();
      await expectHeading(page, 'Setup');
      const newId = /\/tenants\/([^/]+)\/setup$/.exec(page.url())![1]!;
      created = { id: newId, name, fqdn: `t-${id}.localhost` };
    } finally {
      await deleteTenant(created);
      await deleteTenant(source);
    }
  });
});
