// System screens of the super admin (plan step 19, scenario 9): overview with the disk meter,
// maintenance mode (fr/en messages, admin banner, public page, deposits refused), system
// settings, global audit log and the master key screen without a new key.
//
// Maintenance mode refuses deposits on every entity: this file runs in the "system-serial"
// project (playwright.config.ts), one test at a time, after the rest of the suite. Every test
// that changes instance state restores it, through the API when the screen did not.
import { tokenCreateTransfer } from '../support/deposit';
import { externalEmail, internalEmail, textFile } from '../support/data';
import { ORIGINS, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { superAdminApi } from '../support/state';

const SYSTEM = `${ORIGINS.admin}/admin/system`;

test.use({ storageState: STORAGE_SUPER });

test.describe('system overview', () => {
  test('shows the disk meter and the entities', async ({ page }) => {
    await page.goto(SYSTEM);
    await expect(page.getByRole('heading', { name: 'System overview', level: 1 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Data disk', level: 2 })).toBeVisible();
    const meter = page.getByRole('meter', { name: 'Disk space used' });
    await expect(meter).toBeVisible();
    await expect(page.getByText(/^Alert threshold: /)).toBeVisible();
    await expect(page.getByRole('table', { name: /Activity and storage of the entities/ })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Entity A' })).toBeVisible();
    await checkA11y(page);
    await expectCleanStorage(page);
  });
});

test.describe('maintenance mode', () => {
  const messages = {
    fr: 'Mise à jour en cours, retour vers 20 h.',
    en: 'Upgrade in progress, back around 8 pm.',
  };

  // Whatever happens in the test, deposits must be accepted again afterwards.
  test.afterEach(async () => {
    await superAdminApi().ok('PUT', '/admin/system/maintenance', { enabled: false });
  });

  test('is turned on with messages, shown everywhere, refuses deposits, then turned off', async ({
    page,
    newContext,
    state,
  }) => {
    await page.goto(`${SYSTEM}/maintenance`);
    await expect(page.getByRole('heading', { name: 'Maintenance mode', level: 1 })).toBeVisible();
    await checkA11y(page);
    const form = page.getByRole('form', { name: 'Maintenance mode and messages' });
    await form.getByRole('checkbox', { name: 'Maintenance mode on' }).check();
    await form.getByLabel(/^Message in French/).fill(messages.fr);
    await form.getByLabel(/^Message in English/).fill(messages.en);
    // The preview renders each message as text, with its language.
    await expect(form.locator('p[lang="fr"]', { hasText: messages.fr })).toBeVisible();
    await expect(form.locator('p[lang="en"]', { hasText: messages.en })).toBeVisible();
    await form.getByRole('button', { name: 'Save' }).click();
    const confirm = page.getByRole('dialog', { name: 'Turn maintenance mode on?' });
    await checkA11y(page);
    await confirm.getByRole('button', { name: 'Turn on' }).click();
    await expect(
      page.getByText('Maintenance mode is on: new deposits are refused on every entity.').first(),
    ).toBeVisible();
    // Banner of the administration (polite live region).
    const manage = page.getByRole('link', { name: 'Manage maintenance mode' });
    const banner = page.getByRole('status').filter({ has: manage });
    await expect(banner).toBeVisible();
    await expect(banner).toContainText(
      /Maintenance mode (has been on since .+|is on): new deposits are refused/,
    );
    await checkA11y(page);

    // Public page of entity A, in English and in French: the message is text, with its lang.
    for (const [locale, lang, title] of [
      ['en-US', 'en', 'Service under maintenance'],
      ['fr-FR', 'fr', null],
    ] as const) {
      const ctx = await newContext({ locale });
      const pub = await ctx.newPage();
      await pub.goto(`${state.tenants.a.origin}/`);
      await expect(pub.getByRole('heading', { level: 1 })).toBeVisible();
      if (title) await expect(pub.getByRole('heading', { name: title, level: 1 })).toBeVisible();
      const message = pub.getByText(messages[lang], { exact: true });
      await expect(message).toBeVisible();
      await expect(message).toHaveAttribute('lang', lang);
      // Plain text: no markup is interpreted inside the message.
      expect(await message.evaluate((el) => el.children.length)).toBe(0);
      await checkA11y(pub);
    }

    // A new deposit through the API is refused with 503 maintenance.
    const refused = await tokenCreateTransfer(state.apiTokenA, internalEmail('sys-maint-sender'), {
      recipients: [externalEmail('sys-maint-to')],
      files: [textFile('during-maintenance.txt', 'x\n')],
    });
    expect(refused.status).toBe(503);
    expect((refused.json as unknown as { code: string }).code).toBe('maintenance');

    // Global audit log: the instance event is listed, with "Instance" as its entity.
    await page.goto(`${SYSTEM}/audit`);
    const filters = page.getByRole('search', { name: 'Filter the global audit log' });
    await filters.getByLabel(/^Action/).selectOption({ label: 'Maintenance mode enabled' });
    await filters.getByRole('button', { name: 'Apply' }).click();
    await expect(page).toHaveURL(/[?&]action=maintenance\.enabled(&|$)/);
    const enabledRow = page.getByRole('row').filter({ hasText: 'Maintenance mode enabled' }).first();
    await expect(enabledRow.getByText('Instance', { exact: true })).toBeVisible();

    // Turn it off from the screen.
    await page.goto(`${SYSTEM}/maintenance`);
    await form.getByRole('checkbox', { name: 'Maintenance mode on' }).uncheck();
    await form.getByRole('button', { name: 'Save' }).click();
    await page
      .getByRole('dialog', { name: 'Turn maintenance mode off?' })
      .getByRole('button', { name: 'Turn off' })
      .click();
    await expect(
      page.getByText('Maintenance mode is off: new deposits are accepted again.').first(),
    ).toBeVisible();
    await expect(page.getByRole('link', { name: 'Manage maintenance mode' })).toHaveCount(0);
  });

  test('a message in French only is shown to an English visitor with its own language', async ({
    newContext,
    guards,
    state,
  }) => {
    const frenchOnly = 'Maintenance prolongée, retour vers 21 h.';
    const ctx = await newContext({ locale: 'en-US' });
    const pub = await ctx.newPage();

    // Deposit started before maintenance: the email step is shown, then maintenance is turned
    // on with a French message only. Continuing gets 503 maintenance, whose detail carries no
    // language: the screen reads it from GET /tenant.
    await pub.goto(`${state.tenants.a.origin}/`);
    const email = pub.getByLabel(/^Your email address/);
    await expect(email).toBeVisible();
    await email.fill(internalEmail('sys-maint-fallback'));
    await superAdminApi().ok('PUT', '/admin/system/maintenance', {
      enabled: true,
      message: { fr: frenchOnly },
    });
    guards.allowHttpError(503, /\/api\/v1\/deposit-sessions$/);
    await pub.getByRole('button', { name: 'Continue' }).click();
    await expect(pub.getByRole('heading', { name: 'Service under maintenance', level: 1 })).toBeVisible();
    const inFlow = pub.getByText(frenchOnly, { exact: true });
    await expect(inFlow).toBeVisible();
    await expect(inFlow).toHaveAttribute('lang', 'fr');
    await expect(pub.locator('html')).toHaveAttribute('lang', 'en');
    await checkA11y(pub);

    // A fresh visit: the maintenance page is in English, the fallback message keeps lang="fr".
    await pub.reload();
    await expect(pub.getByRole('heading', { name: 'Service under maintenance', level: 1 })).toBeVisible();
    const message = pub.getByText(frenchOnly, { exact: true });
    await expect(message).toBeVisible();
    await expect(message).toHaveAttribute('lang', 'fr');
    await expect(pub.locator('html')).toHaveAttribute('lang', 'en');
    await checkA11y(pub);
  });
});

test.describe('system settings', () => {
  let original: number | undefined;

  test.afterEach(async () => {
    if (original !== undefined) {
      await superAdminApi().ok('PATCH', '/admin/system/settings', { diskAlertThreshold: original });
    }
  });

  test('the disk alert threshold is changed and restored', async ({ page }) => {
    const settings = await superAdminApi().ok<{ diskAlertThreshold: number }>(
      'GET',
      '/admin/system/settings',
    );
    original = settings.diskAlertThreshold;
    const percent = Math.round(original * 100);
    const changed = percent === 90 ? 91 : 90;

    await page.goto(`${SYSTEM}/settings`);
    await expect(page.getByRole('heading', { name: 'System settings', level: 1 })).toBeVisible();
    const threshold = page.getByLabel(/^Alert threshold/);
    await expect(threshold).toHaveValue(String(percent));
    await checkA11y(page);
    await threshold.fill(String(changed));
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('System settings saved.')).toBeVisible();
    await page.reload();
    await expect(page.getByLabel(/^Alert threshold/)).toHaveValue(String(changed));

    // The overview shows the new threshold.
    await page.goto(SYSTEM);
    await expect(page.getByText(`Alert threshold: ${changed}%`)).toBeVisible();

    // Restore it from the screen.
    await page.goto(`${SYSTEM}/settings`);
    await page.getByLabel(/^Alert threshold/).fill(String(percent));
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('System settings saved.')).toBeVisible();
    const after = await superAdminApi().ok<{ diskAlertThreshold: number }>('GET', '/admin/system/settings');
    expect(after.diskAlertThreshold).toBe(original);
  });
});

test.describe('global audit log', () => {
  test('filters by entity and by action, with the Instance column', async ({ page }) => {
    await page.goto(`${SYSTEM}/audit`);
    await expect(page.getByRole('heading', { name: 'Global audit log', level: 1 })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Entity' })).toBeVisible();
    await checkA11y(page);
    const filters = page.getByRole('search', { name: 'Filter the global audit log' });

    // An instance event (setup), without entity.
    await filters.getByLabel(/^Action/).selectOption({ label: 'Initial setup completed' });
    await filters.getByRole('button', { name: 'Apply' }).click();
    await expect(page).toHaveURL(/[?&]action=setup\.completed(&|$)/);
    const setupRow = page.getByRole('row').filter({ hasText: 'Initial setup completed' });
    await expect(setupRow).toHaveCount(1);
    await expect(setupRow.getByText('Instance', { exact: true })).toBeVisible();

    // One entity: its events only, linked to the entity.
    await filters.getByLabel(/^Entity/).selectOption({ label: 'Entity A' });
    await filters.getByLabel(/^Action/).selectOption({ label: 'API token created' });
    await filters.getByRole('button', { name: 'Apply' }).click();
    await expect(page).toHaveURL(/[?&]action=api_token\.created(&|$)/);
    const rows = page.getByRole('row').filter({ hasText: 'API token created' });
    await expect(rows.first()).toBeVisible();
    await expect(rows.first().getByRole('link', { name: 'Entity A' })).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: 'Entity B' })).toHaveCount(0);
    await expect(page.getByRole('cell', { name: 'Instance', exact: true })).toHaveCount(0);
    await checkA11y(page);
  });
});

test.describe('master key', () => {
  test('without a new key: explanation and no start button', async ({ page }) => {
    await page.goto(`${SYSTEM}/master-key`);
    await expect(page.getByRole('heading', { name: 'Master key', level: 1 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Master keys', level: 2 })).toBeVisible();
    await expect(page.getByText('None configured')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Prepare a rotation', level: 2 })).toBeVisible();
    await expect(page.getByText(/No new master key is configured/)).toBeVisible();
    await expect(page.getByRole('button', { name: /Start the rotation|Resume the rotation/ })).toHaveCount(0);
    await checkA11y(page);
  });
});
