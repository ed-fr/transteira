// Tenant configuration by the super admin (CLAUDE.md sections 5, 12, 13, 6.5), through the
// admin interface: creation and general settings, branding (contrast warning, logo upload),
// network (per-line errors, save blocked, normalised save), SMTP (test email received by
// Mailpit), email templates (syntax error located, preview, reset), legal texts (published on
// the public pages) and the creation of a delegated admin with its single-use activation link.
//
// Every test works on its own throwaway tenant (FQDN t-<random>.localhost, never served by
// Caddy), except the legal text test which needs a public host: it edits the English legal
// notice of entity A with unique content and restores the previous text at the end.
import type { Page } from '@playwright/test';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { MAILPIT_SMTP_PORT, ORIGINS, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { internalEmail } from '../support/data';
import { waitForMail } from '../support/mailpit';
import { superAdminApi } from '../support/state';

const GiB = 2 ** 30;

/** A short random suffix for unique names. */
const uniq = (): string => crypto.randomBytes(4).toString('hex');

/** A throwaway tenant created through the API. */
interface TempTenant {
  id: string;
  name: string;
  fqdn: string;
}

/** Creates a throwaway tenant through the admin API (as the seeded super admin). */
async function createTenant(label: string): Promise<TempTenant> {
  const id = uniq();
  const body = {
    name: `E2E ${label} ${id}`,
    fqdn: `t-${id}.localhost`,
    defaultLanguage: 'en',
    storageQuotaBytes: GiB,
    maxTransferBytes: GiB,
    maxTransferCeiling: GiB,
  };
  const t = await superAdminApi().ok<{ id: string }>('POST', '/admin/tenants', body, [201]);
  return { id: t.id, name: body.name, fqdn: body.fqdn };
}

/** Deletes a throwaway tenant and all its data (best effort: the run's database is thrown away). */
async function deleteTenant(tenant: TempTenant | undefined): Promise<void> {
  if (!tenant) return;
  await superAdminApi().call(
    'DELETE',
    `/admin/tenants/${tenant.id}?confirm=${encodeURIComponent(tenant.name)}`,
  );
}

/** Admin URL of a tenant section. */
const tenantUrl = (id: string, section: string): string => `${ORIGINS.admin}/admin/tenants/${id}/${section}`;

/** Waits for the main heading of a screen. */
async function expectHeading(page: Page, name: string | RegExp): Promise<void> {
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

/** A valid size x size RGBA PNG (one solid colour), encoded in-test with node:zlib. */
function makePng(size: number, rgba: [number, number, number, number]): Buffer {
  const chunk = (type: string, data: Buffer): Buffer => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // no interlace
  const row = Buffer.alloc(1 + size * 4); // filter byte 0, then pixels
  for (let x = 0; x < size; x++) Buffer.from(rgba).copy(row, 1 + x * 4);
  const raw = Buffer.concat(Array.from({ length: size }, () => row));
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

test.describe('tenant configuration', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('creates a tenant and saves its general settings', async ({ page, state, guards }) => {
    // The first attempt reuses the FQDN of entity A on purpose: 409.
    guards.allowHttpError(409, /\/api\/v1\/admin\/tenants$/);
    const id = uniq();
    const name = `E2E created ${id}`;
    let created: TempTenant | undefined;
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants`);
      await expectHeading(page, 'Entities');
      await checkA11y(page);
      await page.getByRole('link', { name: 'Create an entity' }).click();
      await expectHeading(page, 'Create an entity');
      await checkA11y(page);

      await page.getByRole('textbox', { name: /^Entity name/ }).fill(name);
      await page.getByRole('textbox', { name: /^Address \(FQDN\)/ }).fill(state.tenants.a.fqdn);
      await page.getByRole('textbox', { name: /^Storage quota/ }).fill('2');
      await page.getByRole('combobox', { name: 'Unit of Storage quota' }).selectOption('GiB');
      await page.getByRole('button', { name: 'Create the entity' }).click();
      await expect(page.getByText('This address is already used by another entity.').first()).toBeVisible();

      const fqdn = `t-${id}.localhost`;
      await page.getByRole('textbox', { name: /^Address \(FQDN\)/ }).fill(fqdn);
      await page.getByRole('button', { name: 'Create the entity' }).click();
      await expectHeading(page, 'General');
      await expect(page).toHaveURL(/\/admin\/tenants\/[^/]+\/general$/);
      const tenantId = /\/tenants\/([^/]+)\/general$/.exec(page.url())![1]!;
      created = { id: tenantId, name, fqdn };
      await expect(page.getByRole('textbox', { name: /^Entity name/ })).toHaveValue(name);
      await expect(
        page.getByRole('navigation', { name: `Configuration of the entity ${name}` }),
      ).toBeVisible();
      await checkA11y(page);

      // General settings: rename, lower the size per transfer, switch the language.
      const renamed = `${name} renamed`;
      await page.getByRole('textbox', { name: /^Entity name/ }).fill(renamed);
      await page.getByRole('radio', { name: 'French' }).check();
      await page.getByRole('textbox', { name: /^Maximum size per transfer/ }).fill('5');
      await page.getByRole('combobox', { name: 'Unit of Maximum size per transfer' }).selectOption('GiB');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The general settings have been saved.')).toBeVisible();
      created.name = renamed;

      await page.reload();
      await expectHeading(page, 'General');
      await expect(page.getByRole('textbox', { name: /^Entity name/ })).toHaveValue(renamed);
      await expect(page.getByRole('radio', { name: 'French' })).toBeChecked();
      await expect(page.getByRole('textbox', { name: /^Maximum size per transfer/ })).toHaveValue('5');
      await expect(page.getByRole('combobox', { name: 'Unit of Maximum size per transfer' })).toHaveValue(
        'GiB',
      );
    } finally {
      await deleteTenant(created);
    }
  });

  test('branding: contrast warning and logo upload', async ({ page }) => {
    const tenant = await createTenant('branding');
    try {
      await page.goto(tenantUrl(tenant.id, 'branding'));
      await expectHeading(page, 'Branding');
      await checkA11y(page);

      // Logo: a valid 64x64 PNG generated in the test, uploaded then displayed.
      const logo = page.getByRole('region', { name: 'Logo', exact: true });
      await expect(logo.getByText('No image saved.')).toBeVisible();
      await logo
        .locator('input[type="file"]')
        .setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer: makePng(64, [26, 95, 180, 255]) });
      await expect(logo.getByText(/^logo\.png \(/)).toBeVisible();
      await logo.getByRole('button', { name: 'Upload the image' }).click();
      await expect(logo.getByText('The image has been saved.')).toBeVisible();
      const img = logo.getByRole('img', { name: 'Logo of the entity' }).first();
      await expect(img).toBeVisible();
      await expect
        .poll(() =>
          img.evaluate((el) => (el as HTMLImageElement).complete && (el as HTMLImageElement).naturalWidth),
        )
        .toBeGreaterThan(0);
      await expect(logo.getByRole('button', { name: 'Delete the image' })).toBeVisible();
      await checkA11y(page);

      // A low-contrast primary colour: warned, but still saved.
      const colors = page.getByRole('region', { name: 'Colors' });
      await expect(colors.getByText(/At least one color does not offer sufficient contrast/)).toHaveCount(0);
      await page.getByRole('textbox', { name: /^Hexadecimal code: Primary color/ }).fill('#FFFF00');
      const warning = colors.getByText(/At least one color does not offer sufficient contrast/);
      await expect(warning).toBeVisible();
      await expect(
        colors.getByText(/Primary color on light background: [\d.]+:1, Insufficient/).first(),
      ).toBeVisible();
      await colors.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The colors have been saved.')).toBeVisible();

      await page.reload();
      await expectHeading(page, 'Branding');
      await expect(page.getByRole('textbox', { name: /^Hexadecimal code: Primary color/ })).toHaveValue(
        /^#ffff00$/i,
      );
      await expect(page.getByText(/At least one color does not offer sufficient contrast/)).toBeVisible();
    } finally {
      await deleteTenant(tenant);
    }
  });

  test('network: invalid lines block the save, a valid save is normalised', async ({ page }) => {
    const SAVED_CIDRS = '192.0.2.0/24\n198.51.100.7/32\n2001:db8::/32';
    const tenant = await createTenant('network');
    try {
      const puts: string[] = [];
      page.on('request', (r) => {
        if (r.method() === 'PUT' && r.url().endsWith(`/tenants/${tenant.id}/network`)) puts.push(r.url());
      });
      await page.goto(tenantUrl(tenant.id, 'network'));
      await expectHeading(page, 'Network');
      await checkA11y(page);

      const cidrs = page.getByRole('textbox', { name: /^Internal IP address ranges/ });
      const domains = page.getByRole('textbox', { name: /^Internal email domains/ });
      await cidrs.fill('192.0.2.0/24\nnot-a-range\n198.51.100.1/24');
      await domains.fill('example.net\nbad domain');

      // One message per invalid line, with a fix offered for host bits.
      await expect(page.getByText(/^Line 2: Not a valid IP address or CIDR range/)).toBeVisible();
      await expect(
        page.getByText(/^Line 3: The address has host bits set: the matching range is 198\.51\.100\.0\/24\./),
      ).toBeVisible();
      await expect(page.getByText(/^Line 2: Not a valid domain name/)).toBeVisible();
      await expect(cidrs).toHaveAttribute('aria-invalid', 'true');
      await expect(domains).toHaveAttribute('aria-invalid', 'true');
      await checkA11y(page);

      // The save is refused in the browser: error summary, no request.
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The form contains errors')).toBeVisible();
      expect(puts).toEqual([]);

      // Fix: apply the suggestion, drop the bad line, use values the server rewrites.
      await page.getByRole('button', { name: 'Replace line 3 with 198.51.100.0/24' }).click();
      await cidrs.fill('192.0.2.0/24\n2001:DB8::/32\n198.51.100.7');
      await domains.fill('example.net');
      await expect(page.getByText(/^Line \d+:/)).toHaveCount(0);
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The network settings have been saved.')).toBeVisible();
      await expect(
        page.getByText('The server normalized some values. The lists shown are the saved ones.'),
      ).toBeVisible();
      // Saved values: a bare address becomes a /32, IPv6 is lowercased, IPv4 ranges come first.
      await expect(cidrs).toHaveValue(SAVED_CIDRS);
      expect(puts).toHaveLength(1);

      await page.reload();
      await expectHeading(page, 'Network');
      await expect(cidrs).toHaveValue(SAVED_CIDRS);
      await expect(domains).toHaveValue('example.net');
    } finally {
      await deleteTenant(tenant);
    }
  });

  test('SMTP: configures Mailpit and sends a test email', async ({ page, guards }) => {
    const tenant = await createTenant('smtp');
    // A tenant without SMTP settings answers 404 on GET /smtp (the screen shows "not configured").
    guards.allowHttpError(404, new RegExp(`/api/v1/admin/tenants/${tenant.id}/smtp$`));
    try {
      await page.goto(tenantUrl(tenant.id, 'smtp'));
      await expectHeading(page, 'Mail (SMTP)');
      await expect(
        page.getByText('Mail is not configured yet: the entity cannot send any email.'),
      ).toBeVisible();
      await expect(page.getByRole('button', { name: 'Send a test email' })).toBeDisabled();
      await checkA11y(page);

      // Mailpit is a relay without authentication nor encryption (section 12.1).
      const fromAddress = `transfer@${tenant.fqdn.replace('.localhost', '')}.example.com`;
      await page.getByRole('textbox', { name: /^SMTP server/ }).fill('127.0.0.1');
      await page.getByRole('radio', { name: 'None (relay on an internal network)' }).check();
      await page.getByRole('textbox', { name: /^Port/ }).fill(String(MAILPIT_SMTP_PORT));
      await page.getByRole('textbox', { name: /^Sender address/ }).fill(fromAddress);
      await page.getByRole('textbox', { name: /^Sender name/ }).fill('E2E transfers');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The SMTP settings have been saved.')).toBeVisible();
      await expect(
        page.getByText('Mail is not configured yet: the entity cannot send any email.'),
      ).toHaveCount(0);

      const to = internalEmail('smtp-test');
      const after = Date.now() - 2000;
      await page.getByRole('textbox', { name: /^Recipient address/ }).fill(to);
      await page.getByRole('button', { name: 'Send a test email' }).click();
      // The result alert (success, or failure with the stage and server message) is checked whole.
      const testSection = page.getByRole('region', { name: 'Test email' });
      await expect(testSection.getByText(/The test email (was accepted|could not be sent)/)).toBeVisible({
        timeout: 20_000,
      });
      // On failure, the section shows the stage and the server message: compared whole.
      await expect(testSection).toContainText(/The test email was accepted by the server in [\d.,\s]+ ms\./);
      await expect(testSection.getByText('Stage: Done')).toBeVisible();
      await checkA11y(page);

      const mail = await waitForMail(to, { after });
      expect(mail.From.Address).toBe(fromAddress);
      expect(mail.To.map((a) => a.Address)).toEqual([to]);
    } finally {
      await deleteTenant(tenant);
    }
  });

  test('email template: syntax error located, save and reset', async ({ page, guards }) => {
    // A template with a syntax error is refused with 400 validation-failed.
    guards.allowHttpError(400, /\/email-templates\/verification-code\/en$/);
    const tenant = await createTenant('templates');
    try {
      await page.goto(tenantUrl(tenant.id, 'templates'));
      await expectHeading(page, 'Email templates');
      await checkA11y(page);
      await page.getByRole('link', { name: 'Edit the template Verification code (English)' }).click();
      await expectHeading(page, 'Verification code (English)');
      await expect(page.getByText('Default', { exact: true })).toBeVisible();

      const subject = page.getByRole('textbox', { name: /^Subject/ });
      const html = page.getByRole('textbox', { name: /^HTML body/ });
      const text = page.getByRole('textbox', { name: /^Text body/ });
      const originalSubject = await subject.inputValue();
      const originalHtml = await html.inputValue();
      const originalText = await text.inputValue();
      expect(originalText).toContain('{{code}}');
      await checkA11y(page);

      // An unclosed placeholder on a new last line: located by line and column.
      const line = originalText.split('\n').length + 1;
      await text.fill(`${originalText}\nBroken {{tenant_name`);
      await page.getByRole('button', { name: 'Save the template' }).click();
      await expect(
        page.getByText('The template was not saved: correct the errors listed below.'),
      ).toBeVisible();
      await expect(page.getByText(new RegExp(`^Text body, line ${line}, column \\d+:$`))).toBeVisible();
      const goTo = page.getByRole('button', { name: `Go to the error (Text body, line ${line})` });
      await expect(goTo).toBeVisible();
      await checkA11y(page);
      await goTo.click();
      await expect(text).toBeFocused();

      // A valid customisation (the preview is covered by the next test).
      await subject.fill(`${originalSubject} (e2e)`);
      await html.fill(
        '<p>Your code for {{tenant_name}}: <strong>{{code}}</strong></p>\n<p>Valid {{validity_minutes}} minutes. E2E customised footer.</p>',
      );
      await text.fill(`${originalText}\nE2E customised footer.`);
      await page.getByRole('button', { name: 'Save the template' }).click();
      await expect(page.getByText('The template has been saved.')).toBeVisible();
      await expect(page.getByText(/^Customized/).first()).toBeVisible();
      await expect(page.getByText(/line \d+, column \d+:/)).toHaveCount(0);
      await checkA11y(page);

      // Reset: the default template comes back.
      await page.getByRole('button', { name: 'Restore the default template' }).click();
      const dialog = page.getByRole('dialog', { name: 'Restore the default template?' });
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: 'Restore the default template' }).click();
      await expect(dialog).toBeHidden();
      await expect(page.getByText('Default', { exact: true })).toBeVisible();
      await expect(subject).toHaveValue(originalSubject);
      await expect(html).toHaveValue(originalHtml);
      await expect(text).toHaveValue(originalText);
      await expect(page.getByRole('button', { name: 'Restore the default template' })).toHaveCount(0);
    } finally {
      await deleteTenant(tenant);
    }
  });

  test('email template: the preview renders without CSP violation', async ({ page, guards }) => {
    // The rendered emails carry inline style attributes (the default templates and the mail
    // layout use them for the mail clients); for the preview only, the server removes them and
    // replaces the images by their alt text (sanitize.ForPreview), so the strict admin CSP
    // reports nothing and the CSP guard of the fixture stays silent.
    const tenant = await createTenant('preview');
    try {
      await page.goto(tenantUrl(tenant.id, 'templates/verification-code/en'));
      await expectHeading(page, 'Verification code (English)');
      const subject = page.getByRole('textbox', { name: /^Subject/ });
      await subject.fill(`${await subject.inputValue()} (e2e)`);
      await page
        .getByRole('textbox', { name: /^HTML body/ })
        .fill(
          '<p>Your code for {{tenant_name}}: <strong>{{code}}</strong></p>\n<p>E2E customised footer.</p>',
        );
      await page.getByRole('button', { name: 'Preview', exact: true }).click();

      // The preview renders the unsaved text with sample data.
      const preview = page.getByRole('region', { name: 'Preview' });
      await expect(preview.getByText(/^Subject: .+ \(e2e\)$/)).toBeVisible();
      const htmlVersion = preview.getByRole('region', { name: 'HTML version' });
      await expect(htmlVersion.getByText('123456')).toBeVisible();
      await expect(htmlVersion.getByText('E2E customised footer.')).toBeVisible();
      await checkA11y(page);

      // The default transfer notification has a cid: QR code image: the preview shows its alt
      // text instead, without any image request blocked by the CSP.
      await page.goto(tenantUrl(tenant.id, 'templates/transfer-notification/en'));
      await expectHeading(page, 'Transfer notification (English)');
      await page.getByRole('button', { name: 'Preview', exact: true }).click();
      const qrVersion = page
        .getByRole('region', { name: 'Preview' })
        .getByRole('region', { name: 'HTML version' });
      await expect(qrVersion.getByText('[QR code of the download link]')).toBeVisible();
      await expect(qrVersion.locator('img')).toHaveCount(0);
      expect(guards.problems()).toEqual([]);
    } finally {
      await deleteTenant(tenant);
    }
  });

  test('legal text: Markdown with a link, preview, published on the public page', async ({ page, state }) => {
    const a = state.tenants.a;
    const api = superAdminApi();
    const docPath = `/admin/tenants/${a.id}/legal/legal-notice/en`;
    const original = await api.ok<{ markdown: string }>('GET', docPath);
    const id = uniq();
    const heading = `E2E legal notice ${id}`;
    const href = `https://www.example.org/legal-${id}`;
    try {
      await page.goto(tenantUrl(a.id, 'legal'));
      await expectHeading(page, 'Legal information');
      await checkA11y(page);
      await page.getByRole('link', { name: 'Edit: Legal notice (English)' }).click();
      await expectHeading(page, 'Legal notice (English)');

      await page
        .getByRole('textbox', { name: /^Text \(Markdown\)/ })
        .fill(`# ${heading}\n\nPublisher: [Example publisher](${href}).\n\n- first item\n- second item\n`);
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The document has been saved.')).toBeVisible();

      // The preview shows the saved, sanitized rendering (links inert).
      const preview = page.getByRole('region', { name: 'Preview' });
      await expect(preview.getByRole('heading', { name: heading })).toBeVisible();
      await expect(preview.getByText('Example publisher')).toBeVisible();
      await expect(preview.getByRole('listitem')).toHaveCount(2);
      await checkA11y(page);

      // Published on the public legal page of entity A.
      await page.goto(`${a.origin}/legal/legal-notice`);
      await expect(page.getByRole('heading', { name: heading })).toBeVisible();
      const link = page.getByRole('link', { name: 'Example publisher' });
      await expect(link).toHaveAttribute('href', href);
      await checkA11y(page);
    } finally {
      await api.ok('PUT', docPath, { markdown: original.markdown });
    }
  });

  test.describe('admin accounts', () => {
    test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

    test('creates a delegated admin whose activation link is shown once', async ({ page, newContext }) => {
      const tenant = await createTenant('accounts');
      const username = `e2e-del-${uniq()}`;
      try {
        await page.goto(`${ORIGINS.admin}/admin/admins`);
        await expectHeading(page, 'Administrators');
        await checkA11y(page);
        await page.getByRole('link', { name: 'Create an administrator' }).click();
        await expectHeading(page, 'Create a delegated administrator');
        await checkA11y(page);

        await page.getByRole('textbox', { name: /^Username/ }).fill(username);
        await page.getByRole('textbox', { name: /^Email address/ }).fill(`${username}@example.com`);
        await page.getByRole('checkbox', { name: tenant.name }).check();
        // No second factor, to keep the activation short.
        await page.getByRole('checkbox', { name: /^Require two-factor authentication/ }).uncheck();
        await page.getByRole('button', { name: 'Create the administrator' }).click();

        await expect(page.getByText(`The administrator ${username} has been created.`)).toBeVisible();
        const panel = page.getByRole('region', { name: 'Activation link' });
        await expect(
          panel.getByText('This link is shown only once and is not sent by any email. Copy it now.'),
        ).toBeVisible();
        const field = panel.getByRole('textbox', { name: /^Activation link/ });
        const url = await field.inputValue();
        expect(url).toMatch(new RegExp(`^${ORIGINS.admin}/admin/activate#.+`));
        await checkA11y(page);

        await panel.getByRole('button', { name: 'Copy the link' }).click();
        await expect(page.getByText('Copied to the clipboard')).toBeAttached();
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(url);
        await panel.getByRole('button', { name: 'I have handed over the link' }).click();
        await expect(panel).toBeHidden();
        // Never shown again: the list has the account pending activation, without any link.
        await page.goto(`${ORIGINS.admin}/admin/admins`);
        const row = page.getByRole('row').filter({ hasText: username });
        await expect(row.getByText('Pending activation')).toBeVisible();
        await expect(page.getByText(url)).toHaveCount(0);

        // The delegated admin opens the link in their own browser and chooses a password.
        const other = await newContext();
        const delegatePage = await other.newPage();
        await delegatePage.goto(url);
        await expectHeading(delegatePage, 'Activate your account');
        await checkA11y(delegatePage);
        const password = `e2e-activation-${crypto.randomBytes(12).toString('base64url')}`;
        await delegatePage.getByLabel(/^New password/).fill(password);
        await delegatePage.getByLabel(/^Confirm the password/).fill(password);
        await delegatePage.getByRole('button', { name: 'Set the password' }).click();
        await expectHeading(delegatePage, 'Home');
        await expect(delegatePage.getByText(`Signed in as ${username}`)).toBeVisible();
        await expect(delegatePage.getByRole('main').getByText(tenant.name).first()).toBeVisible();
        // The activation token never stays in the address bar.
        expect(delegatePage.url()).not.toContain(new URL(url).hash.slice(1));
      } finally {
        const api = superAdminApi();
        const list = await api.call<{ items?: { id: string; username: string }[] }>(
          'GET',
          '/admin/admins?limit=200',
        );
        const admin = (list.json?.items ?? []).find((x) => x.username === username);
        if (admin) await api.call('DELETE', `/admin/admins/${admin.id}`);
        await deleteTenant(tenant);
      }
    });
  });
});
