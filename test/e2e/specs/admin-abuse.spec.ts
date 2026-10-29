// Abuse detection and reports (CLAUDE.md sections 6.4, 10, 15; V1.1 step 8, web interface):
//   - a recipient reports an abuse from the download page (dialog, category, message), even
//     before unlocking a password-protected transfer;
//   - the delegated admin sees the report, reads its message as text, closes it with a note and
//     reopens it;
//   - the admin edits the abuse thresholds (null disables a rule, every member is sent);
//   - the network screen offers the "deposit from outside" option, off by default.
// The screenshots used by the help are captured by screenshots.spec.ts (download-report,
// admin-tenant-abuse, admin-abuse-reports).
import crypto from 'node:crypto';
import { request } from '../support/api';
import { internalEmail, textFile } from '../support/data';
import { recipientPath, tokenDeposit } from '../support/deposit';
import { HOSTS, ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { superAdminApi } from '../support/state';

const GiB = 2 ** 30;
const uniq = (): string => crypto.randomBytes(4).toString('hex');

/** Creates a throwaway tenant through the admin API. */
async function createTenant(label: string): Promise<{ id: string; name: string }> {
  const id = uniq();
  const name = `E2E ${label} ${id}`;
  const t = await superAdminApi().ok<{ id: string }>(
    'POST',
    '/admin/tenants',
    {
      name,
      fqdn: `t-${id}.localhost`,
      defaultLanguage: 'en',
      storageQuotaBytes: GiB,
      maxTransferBytes: GiB,
      maxTransferCeiling: GiB,
    },
    [201],
  );
  return { id: t.id, name };
}

/** Deletes a throwaway tenant (best effort). */
async function deleteTenant(tenant: { id: string; name: string }): Promise<void> {
  await superAdminApi().call(
    'DELETE',
    `/admin/tenants/${tenant.id}?confirm=${encodeURIComponent(tenant.name)}`,
  );
}

/** Deposits a transfer on entity A and returns the path of the recipient link. */
async function transferLink(
  apiToken: string,
  label: string,
  extra: { password?: string } = {},
): Promise<string> {
  const recipient = internalEmail(`abuse-${label}-to`);
  const deposit = await tokenDeposit(apiToken, internalEmail(`abuse-${label}-from`), {
    recipients: [recipient],
    files: [textFile('invoice.txt', 'an invoice\n')],
    ...extra,
  });
  expect(deposit.status).toBe('available');
  return recipientPath(deposit, recipient);
}

/** Files an abuse report straight on the API (same-origin headers, like the browser). */
async function reportOnApi(serverPort: number, linkPath: string, message: string): Promise<void> {
  const token = /\/d\/([^/?#]+)/.exec(linkPath)?.[1];
  expect(token).toBeTruthy();
  const res = await request(serverPort, 'POST', `/api/v1/downloads/${token}/abuse-reports`, {
    host: HOSTS.a,
    body: { category: 'phishing', message },
    headers: { Origin: ORIGINS.a, 'Sec-Fetch-Site': 'same-origin' },
  });
  expect(res.status).toBe(202);
}

test.describe('public: report an abuse', () => {
  test('from the download page, with a category and a message', async ({ page, state }) => {
    const link = await transferLink(state.apiTokenA, 'report');
    await page.goto(`${ORIGINS.a}${link}`);
    await expect(page.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await page.getByRole('button', { name: 'Report an abuse', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Report an abuse' });
    await expect(dialog).toBeVisible();
    await checkA11y(page);

    // A category is required.
    await dialog.getByRole('button', { name: 'Send the report' }).click();
    await expect(dialog.getByText('Choose a reason.')).toBeVisible();

    await dialog.getByRole('radio', { name: /^Phishing/ }).check();
    await dialog.getByLabel(/^Message/).fill('The archive contains a fake login page.');
    await dialog.getByRole('button', { name: 'Send the report' }).click();
    await expect(dialog.getByText('Report sent to the administrators')).toBeVisible();
    await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
    await expect(dialog).toBeHidden();
  });

  test('is available on a password-protected transfer without unlocking', async ({ page, state }) => {
    const link = await transferLink(state.apiTokenA, 'locked', { password: 'correct horse battery staple' });
    await page.goto(`${ORIGINS.a}${link}`);
    await expect(page.getByRole('heading', { name: 'Password required', level: 1 })).toBeVisible();
    await page.getByRole('button', { name: 'Report an abuse', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Report an abuse' });
    await dialog.getByRole('radio', { name: /^Spam/ }).check();
    await dialog.getByRole('button', { name: 'Send the report' }).click();
    await expect(dialog.getByText('Report sent to the administrators')).toBeVisible();
  });
});

test.describe('admin: abuse reports', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('the delegated admin reads a report as text, closes it with a note and reopens it', async ({
    page,
    state,
  }) => {
    const message = `<b>bold</b> fake invoice ${uniq()}`;
    const link = await transferLink(state.apiTokenA, 'admin');
    await reportOnApi(state.serverPort, link, message);

    await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/abuse-reports?status=open`);
    await expect(page.getByRole('heading', { name: 'Abuse reports', level: 1 })).toBeVisible();
    await expect(page).toHaveURL(/status=open/);
    await checkA11y(page);

    // Find our report among the open ones (other tests file reports on the same entity).
    const dialog = page.getByRole('dialog', { name: 'Abuse report' });
    const buttons = page.getByRole('button', { name: /^Details of the/ });
    let found = false;
    for (let i = 0; i < (await buttons.count()); i++) {
      await buttons.nth(i).click();
      if (await dialog.getByText(message, { exact: true }).isVisible()) {
        found = true;
        break;
      }
      await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
    }
    expect(found).toBe(true);

    // The message is text: the tag is shown as typed, never interpreted.
    await expect(dialog.locator('b')).toHaveCount(0);
    await expect(dialog.getByText('Through the link of recipient no. 1, not verified')).toBeVisible();
    await checkA11y(page);

    await dialog.getByLabel(/^Closing note/).fill('Transfer deleted, sender blocklisted.');
    await dialog.getByRole('button', { name: 'Close the report' }).click();
    await expect(dialog).toBeHidden();
    // The message is no longer shown (the closed dialog stays in the DOM, hidden, so its
    // text is checked for visibility rather than counted); the closed filter below finds it.
    await expect(page.getByText(message, { exact: true })).toBeHidden();

    // Closed reports: reopen it.
    await page.goto(`${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/abuse-reports?status=closed`);
    const closed = page.getByRole('button', { name: /^Details of the/ });
    await expect(closed.first()).toBeVisible();
    let reopened = false;
    for (let i = 0; i < (await closed.count()); i++) {
      await closed.nth(i).click();
      if (await dialog.getByText('Transfer deleted, sender blocklisted.').first().isVisible()) {
        await dialog.getByRole('button', { name: 'Reopen the report' }).click();
        await expect(dialog).toBeHidden();
        reopened = true;
        break;
      }
      await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
    }
    expect(reopened).toBe(true);
  });
});

test.describe('admin: abuse thresholds and remote deposit', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('thresholds: validation, disabled rules sent as null, saved values shown again', async ({ page }) => {
    const tenant = await createTenant('abuse');
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenant.id}/abuse`);
      await expect(page.getByRole('heading', { name: 'Abuse detection', level: 1 })).toBeVisible();
      await checkA11y(page);

      const transfers = 'Maximum transfers per sender per day';
      await page.getByLabel(`Enable the rule: ${transfers}`).check();
      await page.getByLabel(new RegExp(`^${transfers}`)).fill('30');
      await page.getByLabel('Enable the rule: Maximum recipients per transfer').uncheck();
      await page.getByLabel('Enable the rule: Unusual volume factor').check();
      await page.getByLabel(/^Unusual volume factor/).fill('1.2');
      await page.getByLabel(/^Time zone/).fill('Mars/Olympus');

      // Invalid values: summary, errors next to the fields, nothing sent.
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('The form contains errors')).toBeVisible();
      await expect(page.getByText(/This time zone is unknown/).first()).toBeVisible();
      await expect(page.getByLabel(/^Unusual volume factor/)).toHaveAttribute('aria-invalid', 'true');

      await page.getByLabel(/^Unusual volume factor/).fill('2,5');
      await page.getByLabel(/^Time zone/).fill('Europe/Paris');
      await page.getByLabel('Block instead of only alerting').check();
      await page.getByLabel('Alert outside office hours').check();
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('Abuse detection settings saved.')).toBeVisible();

      const saved = await superAdminApi().ok<Record<string, unknown>>(
        'GET',
        `/admin/tenants/${tenant.id}/abuse-thresholds`,
      );
      expect(saved).toMatchObject({
        maxDailyTransfersPerSender: 30,
        maxRecipientsPerTransfer: null,
        unusualVolumeFactor: 2.5,
        timeZone: 'Europe/Paris',
        blockOnExceed: true,
      });
      expect(saved['officeHours']).toMatchObject({ start: '08:00', end: '19:00', weekdays: [1, 2, 3, 4, 5] });

      await page.reload();
      await expect(page.getByLabel(new RegExp(`^${transfers}`))).toHaveValue('30');
      await expect(page.getByLabel('Enable the rule: Maximum recipients per transfer')).not.toBeChecked();
      await expect(page.getByLabel('Block instead of only alerting')).toBeChecked();
    } finally {
      await deleteTenant(tenant);
    }
  });

  test('network: the deposit from outside option is off by default and can be enabled', async ({ page }) => {
    const tenant = await createTenant('remote');
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenant.id}/network`);
      await expect(page.getByRole('heading', { name: 'Network', level: 1 })).toBeVisible();
      const section = page.getByRole('region', { name: 'Deposit from outside' });
      const box = section.getByLabel('Allow deposits from outside for already verified internal users');
      await expect(box).not.toBeChecked();
      await expect(section.getByText(/a verification code is asked at each deposit/)).toBeVisible();
      await checkA11y(page);

      await box.check();
      await section.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('Deposit from outside option saved.')).toBeVisible();
      const got = await superAdminApi().ok<{ allowRemoteInternalDeposit?: boolean }>(
        'GET',
        `/admin/tenants/${tenant.id}`,
      );
      expect(got.allowRemoteInternalDeposit).toBe(true);
    } finally {
      await deleteTenant(tenant);
    }
  });
});
