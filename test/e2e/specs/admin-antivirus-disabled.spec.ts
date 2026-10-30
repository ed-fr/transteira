// Disabling the antivirus of an entity (CLAUDE.md section 11.1, V1.1 step 12 bis a): the super
// admin switches the antivirus analysis of entity B off in the admin interface (with a
// confirmation), a file deposited afterwards is delivered unscanned and the sender's recap and the
// download page say "antivirus disabled", then the analysis is switched on again. Entity B is
// mutated and restored in a finally block (entity A is used by parallel specs).
import { internalEmail, makeFile } from '../support/data';
import { ORIGINS, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { deposit, identify, mailLink } from '../support/publicflow';
import { superAdminApi } from '../support/state';

test.describe('admin: antivirus of an entity', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('disabled antivirus: file delivered unscanned and flagged, then re-enabled', async ({
    page,
    state,
    newContext,
  }) => {
    const tenant = state.tenants.b;
    const sender = internalEmail('av-off-sender');
    const recipient = internalEmail('av-off-recipient');
    const file = makeFile('unscanned-report.bin', 16 * 1024);
    const api = superAdminApi();
    try {
      await page.goto(`${ORIGINS.admin}/admin/tenants/${tenant.id}/general`);
      const section = page.getByTestId('antivirus-section');
      await expect(section.getByRole('heading', { name: 'Antivirus analysis', level: 2 })).toBeVisible();
      await checkA11y(page);

      // Disabling asks for a confirmation that explains the consequences.
      await section.getByRole('button', { name: 'Disable the antivirus analysis' }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText('Files already waiting for the analysis keep waiting');
      await dialog.getByRole('button', { name: 'Disable the antivirus', exact: true }).click();
      await expect(section.getByText('Antivirus analysis disabled.')).toBeVisible();
      await expect(section.getByRole('button', { name: 'Enable the antivirus analysis' })).toBeVisible();

      // A deposit on entity B is delivered unscanned and flagged.
      const senderPage = await (await newContext()).newPage();
      await identify(senderPage, tenant.origin, sender);
      await deposit(senderPage, { recipients: [recipient], files: [file] });
      const recap = senderPage.getByRole('list', { name: 'Files of the transfer' });
      await expect(recap.getByRole('listitem').filter({ hasText: file.name })).toContainText(
        'not analysed: antivirus disabled',
      );

      const notification = await waitForMail(recipient, { subject: /sent you files via/ });
      const rpage = await (await newContext()).newPage();
      await rpage.goto(mailLink(notification, '/d/', tenant.origin));
      const table = rpage.getByRole('table', { name: 'Files of this transfer' });
      await expect(table.getByRole('row', { name: /unscanned-report/ })).toContainText(
        'antivirus analysis is disabled',
      );
      await checkA11y(rpage);

      // Enabling again needs no confirmation.
      await section.getByRole('button', { name: 'Enable the antivirus analysis' }).click();
      await expect(section.getByText('Antivirus analysis enabled.')).toBeVisible();
      await expect(section.getByRole('button', { name: 'Disable the antivirus analysis' })).toBeVisible();
    } finally {
      await api.call('PATCH', `/admin/tenants/${tenant.id}`, { antivirusEnabled: true });
    }
  });
});
