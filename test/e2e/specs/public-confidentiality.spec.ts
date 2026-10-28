// Transfer options of V1.1 step 5 (CLAUDE.md sections 8.2, 8.3, 8.4, 10): confidentiality levels
// and recipient domain rules edited by the delegated admin of entity A, a deposit under a
// level (rules enforced in the form, level shown in the notification mail and on the download
// page), a recipient in a denied domain, and the maximum number of downloads.
//
// The tests run in order (serial): the first one saves a level "restricted" and a denied domain
// on entity A through the admin screens, the others rely on them. Both are additive and
// restored from the initial state at the end (the other specs use the seeded levels).
import crypto from 'node:crypto';
import { ORIGINS, STORAGE_DELEGATE } from '../support/env';
import { externalEmail, internalEmail, makeFile, sha256 } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { fillTransfer, identify, mailLink, sendTransfer, download } from '../support/publicflow';
import { delegateApi, loadState } from '../support/state';

interface LevelList {
  items: unknown[];
}
interface RecipientRules {
  allowedDomains: string[];
  deniedDomains: string[];
}

test.describe.configure({ mode: 'serial' });

test.describe('confidentiality levels and recipient rules', () => {
  let tenantId = '';
  let initialLevels: LevelList | undefined;
  let initialRules: RecipientRules | undefined;

  test.beforeAll(async () => {
    // Entity A is the first seeded tenant of the run state.
    tenantId = loadState().tenants.a.id;
    const api = delegateApi();
    initialLevels = await api.ok<LevelList>('GET', `/admin/tenants/${tenantId}/confidentiality-levels`);
    initialRules = await api.ok<RecipientRules>('GET', `/admin/tenants/${tenantId}/recipient-rules`);
  });

  test.afterAll(async () => {
    const api = delegateApi();
    if (initialLevels) {
      await api.call('PUT', `/admin/tenants/${tenantId}/confidentiality-levels`, initialLevels);
    }
    if (initialRules) {
      await api.call('PUT', `/admin/tenants/${tenantId}/recipient-rules`, {
        allowedDomains: initialRules.allowedDomains,
        deniedDomains: initialRules.deniedDomains,
      });
    }
  });

  test.describe('admin screens', () => {
    test.use({ storageState: STORAGE_DELEGATE });

    test('the admin adds a level and denies a domain; both persist', async ({ page }) => {
      const base = `${ORIGINS.admin}/admin/tenants/${tenantId}`;
      await page.goto(`${base}/general`);
      await page
        .getByRole('navigation', { name: /^Configuration of the entity/ })
        .getByRole('link', { name: 'Confidentiality levels' })
        .click();
      await expect(page.getByRole('heading', { name: 'Confidentiality levels', level: 1 })).toBeVisible();
      await expect(page.getByRole('group', { name: /^Level 1:/ })).toBeVisible();
      await checkA11y(page);

      await page.getByRole('button', { name: 'Add a level' }).click();
      const level = page.getByRole('group', { name: /^Level 4:/ });
      await expect(level).toBeVisible();
      await level.getByRole('textbox', { name: /^Key/ }).fill('restricted');
      await level.getByRole('textbox', { name: /^Label \(FR\)/ }).fill('Restreint');
      await level.getByRole('textbox', { name: /^Label \(EN\)/ }).fill('Restricted');
      await level.getByRole('checkbox', { name: '1 day', exact: true }).uncheck();
      await level.getByRole('checkbox', { name: '30 days' }).uncheck();
      await level.getByRole('checkbox', { name: 'Password required' }).check();
      await level.getByRole('spinbutton', { name: /^Maximum number of downloads \(cap\)/ }).fill('2');
      await expect(page.getByRole('group', { name: 'Level 4: Restricted' })).toBeVisible();
      await checkA11y(page);
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText(/saved/i).first()).toBeVisible();

      await page.reload();
      await expect(page.getByRole('heading', { name: 'Confidentiality levels', level: 1 })).toBeVisible();
      const reloaded = page.getByRole('group', { name: 'Level 4: Restricted' });
      await expect(reloaded.getByRole('textbox', { name: /^Key/ })).toHaveValue('restricted');
      await expect(reloaded.getByRole('textbox', { name: /^Label \(FR\)/ })).toHaveValue('Restreint');
      await expect(reloaded.getByRole('checkbox', { name: '1 day', exact: true })).not.toBeChecked();
      await expect(reloaded.getByRole('checkbox', { name: '7 days' })).toBeChecked();
      await expect(reloaded.getByRole('checkbox', { name: '30 days' })).not.toBeChecked();
      await expect(reloaded.getByRole('checkbox', { name: 'Password required' })).toBeChecked();
      await expect(
        reloaded.getByRole('spinbutton', { name: /^Maximum number of downloads \(cap\)/ }),
      ).toHaveValue('2');

      // Recipient domain rules: mixed case and trailing dot are normalised by the save.
      await page
        .getByRole('navigation', { name: /^Configuration of the entity/ })
        .getByRole('link', { name: 'Recipient domains' })
        .click();
      await expect(page.getByRole('heading', { name: 'Recipient domains', level: 1 })).toBeVisible();
      await checkA11y(page);
      const denied = page.getByRole('textbox', { name: /^Denied domains/ });
      // A non-canonical entry is refused with a one-click fix to the normalised form.
      await denied.fill('Denied.Example.COM.');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await page.getByRole('button', { name: 'Replace line 1 with denied.example.com' }).click();
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByText('Recipient rules saved.')).toBeVisible();
      await expect(denied).toHaveValue('denied.example.com');

      await page.reload();
      await expect(page.getByRole('heading', { name: 'Recipient domains', level: 1 })).toBeVisible();
      await expect(page.getByRole('textbox', { name: /^Denied domains/ })).toHaveValue('denied.example.com');
    });
  });

  test('a deposit under the level "restricted" follows its rules', async ({ page, state, newContext }) => {
    const tenant = state.tenants.a;
    const sender = internalEmail('lvl-sender');
    const recipient = internalEmail('lvl-recipient');
    const password = 'correct horse battery staple';
    const file = makeFile('restricted.bin', 8 * 1024);

    await identify(page, tenant.origin, sender);
    await page.getByRole('radio', { name: 'Restricted' }).check();

    // Only 7 days is offered; the password is required and the cap bounds the downloads.
    await expect(page.getByRole('radio', { name: /^\d+ days?$/ })).toHaveCount(1);
    await expect(page.getByRole('radio', { name: '7 days' })).toBeChecked();
    await expect(page.locator('#tt-deposit-password')).toHaveJSProperty('required', true);
    await checkA11y(page);

    await fillTransfer(page, { recipients: [recipient], files: [file] });
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByText('The chosen confidentiality level requires a password.')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Transfer sent' })).toHaveCount(0);

    await page.locator('#tt-deposit-max-downloads').fill('3');
    await page.locator('#tt-deposit-password').fill(password);
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(
      page.getByText('The chosen confidentiality level allows at most 2 downloads.'),
    ).toBeVisible();

    await page.locator('#tt-deposit-max-downloads').fill('2');
    await sendTransfer(page);

    // The notification names the level.
    const mail = await waitForMail(recipient, { subject: /sent you files via/ });
    expect(mail.Text).toContain('Confidentiality level: Restricted');
    expect(mail.Text).not.toContain(password);

    // The download page shows the level and the downloads left (after the password).
    const rpage = await (await newContext()).newPage();
    await rpage.goto(mailLink(mail, '/d/', tenant.origin));
    await expect(rpage.getByRole('heading', { name: 'Password required', level: 1 })).toBeVisible();
    // The level is not disclosed while the page is locked.
    await expect(rpage.getByText('Restricted', { exact: true })).toHaveCount(0);
    await rpage.getByLabel(/^Password/).fill(password);
    await rpage.getByRole('button', { name: 'Unlock' }).click();
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(rpage.getByText('Restricted', { exact: true })).toBeVisible();
    await expect(rpage.getByText('Downloads left')).toBeVisible();
    await expect(rpage.locator('dd', { hasText: /^2$/ })).toBeVisible();
    await checkA11y(rpage);
    const got = await download(rpage, () =>
      rpage.getByRole('link', { name: `Download ${file.name}` }).click(),
    );
    expect(sha256(got.data)).toBe(file.sha256);
    await expectCleanStorage(page);
  });

  test('a recipient in a denied domain is refused next to the recipients field', async ({
    page,
    state,
    guards,
  }) => {
    guards.allowHttpError(403, /\/api\/v1\/transfers$/);
    const tenant = state.tenants.a;
    await identify(page, tenant.origin, internalEmail('deny-sender'));
    const denied = `someone-${crypto.randomBytes(3).toString('hex')}@denied.example.com`;
    await fillTransfer(page, { recipients: [denied], files: [makeFile('denied.bin', 1024)] });
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(
      page.getByText(`${denied}: This service does not allow sending to the domain of this address.`),
    ).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Transfer sent' })).toHaveCount(0);
    await checkA11y(page);
    await expectCleanStorage(page);
  });

  test('a maximum of one download refuses the next start and shows the outcome', async ({
    page,
    state,
    guards,
    newContext,
  }) => {
    guards.allowHttpError(410, /\/api\/v1\/downloads\//);
    const tenant = state.tenants.a;
    const sender = internalEmail('max-sender');
    const recipient = externalEmail('max-recipient');
    const first = makeFile('first.bin', 4 * 1024);
    const second = makeFile('second.bin', 4 * 1024);

    await identify(page, tenant.origin, sender);
    await fillTransfer(page, { recipients: [recipient], files: [first, second] });
    await page.locator('#tt-deposit-max-downloads').fill('1');
    await sendTransfer(page);
    const mail = await waitForMail(recipient, { subject: /sent you files via/ });
    const link = mailLink(mail, '/d/', tenant.origin);

    const rpage = await (await newContext()).newPage();
    await rpage.goto(link);
    await expect(rpage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    await expect(rpage.locator('dd', { hasText: /^1$/ })).toBeVisible();
    const hrefOf = async (name: string): Promise<string> =>
      new URL(
        (await rpage.getByRole('link', { name: `Download ${name}` }).getAttribute('href')) ?? '',
        rpage.url(),
      ).toString();
    const secondHref = await hrefOf(second.name);
    const zipHref = new URL(
      (await rpage.getByRole('link', { name: /^Download all files/ }).getAttribute('href')) ?? '',
      rpage.url(),
    ).toString();

    const got = await download(rpage, () =>
      rpage.getByRole('link', { name: `Download ${first.name}` }).click(),
    );
    expect(sha256(got.data)).toBe(first.sha256);

    // Another client starts a new download: refused with 410 max-downloads-reached.
    const opage = await (await newContext()).newPage();
    await opage.goto(link);
    await expect(
      opage.getByRole('heading', { name: 'Maximum number of downloads reached', level: 1 }),
    ).toBeVisible();
    for (const href of [secondHref, zipHref]) {
      const res = await opage.evaluate(async (url) => {
        const r = await fetch(url);
        return { status: r.status, body: await r.text() };
      }, href);
      expect(res.status).toBe(410);
      expect(res.body).toContain('max-downloads-reached');
    }

    // A reload in the first browser shows the same outcome.
    await rpage.reload();
    await expect(
      rpage.getByRole('heading', { name: 'Maximum number of downloads reached', level: 1 }),
    ).toBeVisible();
    await checkA11y(rpage);
    await expectCleanStorage(rpage);
  });
});
