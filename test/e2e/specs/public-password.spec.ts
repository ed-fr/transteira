// Public scenario 2 (CLAUDE.md section 10): a password-protected transfer. Three wrong passwords
// lock it for 15 minutes, shown as a countdown with the field disabled; the right password unlocks
// another transfer of the same sender, whose file then downloads intact. The lock covers the
// transfer and the client IP, so the successful unlock runs on a second transfer and in a second
// browser context (another IP).
import { internalEmail, makeFile, sha256 } from '../support/data';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { deposit, download, identify, mailLink } from '../support/publicflow';
import { waitForSecurityEvents } from '../support/securitylog';

const UNLOCK = /\/api\/v1\/downloads\/[^/]+\/unlock$/;

test.describe('public: transfer password', () => {
  test('three wrong passwords lock the transfer; the right one unlocks and downloads', async ({
    page,
    state,
    guards,
    clientIp,
    newContext,
  }) => {
    // Wrong passwords are answered 401, then 429 once locked: expected here.
    guards.allowHttpError(401, UNLOCK);
    guards.allowHttpError(429, UNLOCK);
    const tenant = state.tenants.a;
    const sender = internalEmail('pw-sender');
    const lockedRecipient = internalEmail('pw-locked');
    const okRecipient = internalEmail('pw-ok');
    const password = 'correct horse battery staple';
    const lockedFile = makeFile('locked.bin', 8 * 1024);
    const okFile = makeFile('contract.pdf', 24 * 1024, { mimeType: 'application/pdf' });

    // Two protected transfers of the same session.
    await identify(page, tenant.origin, sender);
    await deposit(page, { recipients: [lockedRecipient], password, files: [lockedFile] });
    await expect(page.getByText(/remember to send the password to the recipients/)).toBeVisible();
    await page.getByRole('button', { name: 'New transfer' }).click();
    await deposit(page, { recipients: [okRecipient], password, files: [okFile] });

    // The notification never holds the password, only the mention of another channel.
    const lockedMail = await waitForMail(lockedRecipient, { subject: /sent you files via/ });
    expect(lockedMail.Text).not.toContain(password);
    expect(lockedMail.HTML).not.toContain(password);
    const okMail = await waitForMail(okRecipient, { subject: /sent you files via/ });

    // --- Lockout, as the recipient of the first transfer (client IP of this test). ---
    const lpage = await (await newContext({ clientIp })).newPage();
    await lpage.goto(mailLink(lockedMail, '/d/', tenant.origin));
    await expect(lpage.getByRole('heading', { name: 'Password required', level: 1 })).toBeVisible();
    // Neither the files nor their names are shown before the unlock.
    await expect(lpage.getByText(lockedFile.name)).toHaveCount(0);
    await checkA11y(lpage);

    const field = lpage.getByLabel(/^Password/);
    const submit = lpage.getByRole('button', { name: 'Unlock' });
    await field.fill('wrong-1');
    await submit.click();
    await expect(lpage.getByText('The password is not correct. 2 attempts remaining.')).toBeVisible();
    await field.fill('wrong-2');
    await submit.click();
    await expect(lpage.getByText('The password is not correct. 1 attempt remaining.')).toBeVisible();
    await field.fill('wrong-3');
    await submit.click();

    const alert = lpage.getByRole('alert').filter({ hasText: 'Too many wrong passwords' });
    await expect(alert).toContainText(/Try again in \d+ seconds\./);
    await expect(field).toBeDisabled();
    await expect(submit).toBeDisabled();
    // The countdown starts at 15 minutes and goes down.
    const secondsLeft = async () => Number(/Try again in (\d+) seconds/.exec(await alert.innerText())?.[1]);
    const first = await secondsLeft();
    expect(first).toBeGreaterThan(14 * 60);
    expect(first).toBeLessThanOrEqual(15 * 60);
    await expect.poll(secondsLeft, { timeout: 5_000 }).toBeLessThan(first);
    await checkA11y(lpage);

    // A reload keeps the transfer locked: the right password is refused while the lock lasts.
    await lpage.reload();
    await expect(lpage.getByRole('heading', { name: 'Password required', level: 1 })).toBeVisible();
    await lpage.getByLabel(/^Password/).fill(password);
    await lpage.getByRole('button', { name: 'Unlock' }).click();
    await expect(lpage.getByRole('alert').filter({ hasText: 'Too many wrong passwords' })).toBeVisible();
    await expect(lpage.getByText(lockedFile.name)).toHaveCount(0);

    // fail2ban / CrowdSec see the wrong passwords and the lock with the real client IP.
    await waitForSecurityEvents(
      { ip: clientIp, event: 'transfer_password_invalid', tenant: tenant.fqdn },
      { count: 2 },
    );
    await waitForSecurityEvents({
      ip: clientIp,
      event: 'rate_limited',
      tenant: tenant.fqdn,
      fields: { scope: 'transfer_password' },
    });

    // --- Right password on the other transfer, from another client. ---
    const opage = await (await newContext()).newPage();
    await opage.goto(mailLink(okMail, '/d/', tenant.origin));
    await expect(opage.getByRole('heading', { name: 'Password required', level: 1 })).toBeVisible();
    await opage.getByLabel(/^Password/).fill('almost right');
    await opage.getByRole('button', { name: 'Unlock' }).click();
    await expect(opage.getByText('The password is not correct. 2 attempts remaining.')).toBeVisible();
    await opage.getByLabel(/^Password/).fill(password);
    await opage.getByRole('button', { name: 'Unlock' }).click();
    await expect(opage.getByRole('heading', { name: 'Download files', level: 1 })).toBeVisible();
    const row = opage
      .getByRole('table', { name: 'Files of this transfer' })
      .getByRole('row', { name: /contract/ });
    await expect(row.getByText(okFile.sha256)).toBeVisible();
    await checkA11y(opage);

    const got = await download(opage, () =>
      opage.getByRole('link', { name: `Download ${okFile.name}` }).click(),
    );
    expect(got.name).toBe(okFile.name);
    expect(sha256(got.data)).toBe(okFile.sha256);
    await expectCleanStorage(opage);
    await expectCleanStorage(lpage);
  });
});
