// Redesign of the administration (CLAUDE.md section 13.2, step 3 of V2.3): landmarks and
// aria-current of the sidebar, its collapsible groups with the keyboard, the narrow-screen menu,
// reflow without horizontal page scroll at 320 and 390 px, the pinned entity block of a
// single-entity admin, the auditor's Consultation group, 44 px click targets, visible focus in
// the dark sidebar, forced colors, axe in both themes, and no browser storage but the language.
import type { Locator, Page } from '@playwright/test';
import { internalEmail, textFile } from '../support/data';
import { msg } from '../support/i18n';
import { tokenDeposit } from '../support/deposit';
import { openAsAuditor } from '../support/auditor';
import { HOSTS, ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, checkTargetSize, expect, expectCleanStorage, test } from '../support/fixtures';
import { superAdminApi, type E2EState } from '../support/state';

const ADMIN = `${ORIGINS.admin}/admin`;

/** The nested navigation of an entity in the sidebar. */
function tenantNav(page: Page, state: E2EState): Locator {
  return page.getByRole('navigation', { name: `Configuration of the entity ${state.tenants.a.name}` });
}

/** The main navigation of the sidebar. */
function mainNav(page: Page): Locator {
  return page.getByRole('navigation', { name: 'Main navigation', exact: true });
}

/** Waits until a screen has settled: its heading is there and the data requests are over. */
async function settled(page: Page, heading: string): Promise<void> {
  await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible();
  await page.waitForLoadState('networkidle');
}

/** Creates one transfer in entity A, so that the transfer list has a row (a wide table). */
async function seedTransferInA(state: E2EState): Promise<string> {
  const result = await tokenDeposit(
    state.apiTokenA,
    internalEmail('redesign-sender'),
    { recipients: [internalEmail('redesign-recipient')], files: [textFile('redesign.txt', 'redesign')] },
    { host: HOSTS.a },
  );
  expect(result.status).toBe('available');
  return result.id;
}

/** The help link of the screen: next to the h1, in the page header, named "Help: <title>". */
async function expectHelpIcon(page: Page, name: string | RegExp): Promise<void> {
  const header = page
    .locator('.tt-page-header__title')
    .filter({ has: page.getByRole('heading', { level: 1 }) });
  await expect(header.getByRole('link', { name })).toHaveCount(1);
  await expect(header.getByRole('link', { name })).toBeVisible();
}

test.describe('administration redesign (super admin)', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('landmarks and aria-current of the sidebar', async ({ page, state }) => {
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    await expect(page.getByRole('banner')).toHaveCount(1);
    await expect(page.getByRole('main')).toHaveCount(1);
    await expect(page.getByRole('contentinfo')).toHaveCount(1);
    // The sidebar is the banner; the main navigation lives inside it.
    await expect(page.getByRole('banner').getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    await expect(page.getByRole('main').getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0);
    await expect(page.getByRole('main').getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
    // The footer is slim: help, language, theme (and the version), no navigation.
    const footer = page.getByRole('contentinfo');
    await expect(footer.getByRole('link', { name: /Help/ })).toBeVisible();
    await expect(footer.getByRole('navigation')).toHaveCount(0);

    const main = mainNav(page);
    await expect(main.getByRole('link', { name: 'Home', exact: true })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(main.getByRole('link', { name: 'Entities', exact: true })).not.toHaveAttribute(
      'aria-current',
    );
    for (const name of ['Entities', 'Administrators', 'System', 'My account']) {
      await expect(main.getByRole('link', { name, exact: true })).toBeVisible();
    }

    await main.getByRole('link', { name: 'Entities', exact: true }).click();
    await settled(page, 'Entities');
    await expect(main.getByRole('link', { name: 'Entities', exact: true })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(main.getByRole('link', { name: 'Home', exact: true })).not.toHaveAttribute('aria-current');

    // On a page of an entity, the entry stays marked and the nested navigation marks the page.
    await page.goto(`${ADMIN}/tenants/${state.tenants.a.id}/branding`);
    await settled(page, 'Branding');
    await expect(main.getByRole('link', { name: 'Entities', exact: true })).toHaveAttribute(
      'aria-current',
      'true',
    );
    const nested = tenantNav(page, state);
    await expect(nested).toBeVisible();
    await expect(nested.getByRole('link', { name: 'Branding', exact: true })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(nested.getByRole('link', { name: 'General', exact: true })).not.toHaveAttribute(
      'aria-current',
    );

    // The system navigation is nested under System, on the system screens only.
    await expect(page.getByRole('navigation', { name: 'System administration' })).toHaveCount(0);
    await page.goto(`${ADMIN}/system/maintenance`);
    await settled(page, 'Maintenance mode');
    const system = page.getByRole('navigation', { name: 'System administration' });
    await expect(system.getByRole('link', { name: 'Maintenance', exact: true })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(main.getByRole('link', { name: 'System', exact: true })).toHaveAttribute(
      'aria-current',
      'true',
    );
  });

  test('the entity block is not pinned on the home of an instance with several entities', async ({
    page,
    state,
  }) => {
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    await expect(tenantNav(page, state)).toHaveCount(0);
  });

  test('sidebar groups open by default, collapse and expand with the keyboard', async ({ page, state }) => {
    await page.goto(`${ADMIN}/tenants/${state.tenants.a.id}/general`);
    await settled(page, 'General');
    const nested = tenantNav(page, state);
    const configuration = nested.getByRole('button', { name: 'Configuration', exact: true });
    const operations = nested.getByRole('button', { name: 'Operations', exact: true });
    const consultation = nested.getByRole('button', { name: 'Consultation', exact: true });
    await expect(consultation).toHaveCount(0);
    await expect(configuration).toHaveAttribute('aria-expanded', 'true');
    await expect(operations).toHaveAttribute('aria-expanded', 'true');
    const transfers = nested.getByRole('link', { name: 'Transfers', exact: true });
    await expect(transfers).toBeVisible();

    // Enter collapses, Space expands again; the controlled list is hidden meanwhile.
    await operations.focus();
    await page.keyboard.press('Enter');
    await expect(operations).toHaveAttribute('aria-expanded', 'false');
    await expect(transfers).toBeHidden();
    await page.keyboard.press('Space');
    await expect(operations).toHaveAttribute('aria-expanded', 'true');
    await expect(transfers).toBeVisible();

    // A collapsed group stays collapsed while navigating elsewhere...
    await page.keyboard.press('Enter');
    await expect(transfers).toBeHidden();
    await nested.getByRole('link', { name: 'Branding', exact: true }).click();
    await settled(page, 'Branding');
    await expect(operations).toHaveAttribute('aria-expanded', 'false');
    await expect(configuration).toHaveAttribute('aria-expanded', 'true');
    await operations.focus();
    await page.keyboard.press('Space');
    await expect(transfers).toBeVisible();

    // ...but the group holding the current page opens again on every navigation.
    await configuration.focus();
    await page.keyboard.press('Enter');
    await expect(configuration).toHaveAttribute('aria-expanded', 'false');
    await transfers.click();
    await settled(page, 'Transfers');
    await expect(operations).toHaveAttribute('aria-expanded', 'true');
    await page.goBack();
    await settled(page, 'Branding');
    await expect(configuration).toHaveAttribute('aria-expanded', 'true');
    await expect(nested.getByRole('link', { name: 'Branding', exact: true })).toHaveAttribute(
      'aria-current',
      'page',
    );
    // The collapsed state is kept in memory only.
    await expectCleanStorage(page);
  });

  test('visible focus ring inside the dark sidebar', async ({ page }) => {
    await page.goto(`${ADMIN}/tenants`);
    await settled(page, 'Entities');
    // Tab from the skip link into the sidebar: the first focused element of the sidebar.
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press('Tab');
      if (await page.evaluate(() => !!document.activeElement?.closest('header.tt-admin-sidebar'))) break;
    }
    const focus = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement;
      const style = getComputedStyle(el);
      const sidebar = el.closest('header.tt-admin-sidebar') as HTMLElement | null;
      const parse = (css: string): number[] => (css.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);
      const luminance = ([r, g, b]: number[]): number => {
        const lin = (v: number): number => {
          const c = (v ?? 0) / 255;
          return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        };
        return 0.2126 * lin(r!) + 0.7152 * lin(g!) + 0.0722 * lin(b!);
      };
      const bg = sidebar ? parse(getComputedStyle(sidebar).backgroundColor) : [0, 0, 0];
      const ring = parse(style.outlineColor);
      const l1 = luminance(ring);
      const l2 = luminance(bg);
      return {
        inSidebar: sidebar !== null,
        focusVisible: el.matches(':focus-visible'),
        outlineStyle: style.outlineStyle,
        outlineWidth: parseFloat(style.outlineWidth),
        contrast: (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05),
      };
    });
    expect(focus.inSidebar).toBe(true);
    expect(focus.focusVisible).toBe(true);
    expect(focus.outlineStyle).not.toBe('none');
    expect(focus.outlineWidth).toBeGreaterThanOrEqual(2);
    expect(focus.contrast).toBeGreaterThanOrEqual(3);
  });

  test('forced colors keep the current page identifiable in the sidebar', async ({ page }) => {
    await page.emulateMedia({ forcedColors: 'active' });
    await page.goto(`${ADMIN}/tenants`);
    await settled(page, 'Entities');
    const main = mainNav(page);
    const look = (link: Locator): Promise<string> =>
      link.evaluate((el) => {
        const s = getComputedStyle(el);
        return [
          s.color,
          s.backgroundColor,
          s.borderLeftWidth,
          s.borderLeftColor,
          s.fontWeight,
          s.textDecorationLine,
        ].join('|');
      });
    const current = await look(main.getByRole('link', { name: 'Entities', exact: true }));
    const other = await look(main.getByRole('link', { name: 'My account', exact: true }));
    expect(current).not.toBe(other);
    await expect(main.getByRole('link', { name: 'Entities', exact: true })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  test('click targets of 44 px on four screens', async ({ page, state }) => {
    await seedTransferInA(state);
    for (const [path, heading] of [
      ['/', 'Home'],
      [`/tenants/${state.tenants.a.id}/general`, 'General'],
      [`/tenants/${state.tenants.a.id}/transfers`, 'Transfers'],
      ['/system', 'System overview'],
    ] as const) {
      await page.goto(`${ADMIN}${path}`);
      await settled(page, heading);
      await checkTargetSize(page);
    }
  });

  test('click targets of 44 px on the setup wizard, a transfer detail and three more screens', async ({
    page,
    state,
  }) => {
    const transferId = await seedTransferInA(state);
    const name = 'Example target size';
    const api = superAdminApi();
    const created = await api.ok<{ id: string }>(
      'POST',
      '/admin/tenants',
      {
        name,
        fqdn: 'target-size.localhost',
        defaultLanguage: 'en',
        setupState: 'setup',
        storageQuotaBytes: 1 << 30,
        maxTransferBytes: 1 << 30,
        maxTransferCeiling: 1 << 30,
      },
      [201],
    );
    try {
      for (const [path, heading] of [
        [`/tenants/${created.id}/setup`, msg('en', 'setup.wizard.title')],
        [`/tenants/${state.tenants.a.id}/transfers/${transferId}`, 'Transfer details'],
        ['/admins/new', 'Create a delegated administrator'],
        [`/admins/${state.delegate.id}`, `Edit the administrator ${state.delegate.username}`],
        ['/system/settings', 'System settings'],
      ] as const) {
        await page.goto(`${ADMIN}${path}`);
        await settled(page, heading);
        await checkTargetSize(page);
      }
    } finally {
      await api.call('DELETE', `/admin/tenants/${created.id}?confirm=${encodeURIComponent(name)}`);
    }
  });

  test('every admin screen with a help topic shows a help link next to its title', async ({
    page,
    state,
  }) => {
    const transferId = await seedTransferInA(state);
    const a = state.tenants.a.id;
    const screens: [string, string, string][] = [
      ['/', 'Home', 'Help: Home'],
      ['/search', 'Search', 'Help: Search'],
      ['/account', 'My account', 'Help: My account'],
      ['/admins', 'Administrators', 'Help: Administrators'],
      ['/admins/new', 'Create a delegated administrator', 'Help: Create a delegated administrator'],
      ['/system', 'System overview', 'Help: System overview'],
      ['/system/maintenance', 'Maintenance mode', 'Help: Maintenance mode'],
      ['/system/settings', 'System settings', 'Help: System settings'],
      ['/system/audit', 'Global audit log', 'Help: Global audit log'],
      ['/tenants', 'Entities', 'Help: Entities'],
      ['/tenants/new', 'Create an entity', 'Help: Create an entity'],
      [`/tenants/${a}/transfers`, 'Transfers', 'Help: Transfers'],
      [`/tenants/${a}/transfers/${transferId}`, 'Transfer details', 'Help: Transfer details'],
      [`/tenants/${a}/general`, 'General', 'Help: General'],
      [`/tenants/${a}/branding`, 'Branding', 'Help: Branding'],
      [`/tenants/${a}/stats`, 'Statistics', 'Help: Statistics'],
    ];
    for (const [path, heading, help] of screens) {
      await page.goto(`${ADMIN}${path}`);
      await settled(page, heading);
      await expectHelpIcon(page, help);
    }
    // Next to the title, not the footer link: the footer keeps its own name.
    await expect(
      page.getByRole('contentinfo').getByRole('link', { name: 'Help', exact: true }),
    ).toBeVisible();
  });

  test('axe, both themes: home and an entity screen', async ({ page, state }) => {
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    await checkA11y(page);
    await page.goto(`${ADMIN}/tenants/${state.tenants.a.id}/general`);
    await settled(page, 'General');
    await checkA11y(page);
  });

  test('no browser storage but the language after using the sidebar and the search', async ({
    page,
    state,
  }) => {
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    const main = mainNav(page);
    await main.getByRole('link', { name: 'Entities', exact: true }).click();
    await settled(page, 'Entities');
    await page.goto(`${ADMIN}/tenants/${state.tenants.a.id}/general`);
    await settled(page, 'General');
    await tenantNav(page, state).getByRole('button', { name: 'Operations', exact: true }).click();
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    const box = page.getByRole('searchbox', { name: 'Search', exact: true });
    await box.fill(internalEmail('redesign-storage'));
    await box.press('Enter');
    await expect(page.getByRole('heading', { name: 'Search', level: 1 })).toBeVisible();
    await expectCleanStorage(page);
    const keys = await page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)]);
    expect(keys.filter((k) => k !== 'tt.lang')).toEqual([]);
  });

  test('no horizontal scroll at 320 and 390 px, and the menu of a narrow screen', async ({ page, state }) => {
    await seedTransferInA(state);
    const screens: [string, string][] = [
      ['/', 'Home'],
      ['/tenants', 'Entities'],
      [`/tenants/${state.tenants.a.id}/transfers`, 'Transfers'],
      [`/tenants/${state.tenants.a.id}/general`, 'General'],
    ];
    for (const width of [320, 390]) {
      await page.setViewportSize({ width, height: 800 });
      for (const [path, heading] of screens) {
        await page.goto(`${ADMIN}${path}`);
        await settled(page, heading);
        const overflow = await page.evaluate(() => ({
          scroll: document.scrollingElement!.scrollWidth,
          client: document.scrollingElement!.clientWidth,
        }));
        expect(overflow.scroll, `${path} at ${width}px`).toBeLessThanOrEqual(overflow.client);
      }
    }

    // The menu button of a narrow screen: closed by default, opens, closes after a navigation.
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    const menu = page.getByRole('button', { name: 'Menu', exact: true });
    await expect(menu).toBeVisible();
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    const main = mainNav(page);
    await expect(main).toBeHidden();
    await menu.click();
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(main).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    // Escape closes the open menu from the button.
    await menu.focus();
    await page.keyboard.press('Escape');
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(menu).toBeFocused();
    await menu.click();
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await main.getByRole('link', { name: 'Entities', exact: true }).click();
    await settled(page, 'Entities');
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(main).toBeHidden();
    // On a wide screen the button disappears and the navigation is always shown.
    await page.setViewportSize({ width: 1280, height: 800 });
    await expect(menu).toBeHidden();
    await expect(main).toBeVisible();
  });
});

test.describe('administration redesign (delegated admin of entity A)', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('the block of the only entity is pinned on every screen', async ({ page, state }) => {
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    const nested = tenantNav(page, state);
    await expect(nested).toBeVisible();
    await expect(nested.getByRole('button', { name: 'Configuration', exact: true })).toBeVisible();
    await expect(nested.getByRole('button', { name: 'Operations', exact: true })).toBeVisible();
    await expect(nested.getByRole('button', { name: 'Consultation', exact: true })).toHaveCount(0);
    for (const path of ['/account', '/tenants']) {
      await page.goto(`${ADMIN}${path}`);
      await expect(nested).toBeVisible();
    }
    // No System nor Administrators entry for a delegated admin.
    const main = mainNav(page);
    await expect(main.getByRole('link', { name: 'System', exact: true })).toHaveCount(0);
    await expect(main.getByRole('link', { name: 'Administrators', exact: true })).toHaveCount(0);
  });

  test('axe, both themes: home', async ({ page }) => {
    await page.goto(`${ADMIN}/`);
    await settled(page, 'Home');
    await checkA11y(page);
  });

  test('every screen with a help topic shows a help link next to its title', async ({ page, state }) => {
    const a = state.tenants.a.id;
    const screens: [string, string][] = [
      ['/', 'Home'],
      ['/account', 'My account'],
      [`/tenants/${a}/transfers`, 'Transfers'],
      [`/tenants/${a}/invitations`, 'Invitations'],
      [`/tenants/${a}/blocklist`, 'Blocklist'],
      [`/tenants/${a}/audit`, 'Audit log'],
      [`/tenants/${a}/stats`, 'Statistics'],
      [`/tenants/${a}/privacy`, 'Personal data'],
      [`/tenants/${a}/general`, 'General'],
      [`/tenants/${a}/templates`, 'Email templates'],
    ];
    for (const [path, heading] of screens) {
      await page.goto(`${ADMIN}${path}`);
      await settled(page, heading);
      await expectHelpIcon(page, `Help: ${heading}`);
    }
  });
});

test.describe('administration redesign (French home)', () => {
  test.use({ storageState: STORAGE_SUPER, locale: 'fr-FR' });

  test('the "Tout voir" link is found by an accessible name starting with "Tout voir"', async ({ page }) => {
    await page.goto(`${ADMIN}/`);
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(page.getByRole('heading', { name: 'Accueil', level: 1 })).toBeVisible();
    const seeAll = page.getByRole('link', { name: /^Tout voir/ });
    await expect(seeAll.first()).toBeVisible();
    await expect(seeAll.first()).toHaveAccessibleName(msg('fr', 'adminHome.seeAllName'));
  });
});

test.describe('administration redesign (auditor)', () => {
  test('Consultation group only, and axe on the home in both themes', async ({ state, newContext }) => {
    const page = await openAsAuditor(newContext, state, state.tenants.a.id);
    await settled(page, 'Home');
    const nested = tenantNav(page, state);
    await expect(nested).toBeVisible();
    await expect(nested.getByRole('button', { name: 'Consultation', exact: true })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    await expect(nested.getByRole('button', { name: 'Configuration', exact: true })).toHaveCount(0);
    await expect(nested.getByRole('button', { name: 'Operations', exact: true })).toHaveCount(0);
    await expect(nested.getByRole('button')).toHaveCount(1);
    // Read-only links of the group, the security log among them.
    for (const name of ['Transfers', 'Audit log', 'Statistics', 'Security log']) {
      await expect(nested.getByRole('link', { name, exact: true })).toBeVisible();
    }
    await expect(nested.getByRole('link', { name: 'General', exact: true })).toHaveCount(0);
    await checkA11y(page);
  });
});
