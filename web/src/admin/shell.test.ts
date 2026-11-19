import { describe, expect, it } from 'vitest';
import type { AdminMe } from './auth/machine';
import {
  closesSidebarMenu,
  inAdminFrame,
  SYSTEM_SECTIONS,
  TENANT_CONFIG_SECTIONS,
  TENANT_OPS_SECTIONS,
  TENANT_SECTIONS,
  navCurrent,
  pickAdminLanguage,
  redirectTarget,
  roleKey,
  canSearchByAddress,
  isAuditor,
  mainLinks,
  sectionGroup,
  systemLinks,
  systemPath,
  tenantLinkGroups,
  tenantLinks,
  tenantNameOf,
  tenantPath,
  isGroupOpen,
  pinnedTenantId,
  revealCurrentGroups,
  sidebarModel,
  toggleGroup,
  type CollapsedGroups,
  type SidebarModel,
} from './shell';

const available = ['en', 'fr'];

describe('pickAdminLanguage', () => {
  it('prefers the stored choice', () => {
    expect(pickAdminLanguage({ available, stored: 'fr', meLanguage: 'en', browserLanguages: ['en'] })).toBe(
      'fr',
    );
  });

  it('then the language of the profile', () => {
    expect(pickAdminLanguage({ available, meLanguage: 'fr', browserLanguages: ['en-GB'] })).toBe('fr');
    expect(pickAdminLanguage({ available, stored: 'de', meLanguage: 'fr' })).toBe('fr');
  });

  it('then the first browser language offered', () => {
    expect(
      pickAdminLanguage({ available, meLanguage: 'de', browserLanguages: ['de-DE', 'FR-ca', 'en'] }),
    ).toBe('fr');
  });

  it('then English', () => {
    expect(pickAdminLanguage({ available })).toBe('en');
    expect(pickAdminLanguage({ available, browserLanguages: ['de', ''] })).toBe('en');
  });

  it('falls back to the first language offered without English', () => {
    expect(pickAdminLanguage({ available: ['fr'] })).toBe('fr');
    expect(pickAdminLanguage({ available: [] })).toBe('en');
  });
});

describe('navCurrent', () => {
  it.each([
    ['/', '/', 'page'],
    ['/tenants', '/', undefined],
    ['/tenants', '/tenants', 'page'],
    ['/tenants/', '/tenants', 'page'],
    ['/tenants/new', '/tenants', 'true'],
    ['/tenants/t1/templates/code/fr', '/tenants/t1/templates', 'true'],
    ['/tenants/t1/templates', '/tenants/t1/templates', 'page'],
    ['/tenantsx', '/tenants', undefined],
    ['/admins/a1', '/admins', 'true'],
    ['/account', '/admins', undefined],
  ])('%s against %s', (path, target, expected) => {
    expect(navCurrent(path, target)).toBe(expected);
  });

  it('marks a parent link of the main navigation on the system pages', () => {
    expect(navCurrent('/system', '/system')).toBe('page');
    expect(navCurrent('/system/maintenance', '/system')).toBe('true');
    expect(navCurrent('/systems', '/system')).toBeUndefined();
  });

  it.each([
    ['/system', '/system', 'page'],
    ['/system/', '/system', 'page'],
    ['/system/maintenance', '/system', undefined],
    ['/system/master-key', '/system', undefined],
    ['/tenants/new', '/tenants', undefined],
  ])('exact: %s against %s', (path, target, expected) => {
    expect(navCurrent(path, target, true)).toBe(expected);
  });
});

describe('system navigation', () => {
  it('builds the path of every section', () => {
    expect(SYSTEM_SECTIONS.map(systemPath)).toEqual([
      '/system',
      '/system/maintenance',
      '/system/settings',
      '/system/webhooks',
      '/system/audit',
      '/system/security-events',
      '/system/master-key',
      '/system/provisioning-tokens',
    ]);
  });

  it('lists the links in order, the overview marked on its exact page only', () => {
    const links = systemLinks();
    expect(links.map((l) => l.section)).toEqual([...SYSTEM_SECTIONS]);
    expect(links[0]).toEqual({
      section: 'overview',
      path: '/system',
      labelKey: 'adminSystem.nav.overview',
      exact: true,
    });
    expect(links.at(-1)).toEqual({
      section: 'provisioning',
      path: '/system/provisioning-tokens',
      labelKey: 'adminSystem.nav.provisioning',
      exact: false,
    });
    expect(links.filter((l) => l.exact)).toHaveLength(1);
  });

  it('marks exactly one link on each system page', () => {
    for (const page of systemLinks()) {
      const marked = systemLinks().filter((l) => navCurrent(page.path, l.path, l.exact) !== undefined);
      expect(marked.map((l) => l.section)).toEqual([page.section]);
    }
  });
});

describe('tenant navigation', () => {
  it('lists the sections in order with their labels', () => {
    const links = tenantLinks('ten_1');
    expect(links.map((l) => l.section)).toEqual([...TENANT_SECTIONS]);
    expect(links[0]).toEqual({
      section: 'setup',
      group: 'configuration',
      path: '/tenants/ten_1/setup',
      labelKey: 'adminTenants.nav.setup',
    });
    expect(links[1]?.section).toBe('general');
    expect(links.at(-1)).toEqual({
      section: 'privacy',
      group: 'operations',
      path: '/tenants/ten_1/privacy',
      labelKey: 'adminOps.nav.privacy',
    });
  });

  it('places the operation sections after the configuration ones', () => {
    expect(TENANT_SECTIONS.indexOf('legal') + 1).toBe(TENANT_SECTIONS.indexOf('transfers'));
    expect(sectionGroup('legal')).toBe('configuration');
    expect(sectionGroup('transfers')).toBe('operations');
  });

  it('groups the links under titled groups', () => {
    const groups = tenantLinkGroups('ten_1');
    expect(groups.map((g) => [g.group, g.labelKey])).toEqual([
      ['configuration', 'adminOps.nav.groupConfiguration'],
      ['operations', 'adminOps.nav.groupOperations'],
    ]);
    expect(groups[0]?.links.map((l) => l.section)).toEqual([...TENANT_CONFIG_SECTIONS]);
    expect(groups[1]?.links.map((l) => l.section)).toEqual([...TENANT_OPS_SECTIONS]);
    for (const link of groups[1]?.links ?? []) {
      expect(link.labelKey).toBe(`adminOps.nav.${link.section}`);
    }
  });

  it('keeps a section link marked on its sub-pages', () => {
    expect(navCurrent('/tenants/ten_1/transfers/trf_1', tenantPath('ten_1', 'transfers'))).toBe('true');
    expect(navCurrent('/tenants/ten_1/tokens/new', tenantPath('ten_1', 'tokens'))).toBe('true');
    expect(navCurrent('/tenants/ten_1/tokens', tenantPath('ten_1', 'transfers'))).toBeUndefined();
  });

  it('encodes the tenant id', () => {
    expect(tenantPath('a/b c', 'smtp')).toBe('/tenants/a%2Fb%20c/smtp');
  });

  it('finds the tenant name in the profile', () => {
    const me = {
      id: 'adm_1',
      username: 'alice',
      email: 'alice@example.com',
      role: 'delegated_admin',
      totpEnabled: true,
      csrfToken: 'x',
      tenants: [{ id: 'ten_1', name: 'Entity A', fqdn: 'transfer.entity-a.example.com' }],
    } satisfies AdminMe;
    expect(tenantNameOf(me, 'ten_1')).toBe('Entity A');
    expect(tenantNameOf(me, 'ten_2')).toBeUndefined();
    expect(tenantNameOf(me, undefined)).toBeUndefined();
    expect(tenantNameOf(undefined, 'ten_1')).toBeUndefined();
  });
});

describe('redirectTarget', () => {
  it('returns the target of a redirect to another page', () => {
    expect(redirectTarget({ kind: 'redirect', to: '/login?next=%2Ftenants' }, '/tenants')).toBe(
      '/login?next=%2Ftenants',
    );
  });

  it('ignores a redirect to the page shown and the other decisions', () => {
    expect(redirectTarget({ kind: 'redirect', to: '/login' }, '/login')).toBeUndefined();
    expect(redirectTarget({ kind: 'render' }, '/')).toBeUndefined();
    expect(redirectTarget({ kind: 'notFound' }, '/')).toBeUndefined();
    expect(redirectTarget({ kind: 'pending' }, '/')).toBeUndefined();
  });
});

describe('role-aware navigation', () => {
  it('limits an auditor to the consultation sections, in one group', () => {
    const links = tenantLinks('ten_1', 'auditor');
    expect(links.map((l) => l.section)).toEqual([
      'general',
      'sso',
      'transfers',
      'dropLinks',
      'secrets',
      'audit',
      'security',
      'stats',
    ]);
    expect(links.map((l) => l.path)).toEqual([
      '/tenants/ten_1/general',
      '/tenants/ten_1/sso',
      '/tenants/ten_1/transfers',
      '/tenants/ten_1/drop-links',
      '/tenants/ten_1/secrets',
      '/tenants/ten_1/audit',
      '/tenants/ten_1/security-events',
      '/tenants/ten_1/stats',
    ]);
    expect(links[0]?.labelKey).toBe('adminTenants.nav.summary');
    expect(links.map((l) => l.group)).toEqual(Array(8).fill('consultation'));
    const groups = tenantLinkGroups('ten_1', 'auditor');
    expect(groups).toHaveLength(1);
    expect(groups[0]?.labelKey).toBe('adminOps.nav.groupConsultation');
    expect(groups[0]?.links).toEqual(links);
  });

  it('gives no configuration section to an auditor', () => {
    const sections = tenantLinks('ten_1', 'auditor').map((l) => l.section) as string[];
    for (const config of TENANT_CONFIG_SECTIONS.filter((s) => s !== 'general' && s !== 'sso')) {
      expect(sections).not.toContain(config);
    }
    for (const op of [
      'secretSettings',
      'invitations',
      'blocklist',
      'abuseReports',
      'tokens',
      'webhooks',
      'privacy',
    ]) {
      expect(sections).not.toContain(op);
    }
  });

  it('keeps every section for the other roles, the security log among the operations', () => {
    for (const role of ['super_admin', 'delegated_admin', undefined] as const) {
      expect(tenantLinks('ten_1', role).map((l) => l.section)).toEqual([...TENANT_SECTIONS]);
    }
    expect(TENANT_OPS_SECTIONS).toContain('security');
    expect(tenantLinks('ten_1').find((l) => l.section === 'security')?.labelKey).toBe(
      'adminOps.nav.security',
    );
  });

  it('builds the main navigation per role', () => {
    const paths = (role: Parameters<typeof mainLinks>[0]) => mainLinks(role).map((l) => l.path);
    expect(mainLinks('super_admin').map((l) => [l.id, l.icon])).toEqual([
      ['home', 'home'],
      ['tenants', 'grid'],
      ['admins', 'users'],
      ['system', 'settings'],
      ['account', 'user'],
    ]);
    expect(paths('super_admin')).toEqual(['/', '/tenants', '/admins', '/system', '/account']);
    expect(paths('delegated_admin')).toEqual(['/', '/tenants', '/account']);
    expect(paths('auditor')).toEqual(['/', '/tenants', '/account']);
    expect(paths(undefined)).toEqual(['/', '/tenants', '/account']);
  });

  it('puts the global security log in the system navigation', () => {
    expect(systemPath('security')).toBe('/system/security-events');
    expect(systemLinks().find((l) => l.section === 'security')?.labelKey).toBe('adminSystem.nav.security');
  });

  it('recognises the auditor', () => {
    expect(isAuditor('auditor')).toBe(true);
    expect(isAuditor('delegated_admin')).toBe(false);
    expect(isAuditor(undefined)).toBe(false);
  });
});

describe('roleKey', () => {
  it('maps the known roles and a future one', () => {
    expect(roleKey('super_admin')).toBe('admin.role.super_admin');
    expect(roleKey('delegated_admin')).toBe('admin.role.delegated_admin');
    expect(roleKey('auditor')).toBe('admin.role.auditor');
    expect(roleKey('observer')).toBe('admin.role.unknown');
  });
});

describe('canSearchByAddress', () => {
  it('denies the search by address to the auditor and to an unknown role (T-282)', () => {
    expect(canSearchByAddress('super_admin')).toBe(true);
    expect(canSearchByAddress('delegated_admin')).toBe(true);
    expect(canSearchByAddress('auditor')).toBe(false);
    expect(canSearchByAddress('observer')).toBe(false);
    expect(canSearchByAddress(undefined)).toBe(false);
  });
});

describe('sidebar model', () => {
  const tenantA = { id: 'ten_a', name: 'Entity A', fqdn: 'transfer.entity-a.example.com' };
  const tenantB = { id: 'ten_b', name: 'Entity B', fqdn: 'transfer.entity-b.example.com' };
  const profile = (role: AdminMe['role'], tenants: AdminMe['tenants']): AdminMe => ({
    id: 'adm_1',
    username: 'alice',
    email: 'alice@example.com',
    role,
    totpEnabled: true,
    csrfToken: 'x',
    tenants,
  });
  const superAdmin = profile('super_admin', [tenantA, tenantB]);
  const delegate = profile('delegated_admin', [tenantA]);
  const delegateOfTwo = profile('delegated_admin', [tenantA, tenantB]);
  const auditor = profile('auditor', [tenantA]);

  const entry = (model: SidebarModel, id: string) => model.entries.find((e) => e.id === id);
  const currentLinks = (model: SidebarModel) =>
    model.entries.flatMap((e) => [
      ...(e.current === undefined ? [] : [[e.path, e.current]]),
      ...(e.tenant?.groups ?? []).flatMap((g) =>
        g.links.filter((l) => l.current !== undefined).map((l) => [l.path, l.current]),
      ),
      ...(e.system?.links ?? []).filter((l) => l.current !== undefined).map((l) => [l.path, l.current]),
    ]);

  it('pins the tenant of an admin who has exactly one', () => {
    expect(pinnedTenantId(delegate)).toBe('ten_a');
    expect(pinnedTenantId(auditor)).toBe('ten_a');
    expect(pinnedTenantId(superAdmin)).toBeUndefined();
    expect(pinnedTenantId(profile('delegated_admin', []))).toBeUndefined();
    expect(pinnedTenantId(undefined)).toBeUndefined();
  });

  it('lists the main entries of the role with their icon, home current', () => {
    const model = sidebarModel(superAdmin, '/', undefined, false);
    expect(model.entries.map((e) => [e.id, e.path, e.key, e.icon, e.current])).toEqual([
      ['home', '/', 'admin.nav.home', 'home', 'page'],
      ['tenants', '/tenants', 'admin.nav.tenants', 'grid', undefined],
      ['admins', '/admins', 'admin.nav.admins', 'users', undefined],
      ['system', '/system', 'admin.nav.system', 'settings', undefined],
      ['account', '/account', 'admin.nav.account', 'user', undefined],
    ]);
    expect(model.entries.some((e) => e.tenant !== undefined || e.system !== undefined)).toBe(false);
    expect(sidebarModel(delegateOfTwo, '/account', undefined, false).entries.map((e) => e.id)).toEqual([
      'home',
      'tenants',
      'account',
    ]);
  });

  it('nests the block of the tenant shown under Entities, with both groups', () => {
    const model = sidebarModel(superAdmin, '/tenants/ten_b/templates/code/fr', 'ten_b', false);
    const tenants = entry(model, 'tenants');
    expect(tenants?.current).toBe('true');
    expect(tenants?.tenant).toMatchObject({ tenantId: 'ten_b', name: 'Entity B', pinned: false });
    expect(tenants?.tenant?.groups.map((g) => [g.group, g.labelKey, g.holdsCurrent])).toEqual([
      ['configuration', 'adminOps.nav.groupConfiguration', true],
      ['operations', 'adminOps.nav.groupOperations', false],
    ]);
    expect(tenants?.tenant?.groups[0]?.links.find((l) => l.section === 'templates')).toEqual({
      section: 'templates',
      path: '/tenants/ten_b/templates',
      labelKey: 'adminTenants.nav.templates',
      current: 'true',
    });
    expect(currentLinks(model)).toEqual([
      ['/tenants', 'true'],
      ['/tenants/ten_b/templates', 'true'],
    ]);
    expect(entry(model, 'system')?.system).toBeUndefined();
  });

  it('gives an auditor the single consultation group', () => {
    const model = sidebarModel(auditor, '/tenants/ten_a/audit', 'ten_a', false);
    const block = entry(model, 'tenants')?.tenant;
    expect(block?.pinned).toBe(true);
    expect(block?.groups.map((g) => g.group)).toEqual(['consultation']);
    expect(block?.groups[0]?.links.map((l) => l.section)).toEqual([
      'general',
      'sso',
      'transfers',
      'dropLinks',
      'secrets',
      'audit',
      'security',
      'stats',
    ]);
    expect(block?.groups[0]?.holdsCurrent).toBe(true);
  });

  it('shows the pinned tenant on every page of an admin with one tenant', () => {
    const home = sidebarModel(delegate, '/', undefined, false);
    expect(entry(home, 'tenants')?.tenant).toMatchObject({ tenantId: 'ten_a', pinned: true });
    expect(entry(home, 'tenants')?.tenant?.groups.every((g) => !g.holdsCurrent)).toBe(true);
    expect(currentLinks(home)).toEqual([['/', 'page']]);
  });

  it('never shows a tenant outside the scope of the admin', () => {
    // The delegate of A on a page of B ("not found"): its own pinned block, never B.
    const pinned = sidebarModel(delegate, '/tenants/ten_b/general', 'ten_b', false);
    expect(entry(pinned, 'tenants')?.tenant?.tenantId).toBe('ten_a');
    expect(JSON.stringify(pinned)).not.toContain('ten_b');
    // An admin of two tenants on an unknown one: no block at all.
    const none = sidebarModel(delegateOfTwo, '/tenants/ten_x/general', 'ten_x', false);
    expect(entry(none, 'tenants')?.tenant).toBeUndefined();
    expect(JSON.stringify(none)).not.toContain('ten_x');
    // Without a tenant page and without a pinned tenant: no block.
    expect(
      entry(sidebarModel(delegateOfTwo, '/tenants', undefined, false), 'tenants')?.tenant,
    ).toBeUndefined();
  });

  it('nests the system block under System on the system pages of a super admin', () => {
    const overview = sidebarModel(superAdmin, '/system', undefined, true);
    const system = entry(overview, 'system');
    expect(system?.system?.links.map((l) => l.section)).toEqual([...SYSTEM_SECTIONS]);
    // The overview is the exact page: the entry itself is only "true".
    expect(currentLinks(overview)).toEqual([
      ['/system', 'true'],
      ['/system', 'page'],
    ]);
    const maintenance = sidebarModel(superAdmin, '/system/maintenance', undefined, true);
    expect(currentLinks(maintenance)).toEqual([
      ['/system', 'true'],
      ['/system/maintenance', 'page'],
    ]);
    expect(entry(sidebarModel(superAdmin, '/admins', undefined, false), 'system')?.system).toBeUndefined();
    // Never for another role, even if asked.
    expect(sidebarModel(delegate, '/system', undefined, true).entries.some((e) => e.system)).toBe(false);
  });

  it('keeps an entry "page" when its block does not hold the page', () => {
    const list = sidebarModel(delegate, '/tenants', undefined, false);
    expect(entry(list, 'tenants')?.current).toBe('page');
  });

  it('builds the entries of an unknown profile without block', () => {
    const model = sidebarModel(undefined, '/', 'ten_a', true);
    expect(model.entries.map((e) => e.id)).toEqual(['home', 'tenants', 'account']);
    expect(model.entries.some((e) => e.tenant !== undefined || e.system !== undefined)).toBe(false);
  });
});

describe('sidebar groups', () => {
  const none: CollapsedGroups = new Set();

  it('opens every group by default and toggles one', () => {
    expect(isGroupOpen(none, 'configuration')).toBe(true);
    const collapsed = toggleGroup(none, 'operations');
    expect(isGroupOpen(collapsed, 'operations')).toBe(false);
    expect(isGroupOpen(collapsed, 'configuration')).toBe(true);
    expect(none.size).toBe(0);
    expect(isGroupOpen(toggleGroup(collapsed, 'operations'), 'operations')).toBe(true);
  });

  it('opens the group of the page shown on a navigation', () => {
    const collapsed = toggleGroup(toggleGroup(none, 'operations'), 'configuration');
    const revealed = revealCurrentGroups(collapsed, [
      { group: 'configuration', holdsCurrent: false },
      { group: 'operations', holdsCurrent: true },
    ]);
    expect(isGroupOpen(revealed, 'operations')).toBe(true);
    expect(isGroupOpen(revealed, 'configuration')).toBe(false);
    expect(revealCurrentGroups(revealed, [{ group: 'operations', holdsCurrent: true }])).toBe(revealed);
  });
});

describe('inAdminFrame', () => {
  const me = { id: 'adm_1', username: 'root', role: 'super_admin', tenants: [] } as unknown as AdminMe;

  it('is the signed-in frame only for an authenticated session with a profile', () => {
    expect(inAdminFrame({ state: { kind: 'authenticated' }, me })).toBe(true);
    expect(inAdminFrame({ state: { kind: 'authenticated' }, me: undefined })).toBe(false);
    expect(inAdminFrame({ state: { kind: 'anonymous' }, me })).toBe(false);
    expect(inAdminFrame({ state: { kind: 'loading' }, me: undefined })).toBe(false);
  });
});

describe('closesSidebarMenu', () => {
  it('closes the open menu on Escape when the focus is on its button or in its panel', () => {
    expect(closesSidebarMenu('Escape', true, true)).toBe(true);
  });

  it('leaves a closed menu, another key or a focus outside the sidebar alone', () => {
    expect(closesSidebarMenu('Escape', false, true)).toBe(false);
    expect(closesSidebarMenu('Enter', true, true)).toBe(false);
    expect(closesSidebarMenu('Escape', true, false)).toBe(false);
  });
});
