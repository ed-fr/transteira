import { describe, expect, it } from 'vitest';
import type { AdminMe } from './auth/machine';
import {
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
    expect(links.map((l) => l.section)).toEqual(['general', 'transfers', 'audit', 'security', 'stats']);
    expect(links.map((l) => l.path)).toEqual([
      '/tenants/ten_1/general',
      '/tenants/ten_1/transfers',
      '/tenants/ten_1/audit',
      '/tenants/ten_1/security-events',
      '/tenants/ten_1/stats',
    ]);
    expect(links[0]?.labelKey).toBe('adminTenants.nav.summary');
    expect(links.map((l) => l.group)).toEqual(Array(5).fill('consultation'));
    const groups = tenantLinkGroups('ten_1', 'auditor');
    expect(groups).toHaveLength(1);
    expect(groups[0]?.labelKey).toBe('adminOps.nav.groupConsultation');
    expect(groups[0]?.links).toEqual(links);
  });

  it('gives no configuration section to an auditor', () => {
    const sections = tenantLinks('ten_1', 'auditor').map((l) => l.section) as string[];
    for (const config of TENANT_CONFIG_SECTIONS.filter((s) => s !== 'general')) {
      expect(sections).not.toContain(config);
    }
    for (const op of ['invitations', 'blocklist', 'abuseReports', 'tokens', 'webhooks', 'privacy']) {
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
