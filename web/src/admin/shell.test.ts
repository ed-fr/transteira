import { describe, expect, it } from 'vitest';
import type { AdminMe } from './auth/machine';
import {
  TENANT_CONFIG_SECTIONS,
  TENANT_OPS_SECTIONS,
  TENANT_SECTIONS,
  navCurrent,
  pickAdminLanguage,
  redirectTarget,
  roleKey,
  sectionGroup,
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
});

describe('tenant navigation', () => {
  it('lists the sections in order with their labels', () => {
    const links = tenantLinks('ten_1');
    expect(links.map((l) => l.section)).toEqual([...TENANT_SECTIONS]);
    expect(links[0]).toEqual({
      section: 'general',
      group: 'configuration',
      path: '/tenants/ten_1/general',
      labelKey: 'adminTenants.nav.general',
    });
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

describe('roleKey', () => {
  it('maps the known roles and a future one', () => {
    expect(roleKey('super_admin')).toBe('admin.role.super_admin');
    expect(roleKey('delegated_admin')).toBe('admin.role.delegated_admin');
    expect(roleKey('auditor')).toBe('admin.role.unknown');
  });
});
